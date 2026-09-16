"""
Phase 5 — Graph Query Layer
============================
View-ready subgraph payloads for the dashboard topology view.

The dashboard does NOT render the whole graph by default. It renders
**attacker-centred subgraphs**, because a node ranked by danger score in
isolation carries no structural meaning — an attacker only becomes a pattern
when you can see the cluster around it.

Default render set (Level 0)
----------------------------
    nodes ∈ members of the malicious communities (top-K by severity)
          ∪ every node flagged ``is_attacker = true``
          ∪ every node directly connected to an attacker
    edges ∈ all connections between those nodes
            (the dashboard lens defaults to ``has_attack = true`` only)

Everything else — normal traffic with no path to an attacker — is simply not
shipped to the browser by default.

Scopes
------
  ``threat``  Level 0 — attacker-centred clusters (small, fast)
  ``ego``     Level 1 — one node + its 1-hop neighbourhood (click / search)
  ``full``    Level 2 — sampled macro view of the whole graph, for
              structure-spotting only (clearly flagged as sampled)

Data source is MongoDB (``graph_nodes`` / ``graph_edges`` / ``graph_communities``)
with a fallback to ``graph_export.json`` when Mongo is unavailable.

Note: UNSW-NB15 CSV files carry a UTF-8 BOM on the first field of the first
row, so a handful of stored IPs look like ``"\\ufeff59.166.0.0"``. Every IP
read here is sanitised and de-duplicated, otherwise the BOM variant shows up
as a phantom duplicate node.

Usage:
    from backend.graph.graph_query import load_view, load_ego
    payload = load_view(db, scope="threat", k=3)
    ego = load_ego("175.45.176.0", db)
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")
_DB_NAME = os.getenv("MONGO_DB", "threvia")
_EXPORT_JSON = Path(__file__).parent / "graph_export.json"

# Budgets keep the payload browser-friendly. ``full`` is explicitly a *sampled*
# macro view, and says so in its metadata.
_MAX_NODES = {"threat": 1500, "full": 2500, "ego": 400}
_MAX_EDGES = {"threat": 6000, "full": 15000, "ego": 800}

_DANGER_FORMULA = "0.5*pagerank + 0.3*out_degree_centrality + 0.2*degree_centrality"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _clean(value: Any) -> str:
    """Strip BOM / whitespace from an IP string."""
    if value is None:
        return ""
    return str(value).replace("\ufeff", "").strip()


def _variants(ip: str) -> list[str]:
    """Both the clean and the legacy BOM-prefixed spelling of an IP."""
    ip = _clean(ip)
    return [ip, "\ufeff" + ip] if ip else []


def _in_variants(ips: Iterable[str]) -> list[str]:
    out: list[str] = []
    for ip in ips:
        out.extend(_variants(ip))
    return out


def _jsonable(value: Any) -> Any:
    """Recursively make a Mongo document JSON-safe."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _danger_score(doc: dict, n_nodes: int) -> float:
    """
    Danger score — identical formula to graph_analytics.run_analytics():

        (pagerank * 0.5) + (out_degree_centrality * 0.3) + (degree_centrality * 0.2)

    Accepts either a Mongo node doc (centrality fields) or an exported JSON node
    (raw degree ints only) and derives the centrality values it is missing.
    """
    pr = float(doc.get("pagerank") or 0.0)

    deg_cent = doc.get("degree")
    out_cent = doc.get("out_degree")
    if deg_cent is None or out_cent is None:
        raw_in = int(doc.get("raw_in_deg") or doc.get("in_degree") or 0)
        raw_out = int(doc.get("raw_out_deg") or doc.get("out_degree") or 0)
        denom = max(n_nodes - 1, 1)
        deg_cent = (raw_in + raw_out) / denom
        out_cent = raw_out / denom

    return 0.5 * pr + 0.3 * float(out_cent) + 0.2 * float(deg_cent)


def _raw_degrees(doc: dict) -> tuple[int, int]:
    """(in_degree, out_degree) as integers, tolerating exported JSON nodes."""
    if "raw_in_deg" in doc or "raw_out_deg" in doc:
        return int(doc.get("raw_in_deg") or 0), int(doc.get("raw_out_deg") or 0)
    return int(doc.get("in_degree") or 0), int(doc.get("out_degree") or 0)


def _norm_node(doc: dict) -> dict:
    """Normalise one raw node document (Mongo or exported JSON)."""
    ip = _clean(doc.get("ip") or doc.get("id"))
    in_deg, out_deg = _raw_degrees(doc)
    return {
        "ip": ip,
        "is_attacker": bool(doc.get("is_attacker")),
        "community_id": doc.get("community_id", -1) if doc.get("community_id") is not None else -1,
        "pagerank": float(doc.get("pagerank") or 0.0),
        "total_flows": int(doc.get("total_flows") or 0),
        "in_degree": in_deg,
        "out_degree": out_deg,
        "attack_cats": [c for c in (doc.get("attack_cats") or []) if c],
        "label": doc.get("label") or "NORMAL",
        "raw": doc,
    }


def _norm_edge(doc: dict) -> Optional[dict]:
    """Normalise one raw edge document; returns None for self-loops/blank ends."""
    src = _clean(doc.get("src_ip") or doc.get("source"))
    dst = _clean(doc.get("dst_ip") or doc.get("target"))
    if not src or not dst or src == dst:
        return None
    return {
        "source": src,
        "target": dst,
        "has_attack": bool(doc.get("has_attack")),
        "weight": int(doc.get("weight") or 1),
        "total_bytes": int(doc.get("total_bytes") or 0),
        "attack_cats": [c for c in (doc.get("attack_cats") or []) if c],
        "proto_counts": doc.get("proto_counts") or {},
    }


def _norm_community(doc: dict) -> dict:
    return {
        "community_id": doc.get("community_id", -1),
        "size": int(doc.get("size") or 0),
        "attacker_count": int(doc.get("attacker_count") or 0),
        "attacker_ips": [_clean(ip) for ip in (doc.get("attacker_ips") or [])],
        "internal_edges": int(doc.get("internal_edges") or 0),
        "attack_cats": [c for c in (doc.get("attack_cats") or []) if c],
        "is_malicious": bool(doc.get("is_malicious")),
        "members": [_clean(m) for m in (doc.get("members") or []) if _clean(m)],
    }


# ── Data sources ───────────────────────────────────────────────────────────────

class _MongoBundle:
    """Reads the graph lazily from MongoDB — only the rows a view actually needs."""

    source = "mongo"
    capped = False

    _NODE_PROJ = {"_id": 0}

    def __init__(self, db):
        self.db = db

    # meta / counts
    def meta(self) -> dict:
        doc = self.db.graph_meta.find_one(
            {}, {"_id": 0, "top_nodes": 0, "flagged_malicious": 0}
        ) or {}
        return _jsonable(doc)

    def totals(self) -> tuple[int, int]:
        return (
            self.db.graph_nodes.count_documents({}),
            self.db.graph_edges.count_documents({}),
        )

    def communities(self) -> list[dict]:
        return [_norm_community(c) for c in self.db.graph_communities.find({}, {"_id": 0})]

    def attacker_ids(self) -> set[str]:
        return {
            _clean(d.get("ip"))
            for d in self.db.graph_nodes.find({"is_attacker": True}, {"_id": 0, "ip": 1})
            if _clean(d.get("ip"))
        }

    def community_attack_stats(self) -> dict:
        """{community_id: {attack_edges, attack_bytes}} — attack flow volume per community."""
        pipeline = [
            {"$match": {"has_attack": True}},
            {"$group": {
                "_id": "$src_community",
                "attack_edges": {"$sum": 1},
                "attack_bytes": {"$sum": "$total_bytes"},
            }},
        ]
        try:
            return {r["_id"]: r for r in self.db.graph_edges.aggregate(pipeline)}
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("community attack stats aggregation failed: %s", exc)
            return {}

    def attacker_edges(self, attacker_ids: set[str]) -> list[dict]:
        if not attacker_ids:
            return []
        variants = _in_variants(attacker_ids)
        cursor = self.db.graph_edges.find(
            {"$or": [{"src_ip": {"$in": variants}}, {"dst_ip": {"$in": variants}}]},
            self._NODE_PROJ,
        )
        return [e for e in (_norm_edge(d) for d in cursor) if e]

    def nodes_by_ids(self, ids: Iterable[str]) -> dict[str, dict]:
        ids = set(ids)
        if not ids:
            return {}
        out: dict[str, dict] = {}
        for doc in self.db.graph_nodes.find({"ip": {"$in": _in_variants(ids)}}, self._NODE_PROJ):
            node = _norm_node(doc)
            if node["ip"]:
                out.setdefault(node["ip"], node)
        return out

    def nodes_top(self, limit: int) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for doc in self.db.graph_nodes.find({}, self._NODE_PROJ).sort("pagerank", -1).limit(limit):
            node = _norm_node(doc)
            if node["ip"]:
                out.setdefault(node["ip"], node)
        return out

    def edges_among(self, ids: Iterable[str], limit: int, prefer_attack: bool = True) -> list[dict]:
        ids = set(ids)
        if not ids:
            return []
        variants = _in_variants(ids)
        endpoints = [{"src_ip": {"$in": variants}}, {"dst_ip": {"$in": variants}}]

        edges: list[dict] = []
        seen: set[tuple[str, str]] = set()

        def collect(query: dict, budget: int) -> None:
            if budget <= 0:
                return
            for doc in self.db.graph_edges.find(query, self._NODE_PROJ).limit(budget):
                edge = _norm_edge(doc)
                if not edge or edge["source"] not in ids or edge["target"] not in ids:
                    continue
                key = (edge["source"], edge["target"])
                if key in seen:
                    continue
                seen.add(key)
                edges.append(edge)

        if prefer_attack:
            collect({"has_attack": True, "$or": endpoints}, max(1, int(limit * 0.6)))
        collect({"$or": endpoints}, limit - len(edges))
        return edges

    def node_by_ip(self, ip: str) -> Optional[dict]:
        doc = self.db.graph_nodes.find_one({"ip": {"$in": _variants(ip)}}, self._NODE_PROJ)
        return _norm_node(doc) if doc else None

    def communities_by_ids(self, comm_ids: Iterable[int]) -> list[dict]:
        comm_ids = [c for c in set(comm_ids) if c is not None and c != -1]
        if not comm_ids:
            return []
        return [
            _norm_community(c)
            for c in self.db.graph_communities.find({"community_id": {"$in": comm_ids}}, {"_id": 0})
        ]


class _JsonBundle:
    """In-memory bundle backed by backend/graph/graph_export.json."""

    source = "json_export"

    def __init__(self, path: Path):
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        self._nodes: dict[str, dict] = {}
        for doc in raw.get("nodes", []):
            node = _norm_node(doc)
            if node["ip"]:
                self._nodes[node["ip"]] = node

        self._edges: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for doc in raw.get("edges", []):
            edge = _norm_edge(doc)
            if not edge:
                continue
            key = (edge["source"], edge["target"])
            if key in seen:
                continue
            seen.add(key)
            self._edges.append(edge)

        self._meta = _jsonable(raw.get("metadata") or {})

        # Communities: prefer the exported array, otherwise derive from nodes.
        raw_comms = raw.get("communities") or []
        if raw_comms:
            self._comms = [_norm_community(c) for c in raw_comms]
            for comm in self._comms:
                if not comm["members"]:
                    comm["members"] = [
                        ip for ip, n in self._nodes.items() if n["community_id"] == comm["community_id"]
                    ]
        else:
            grouped: dict[int, list[str]] = {}
            for ip, node in self._nodes.items():
                grouped.setdefault(node["community_id"], []).append(ip)
            self._comms = []
            for cid, members in grouped.items():
                attackers = [m for m in members if self._nodes[m]["is_attacker"]]
                cats: set[str] = set()
                for m in members:
                    cats.update(self._nodes[m]["attack_cats"])
                self._comms.append({
                    "community_id": cid,
                    "size": len(members),
                    "attacker_count": len(attackers),
                    "attacker_ips": attackers,
                    "internal_edges": 0,
                    "attack_cats": sorted(cats),
                    "is_malicious": bool(attackers),
                    "members": members,
                })

    # meta / counts
    def meta(self) -> dict:
        return dict(self._meta)

    def totals(self) -> tuple[int, int]:
        return len(self._nodes), len(self._edges)

    def communities(self) -> list[dict]:
        return list(self._comms)

    def attacker_ids(self) -> set[str]:
        return {ip for ip, n in self._nodes.items() if n["is_attacker"]}

    def community_attack_stats(self) -> dict:
        stats: dict[int, dict] = {}
        for edge in self._edges:
            if not edge["has_attack"]:
                continue
            cid = self._nodes[edge["source"]]["community_id"]
            entry = stats.setdefault(cid, {"_id": cid, "attack_edges": 0, "attack_bytes": 0})
            entry["attack_edges"] += 1
            entry["attack_bytes"] += edge["total_bytes"]
        return stats

    def attacker_edges(self, attacker_ids: set[str]) -> list[dict]:
        return [e for e in self._edges if e["source"] in attacker_ids or e["target"] in attacker_ids]

    def nodes_by_ids(self, ids: Iterable[str]) -> dict[str, dict]:
        return {ip: self._nodes[ip] for ip in set(ids) if ip in self._nodes}

    def nodes_top(self, limit: int) -> dict[str, dict]:
        ordered = sorted(self._nodes.items(), key=lambda kv: kv[1]["pagerank"], reverse=True)
        return dict(ordered[:limit])

    def edges_among(self, ids: Iterable[str], limit: int, prefer_attack: bool = True) -> list[dict]:
        ids = set(ids)
        inside = [e for e in self._edges if e["source"] in ids and e["target"] in ids]
        if not prefer_attack:
            return inside[:limit]
        inside.sort(key=lambda e: (not e["has_attack"], -e["weight"]))
        return inside[:limit]

    def node_by_ip(self, ip: str) -> Optional[dict]:
        return self._nodes.get(_clean(ip))

    def communities_by_ids(self, comm_ids: Iterable[int]) -> list[dict]:
        wanted = set(comm_ids)
        return [c for c in self._comms if c["community_id"] in wanted]


def open_bundle(db=None):
    """Open the best available graph source (Mongo first, JSON export second)."""
    if db is not None:
        try:
            if db.graph_nodes.estimated_document_count() > 0:
                return _MongoBundle(db)
            logger.warning("graph_nodes is empty — falling back to JSON export")
        except Exception as exc:
            logger.warning("Mongo unavailable (%s) — falling back to JSON export", exc)

    if _EXPORT_JSON.exists():
        return _JsonBundle(_EXPORT_JSON)

    raise FileNotFoundError(
        "No graph data available: MongoDB has no graph_nodes and "
        f"{_EXPORT_JSON} does not exist. Run: python backend/graph/run_phase5.py all"
    )


# ── Selection + assembly ───────────────────────────────────────────────────────

def _rank_malicious(comms: list[dict], attack_stats: dict) -> list[dict]:
    """
    Rank malicious communities by severity.

    Order of precedence: attacker count → attack-edge count → attack byte volume
    → internal edge density → size. Returned richest first.
    """
    ranked: list[dict] = []
    for comm in comms:
        if not comm["is_malicious"]:
            continue
        cid = comm["community_id"]
        stats = attack_stats.get(cid) or {}
        ranked.append({
            **comm,
            "attack_edges": int(stats.get("attack_edges") or 0),
            "attack_bytes": int(stats.get("attack_bytes") or 0),
        })

    ranked.sort(
        key=lambda c: (
            c["attacker_count"],
            c["attack_edges"],
            c["attack_bytes"],
            c["internal_edges"],
            c["size"],
        ),
        reverse=True,
    )
    return ranked


def _node_payload(node: dict, n_nodes: int, malicious_ids: set[int], neighbours: set[str],
                  ranks: dict[str, int]) -> dict:
    ip = node["ip"]
    cid = node["community_id"]
    in_deg, out_deg = node["in_degree"], node["out_degree"]
    pagerank = round(node["pagerank"], 8)
    return {
        "id": ip,
        "label": ip,
        "is_attacker": node["is_attacker"],
        "community_id": cid,
        "community_malicious": cid in malicious_ids,
        "malicious_neighbor": ip in neighbours,
        "pagerank": pagerank,
        "danger_score": round(_danger_score(node["raw"], n_nodes), 8),
        "danger_rank": ranks.get(ip),
        "degree_centrality": round(float(node["raw"].get("degree") or 0.0), 6),
        "out_degree_centrality": round(float(node["raw"].get("out_degree") or 0.0), 6),
        "in_degree": in_deg,
        "out_degree": out_deg,
        "degree": in_deg + out_deg,
        "total_flows": node["total_flows"],
        "attack_cats": node["attack_cats"],
        "label_class": node["label"],
    }


def load_view(db=None, scope: str = "threat", k: int = 3,
              max_nodes: Optional[int] = None, max_edges: Optional[int] = None,
              bundle=None) -> dict[str, Any]:
    """
    Build a view-ready subgraph payload.

    Parameters
    ----------
    db        : pymongo database (optional — JSON export is the fallback)
    scope     : "threat" (Level 0) | "full" (Level 2 macro)
    k         : number of malicious communities to expand fully (<=0 → all)
    max_nodes, max_edges : override the per-scope budgets
    """
    bundle = bundle or open_bundle(db)
    scope = scope if scope in ("threat", "full") else "threat"
    node_budget = max_nodes or _MAX_NODES[scope]
    edge_budget = max_edges or _MAX_EDGES[scope]

    total_nodes, total_edges = bundle.totals()
    comms = bundle.communities()
    malicious = [c for c in comms if c["is_malicious"]]
    malicious_ids = {c["community_id"] for c in malicious}
    attackers = bundle.attacker_ids()
    attack_stats = bundle.community_attack_stats()
    ranked = _rank_malicious(comms, attack_stats)

    selected = ranked if k is None or k <= 0 else ranked[:k]
    selected_ids = [c["community_id"] for c in selected]

    # ── Level 0: attacker-centred selection ───────────────────────────────────
    neighbour_ids: set[str] = set()
    if scope == "threat":
        attacker_edges = bundle.attacker_edges(attackers)
        for edge in attacker_edges:
            neighbour_ids.add(edge["source"])
            neighbour_ids.add(edge["target"])
        neighbour_ids -= attackers

        wanted: set[str] = set(attackers)
        for comm in selected:
            wanted.update(comm["members"])
        wanted.update(neighbour_ids)

        nodes = bundle.nodes_by_ids(wanted)
        drawn_ids = set(nodes.keys())

        # Cap: attackers and their direct neighbours are structurally essential,
        # the rest of a community is ranked by danger score.
        truncated = False
        if len(drawn_ids) > node_budget:
            essential = {ip for ip, n in nodes.items() if n["is_attacker"] or ip in neighbour_ids}
            rest = sorted(
                (ip for ip in drawn_ids - essential),
                key=lambda ip: _danger_score(nodes[ip]["raw"], total_nodes),
                reverse=True,
            )
            keep = essential | set(rest[: max(0, node_budget - len(essential))])
            omitted = len(drawn_ids) - len(keep)
            drawn_ids = keep
            truncated = omitted > 0
        else:
            omitted = 0

        edges = bundle.edges_among(drawn_ids, edge_budget)
    else:
        # ── Level 2: sampled macro view ───────────────────────────────────────
        truncated = total_nodes > node_budget
        omitted = max(0, total_nodes - node_budget)
        nodes = bundle.nodes_top(node_budget)
        drawn_ids = set(nodes.keys())
        edges = bundle.edges_among(drawn_ids, edge_budget)

        # Derive "connected to an attacker" from the sampled edges
        for edge in edges:
            if not edge["has_attack"]:
                continue
            if edge["source"] in attackers:
                neighbour_ids.add(edge["target"])
            if edge["target"] in attackers:
                neighbour_ids.add(edge["source"])
        neighbour_ids -= attackers

    selected_ids = [cid for cid in selected_ids if any(
        n["community_id"] == cid for n in nodes.values()
    )]
    drawn_nodes = set(drawn_ids)

    # ── Danger ranking (for label budgets / top-N lists) ───────────────────────
    ordered = sorted(
        (n for n in nodes.values() if n["ip"] in drawn_nodes),
        key=lambda n: _danger_score(n["raw"], total_nodes),
        reverse=True,
    )
    ranks = {n["ip"]: i + 1 for i, n in enumerate(ordered)}

    node_payload = [
        _node_payload(nodes[ip], total_nodes, malicious_ids, neighbour_ids, ranks)
        for ip in drawn_nodes
    ]

    # ── Community payloads ────────────────────────────────────────────────────
    comm_payload = []
    for comm in ranked:
        cid = comm["community_id"]
        members = [m for m in comm["members"] if m in drawn_nodes]
        attack_edges = [
            e for e in edges
            if e["has_attack"] and e["source"] in drawn_nodes and e["target"] in drawn_nodes
            and nodes[e["source"]]["community_id"] == cid
            and nodes[e["target"]]["community_id"] == cid
        ]
        comm_payload.append({
            "community_id": cid,
            "size": comm["size"],
            "attacker_count": comm["attacker_count"],
            "attacker_ips": [ip for ip in comm["attacker_ips"] if ip in drawn_nodes],
            "internal_edges": comm["internal_edges"],
            "attack_cats": comm["attack_cats"],
            "is_malicious": comm["is_malicious"],
            "attack_edges": comm.get("attack_edges", 0),
            "attack_bytes": comm.get("attack_bytes", 0),
            "selected": cid in selected_ids,
            "drawn_nodes": len(members),
            "drawn_attack_edges": len(attack_edges),
            "drawn_attack_bytes": sum(e["total_bytes"] for e in attack_edges),
        })

    benign_communities = [c for c in comms if not c["is_malicious"]]

    meta = bundle.meta()
    return {
        "scope": scope,
        "nodes": node_payload,
        "edges": edges,
        "communities": comm_payload,
        "metadata": {
            "source": bundle.source,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "graph_built_at": meta.get("created_at"),
            "modularity": meta.get("modularity"),
            "scope": scope,
            "k": k,
            "selected_communities": selected_ids,
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "attacker_nodes": len(attackers),
            "attack_edges": sum(1 for e in edges if e["has_attack"]),
            "communities": len(comms),
            "malicious_communities": len(malicious),
            "benign_communities": len(benign_communities),
            "visible_nodes": len(node_payload),
            "visible_edges": len(edges),
            "visible_attack_edges": sum(1 for e in edges if e["has_attack"]),
            # What was deliberately left out — the UI reports this explicitly.
            "omitted_nodes": int(omitted),
            "omitted_communities": max(0, len(malicious) - len(selected_ids)),
            "truncated": bool(truncated),
            "danger_formula": _DANGER_FORMULA,
            "sampled": scope == "full",
        },
    }


def load_ego(ip: str, db=None, limit: int = 200, bundle=None) -> dict[str, Any]:
    """
    Level 1 expansion — one node plus its 1-hop neighbourhood, regardless of
    whether any of it sits in a flagged community.
    """
    bundle = bundle or open_bundle(db)
    total_nodes, total_edges = bundle.totals()
    ip = _clean(ip)
    if not ip:
        raise ValueError("ip is required")

    comms = bundle.communities()
    malicious_ids = {c["community_id"] for c in comms if c["is_malicious"]}
    attackers = bundle.attacker_ids()

    focus = bundle.node_by_ip(ip)
    if focus is None:
        # Unknown to the graph (e.g. a live alert IP) — return an empty ego net
        # so the UI can say so instead of drawing a fake node.
        return {
            "scope": "ego",
            "focus": ip,
            "found": False,
            "nodes": [],
            "edges": [],
            "communities": [],
            "metadata": {
                "source": bundle.source,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "visible_nodes": 0,
                "visible_edges": 0,
                "total_nodes": total_nodes,
                "total_edges": total_edges,
                "attacker_nodes": len(attackers),
                "communities": len(comms),
                "malicious_communities": len(malicious_ids),
                "omitted_nodes": total_nodes,
                "omitted_communities": 0,
                "truncated": False,
                "sampled": False,
                "danger_formula": _DANGER_FORMULA,
            },
        }

    edges = _ego_edges(bundle, ip, limit)

    ids = {ip}
    for edge in edges:
        ids.add(edge["source"])
        ids.add(edge["target"])

    nodes = bundle.nodes_by_ids(ids)
    drawn = set(nodes.keys())
    neighbour_ids = {i for i in ids if i != ip}

    ordered = sorted(
        nodes.values(),
        key=lambda n: _danger_score(n["raw"], total_nodes),
        reverse=True,
    )
    ranks = {n["ip"]: i + 1 for i, n in enumerate(ordered)}

    comm_ids = {nodes[i]["community_id"] for i in drawn}
    ego_comms: list[dict] = []
    for comm in bundle.communities_by_ids(comm_ids):
        members = [m for m in comm["members"] if m in drawn]
        ego_comms.append({
            "community_id": comm["community_id"],
            "size": comm["size"],
            "attacker_count": comm["attacker_count"],
            "attacker_ips": [a for a in comm["attacker_ips"] if a in drawn],
            "internal_edges": comm["internal_edges"],
            "attack_cats": comm["attack_cats"],
            "is_malicious": comm["is_malicious"],
            "attack_edges": 0,
            "attack_bytes": 0,
            "selected": comm["community_id"] in malicious_ids,
            "drawn_nodes": len(members),
            "drawn_attack_edges": 0,
            "drawn_attack_bytes": 0,
        })

    return {
        "scope": "ego",
        "focus": ip,
        "found": True,
        "nodes": [
            _node_payload(nodes[i], total_nodes, malicious_ids, neighbour_ids, ranks)
            for i in drawn
        ],
        "edges": [e for e in edges if e["source"] in drawn and e["target"] in drawn],
        "communities": ego_comms,
        "metadata": {
            "source": bundle.source,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "visible_nodes": len(drawn),
            "visible_edges": len(edges),
            "visible_attack_edges": sum(1 for e in edges if e["has_attack"]),
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "attacker_nodes": len(attackers),
            "communities": len(comms),
            "malicious_communities": len(malicious_ids),
            "omitted_nodes": max(0, total_nodes - len(drawn)),
            "omitted_communities": 0,
            "truncated": False,
            "sampled": False,
            "danger_formula": _DANGER_FORMULA,
        },
    }


def _ego_edges(bundle, ip: str, limit: int) -> list[dict]:
    """1-hop edges of ``ip`` — works for both bundles."""
    if isinstance(bundle, _JsonBundle):
        return bundle.edges_among({ip}, limit, prefer_attack=False)

    variants = _variants(ip)
    cursor = bundle.db.graph_edges.find(
        {"$or": [{"src_ip": {"$in": variants}}, {"dst_ip": {"$in": variants}}]},
        {"_id": 0},
    ).limit(limit)
    return [e for e in (_norm_edge(d) for d in cursor) if e]
