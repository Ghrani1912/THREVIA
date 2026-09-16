"""
Phase 5 — Graph Writer
=======================
Persists graph analytics results to MongoDB and exports a self-contained
PyVis HTML file for the dashboard to serve.

MongoDB collections written:
  graph_nodes        — one doc per node (IP) with all centrality scores
  graph_edges        — one doc per directed edge with weight/attack attrs
  graph_communities  — one doc per community with member IPs + stats
  graph_meta         — single doc with run metadata (overwritten each run)

The PyVis export writes an interactive HTML file to:
  backend/graph/graph_export.html

Node colour coding in PyVis:
  Red    → is_attacker = True
  Orange → in a malicious community but not itself an attacker
  Blue   → normal node

Node size in PyVis:
  Scaled by PageRank (min 10, max 60)

Usage:
    from backend.graph.graph_writer import GraphWriter
    writer = GraphWriter()
    writer.write_to_mongo(G, results)
    writer.export_pyvis(G, results, "backend/graph/graph_export.html")
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx
from pymongo import MongoClient, ASCENDING, errors

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
_DB_NAME   = os.getenv("MONGO_DB", "threvia")

_COL_NODES  = "graph_nodes"
_COL_EDGES  = "graph_edges"
_COL_COMMS  = "graph_communities"
_COL_META   = "graph_meta"

_EXPORT_PATH = Path(__file__).parent / "graph_export.html"


class GraphWriter:
    """Writes Phase 5 results to MongoDB and exports PyVis HTML."""

    def __init__(self, mongo_uri: str = _MONGO_URI, db_name: str = _DB_NAME):
        self._uri     = mongo_uri
        self._db_name = db_name
        self._client: MongoClient | None = None
        self._db = None

    # ── Connection ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000)
        self._client.admin.command("ping")
        self._db = self._client[self._db_name]
        self._ensure_indexes()
        logger.info("GraphWriter connected to MongoDB (%s)", self._uri)

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "GraphWriter":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Write to MongoDB ───────────────────────────────────────────────────────

    def write_to_mongo(self, G: nx.DiGraph, results: dict) -> None:
        """Persist nodes, edges, communities and metadata to MongoDB."""
        now = datetime.now(timezone.utc)

        # ── Nodes ──────────────────────────────────────────────────────────
        logger.info("Writing %d graph nodes …", G.number_of_nodes())
        self._db[_COL_NODES].drop()   # full refresh each run
        node_docs = []
        for node, score in results["centrality_scores"].items():
            doc = dict(score)
            doc["created_at"] = now
            node_docs.append(doc)
        if node_docs:
            self._db[_COL_NODES].insert_many(node_docs)
        logger.info("  Nodes written: %d", len(node_docs))

        # ── Edges ──────────────────────────────────────────────────────────
        logger.info("Writing %d graph edges …", G.number_of_edges())
        self._db[_COL_EDGES].drop()
        edge_docs = []
        for src, dst, attrs in G.edges(data=True):
            edge_docs.append({
                "src_ip":       src,
                "dst_ip":       dst,
                "weight":       attrs.get("weight", 1),
                "has_attack":   attrs.get("has_attack", False),
                "attack_cats":  attrs.get("attack_cats", []),
                "proto_counts": attrs.get("proto_counts", {}),
                "total_bytes":  attrs.get("total_bytes", 0),
                "src_community": G.nodes[src].get("community", -1),
                "dst_community": G.nodes[dst].get("community", -1),
                "created_at":   now,
            })
        if edge_docs:
            self._db[_COL_EDGES].insert_many(edge_docs)
        logger.info("  Edges written: %d", len(edge_docs))

        # ── Communities ────────────────────────────────────────────────────
        logger.info("Writing %d communities …", len(results["community_stats"]))
        self._db[_COL_COMMS].drop()
        comm_docs = []
        for c in results["community_stats"]:
            doc = dict(c)
            doc["members"] = results["communities"].get(c["community_id"], [])
            doc["created_at"] = now
            comm_docs.append(doc)
        if comm_docs:
            self._db[_COL_COMMS].insert_many(comm_docs)
        logger.info("  Communities written: %d", len(comm_docs))

        # ── Metadata ───────────────────────────────────────────────────────
        meta_doc = dict(results["algorithm_meta"])
        meta_doc["top_nodes"]         = results["top_nodes"]
        meta_doc["flagged_malicious"] = results["flagged_malicious"]
        meta_doc["created_at"]        = now
        self._db[_COL_META].replace_one({}, meta_doc, upsert=True)
        logger.info("Metadata written.")

    # ── PyVis HTML Export ──────────────────────────────────────────────────────

    def export_json(
        self,
        G: nx.DiGraph,
        results: dict,
        output_path: str | Path = None,
    ) -> Path:
        """
        Export graph as JSON for frontend consumption (vis-network, Cytoscape, etc.).
        
        Returns a JSON file with nodes and edges arrays that can be directly
        consumed by JavaScript visualization libraries without PyVis overhead.
        
        Includes all analytics results: PageRank, danger scores, communities, etc.
        """
        import json
        
        if output_path is None:
            output_path = Path(__file__).parent / "graph_export.json"
        else:
            output_path = Path(output_path)
        
        logger.info("Exporting graph as JSON to %s …", output_path)
        
        # Get analytics from results. run_analytics() returns everything under
        # "centrality_scores"; danger scores are re-derived here with the same
        # formula so the export matches the Mongo documents / API payloads.
        scores = results.get("centrality_scores", {}) or {}
        communities = results.get("communities", {}) or {}
        community_stats = results.get("community_stats", []) or []

        n_nodes = max(G.number_of_nodes(), 1)

        def danger_score(score: dict) -> float:
            return round(
                (score.get("pagerank", 0.0) * 0.5)
                + (score.get("out_degree", 0.0) * 0.3)
                + (score.get("degree", 0.0) * 0.2),
                8,
            )

        # Build community lookups once (membership + maliciousness)
        comm_of: dict[str, int] = {}
        for comm_id, members in communities.items():
            for ip in members:
                comm_of[ip] = comm_id
        comm_mal = {c["community_id"]: c["is_malicious"] for c in community_stats}
        
        # Export nodes
        nodes = []
        for node, data in G.nodes(data=True):
            is_attacker = data.get("is_attacker", False)
            comm_id = comm_of.get(node)
            score = scores.get(node, {})
            pr = score.get("pagerank", 0.0)
            
            # Determine color based on attacker status and community
            if is_attacker:
                color = "#ff3344"  # Red - confirmed attacker
            elif comm_id is not None and comm_mal.get(comm_id):
                color = "#ffaa00"  # Orange - malicious community
            else:
                color = "#00d9ff"  # Blue - normal
            
            nodes.append({
                "id": node,
                "label": node,
                "pagerank": pr,
                "danger_score": danger_score(score),
                "is_attacker": is_attacker,
                "community_id": comm_id if comm_id is not None else -1,
                "attack_cats": data.get("attack_cats", []),
                "total_flows": data.get("total_flows", 0),
                "out_degree": G.out_degree(node),
                "in_degree": G.in_degree(node),
                "color": color,
                "size": max(10, min(60, pr * 1000)),  # Scale by PageRank
            })
        
        # Export edges
        edges = []
        for src, dst, data in G.edges(data=True):
            edges.append({
                "source": src,
                "target": dst,
                "weight": data.get("weight", 1),
                "has_attack": data.get("has_attack", False),
                "attack_cats": data.get("attack_cats", []),
                "total_bytes": data.get("total_bytes", 0),
                "proto_counts": data.get("proto_counts", {}),
                "color": "#ff4757" if data.get("has_attack") else "#00d9ff",
                "width": max(1, min(5, data.get("weight", 1) / 10)),  # Scale by weight
            })
        
        # Community payload — lets the dashboard build the attacker-centred
        # default view (malicious clusters + their members) without a second call.
        comm_payload = []
        for c in community_stats:
            comm_payload.append({
                **c,
                "members": communities.get(c["community_id"], []),
            })
        
        # Bundle with metadata
        graph_json = {
            "nodes": nodes,
            "edges": edges,
            "communities": comm_payload,
            "metadata": {
                "total_nodes": G.number_of_nodes(),
                "total_edges": G.number_of_edges(),
                "attacker_nodes": len([n for n in nodes if n["is_attacker"]]),
                "attack_edges": len([e for e in edges if e["has_attack"]]),
                "communities": len(communities),
                "malicious_communities": sum(1 for c in community_stats if c["is_malicious"]),
                "modularity": results.get("modularity"),
                "top_n": len(results.get("top_nodes", [])),
                "danger_formula": "0.5*pagerank + 0.3*out_degree_centrality + 0.2*degree_centrality",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        }
        
        # Write JSON
        with open(output_path, 'w') as f:
            json.dump(graph_json, f, indent=2)
        
        logger.info("JSON graph exported: %s (%d nodes, %d edges)",
                   output_path, len(nodes), len(edges))
        return output_path

    def export_pyvis(
        self,
        G: nx.DiGraph,
        results: dict,
        output_path: str | Path | None = None,
    ) -> Path:
        """
        Generate an interactive PyVis HTML graph and save it to disk.

        Returns the path of the written HTML file.
        """
        try:
            from pyvis.network import Network
        except ImportError:
            logger.error(
                "pyvis not installed — skipping HTML export. "
                "Install with: pip install pyvis==0.3.2"
            )
            return None

        output_path = Path(output_path) if output_path else _EXPORT_PATH
        logger.info("Exporting PyVis graph to %s …", output_path)

        # Build lookup for community maliciousness
        malicious_comms: set[int] = {
            c["community_id"]
            for c in results["community_stats"]
            if c["is_malicious"]
        }

        # PageRank → node size  (normalise to [10, 60])
        pr_values = [s["pagerank"] for s in results["centrality_scores"].values()]
        pr_min, pr_max = min(pr_values), max(pr_values)
        pr_range = max(pr_max - pr_min, 1e-10)

        def node_size(pr: float) -> float:
            return 10 + 50 * (pr - pr_min) / pr_range

        net = Network(
            height="750px",
            width="100%",
            directed=True,
            bgcolor="#1a1a2e",
            font_color="#e0e0e0",
            notebook=False,
        )
        net.barnes_hut(gravity=-8000, central_gravity=0.3,
                       spring_length=120, spring_strength=0.04)

        # Add nodes
        for node, score in results["centrality_scores"].items():
            is_attacker = score["is_attacker"]
            community   = score.get("community_id", -1)
            pr          = score["pagerank"]

            if is_attacker:
                color = "#e63946"       # red — confirmed attacker
                border = "#ff0000"
            elif community in malicious_comms:
                color = "#f4a261"       # orange — in malicious community
                border = "#e76f51"
            else:
                color = "#457b9d"       # blue — normal
                border = "#1d3557"

            title = (
                f"<b>{node}</b><br>"
                f"PageRank: {pr:.6f}<br>"
                f"Out-degree: {score['raw_out_deg']}<br>"
                f"In-degree: {score['raw_in_deg']}<br>"
                f"Flows: {score['total_flows']}<br>"
                f"Community: {community}<br>"
                f"Attack cats: {', '.join(score['attack_cats']) or 'none'}<br>"
                f"Label: {score['label']}"
            )

            net.add_node(
                node,
                label     = node,
                title     = title,
                size      = node_size(pr),
                color     = {"background": color, "border": border,
                             "highlight": {"background": "#ffff00"}},
                font      = {"size": 12, "color": "#ffffff"},
            )

        # Add edges
        for src, dst, attrs in G.edges(data=True):
            weight     = attrs.get("weight", 1)
            has_attack = attrs.get("has_attack", False)
            cats       = ", ".join(attrs.get("attack_cats", [])) or "normal"

            # Scale edge width: log scale capped at 10
            import math
            width = min(1 + math.log1p(weight) * 0.8, 10)

            edge_color = "#e63946" if has_attack else "#6b6b8a"
            net.add_edge(
                src, dst,
                value = width,
                color = edge_color,
                title = (
                    f"{src} → {dst}<br>"
                    f"Flows: {weight}<br>"
                    f"Bytes: {attrs.get('total_bytes', 0):,}<br>"
                    f"Attack: {'YES' if has_attack else 'no'}<br>"
                    f"Categories: {cats}"
                ),
                arrows = "to",
            )

        net.set_options("""
        {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 120
            }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
          },
          "edges": {
            "smooth": {"type": "curvedCW", "roundness": 0.2}
          }
        }
        """)

        net.save_graph(str(output_path))
        logger.info("PyVis HTML exported: %s  (%d nodes, %d edges)",
                    output_path, G.number_of_nodes(), G.number_of_edges())
        return output_path

    # ── Query helpers (for dashboard) ─────────────────────────────────────────

    def get_top_nodes(self, limit: int = 20) -> list[dict]:
        meta = self._db[_COL_META].find_one({}, {"_id": 0, "top_nodes": 1})
        if meta:
            return meta.get("top_nodes", [])[:limit]
        return []

    def get_flagged_malicious(self) -> list[dict]:
        meta = self._db[_COL_META].find_one({}, {"_id": 0, "flagged_malicious": 1})
        if meta:
            return meta.get("flagged_malicious", [])
        return []

    def get_malicious_communities(self) -> list[dict]:
        cursor = (
            self._db[_COL_COMMS]
            .find({"is_malicious": True}, {"_id": 0})
            .sort("size", -1)
        )
        return list(cursor)

    def get_community_for_ip(self, ip: str) -> dict | None:
        node = self._db[_COL_NODES].find_one({"ip": ip}, {"_id": 0})
        if not node:
            return None
        cid = node.get("community_id", -1)
        return self._db[_COL_COMMS].find_one({"community_id": cid}, {"_id": 0})

    # ── Internals ──────────────────────────────────────────────────────────────

    def _col(self, name: str):
        if self._db is None:
            self.connect()
        return self._db[name]

    def _ensure_indexes(self) -> None:
        try:
            self._db[_COL_NODES].create_index([("ip",        ASCENDING)], background=True)
            self._db[_COL_NODES].create_index([("pagerank",  ASCENDING)], background=True)
            self._db[_COL_NODES].create_index([("is_attacker", ASCENDING)], background=True)
            self._db[_COL_EDGES].create_index([("src_ip",    ASCENDING)], background=True)
            self._db[_COL_EDGES].create_index([("has_attack",ASCENDING)], background=True)
            self._db[_COL_COMMS].create_index([("community_id", ASCENDING)], background=True)
        except errors.PyMongoError as exc:
            logger.warning("Index creation warning: %s", exc)
