"""
Phase 5 — Graph Builder
========================
Reads all UNSW-NB15 CSV files and constructs a NetworkX DiGraph where:

  Nodes  = IP addresses (src or dst)
  Edges  = network connections  src_ip → dst_ip

Node attributes:
  is_attacker   : bool  — True if the IP ever appeared as a src with label=1
  attack_cats   : set   — attack categories observed from this IP
  out_degree    : int   — number of distinct destinations contacted
  in_degree     : int   — number of distinct sources that contacted it
  total_flows   : int   — total flow count (in + out)

Edge attributes:
  weight        : int   — number of flows between this src→dst pair
  attack_cats   : set   — union of attack categories on this edge
  has_attack    : bool  — True if any flow on this edge was malicious
  proto_counts  : dict  — protocol → count breakdown

The graph is built entirely from UNSW-NB15 (the only dataset with real IPs).

Design notes:
  - Uses a two-pass approach: first accumulate raw counters in plain dicts
    (fast, no nx overhead per row), then construct the nx graph once.
  - 2.5M rows → ~seconds on a modern laptop.
  - Returns a nx.DiGraph so downstream analytics can use directed algorithms.

Usage:
    from backend.graph.graph_builder import build_graph
    G = build_graph()                # full dataset
    G = build_graph(max_rows=50000)  # quick test
"""

from __future__ import annotations

import csv
import logging
from collections import defaultdict
from pathlib import Path
from typing import Optional

import networkx as nx

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE    = Path(__file__).parent
_BACKEND = _HERE.parent
_DATA_DIR = _BACKEND / "data" / "UNSW-NB15" / "CSV Files"

# UNSW-NB15 column indices (no header row)
_COL_SRCIP      = 0
_COL_SPORT      = 1
_COL_DSTIP      = 2
_COL_DSPORT     = 3
_COL_PROTO      = 4
_COL_SBYTES     = 7    # source→dest bytes
_COL_DBYTES     = 8    # dest→source bytes
_COL_ATTACK_CAT = 47
_COL_LABEL      = 48   # "1" = attack, "0" = normal

# Known attacker IPs in UNSW-NB15
KNOWN_ATTACKER_IPS: frozenset[str] = frozenset(
    ["175.45.176.0", "175.45.176.1", "175.45.176.2", "175.45.176.3"]
)


def _csv_files() -> list[Path]:
    files = sorted(_DATA_DIR.glob("UNSW-NB15_*.csv"))
    if not files:
        raise FileNotFoundError(f"No UNSW-NB15 CSV files found in {_DATA_DIR}")
    return files


def build_graph(max_rows: Optional[int] = None) -> nx.DiGraph:
    """
    Parse all UNSW-NB15 CSV files and return a populated nx.DiGraph.

    Parameters
    ----------
    max_rows : int, optional
        If set, stop after reading this many rows (useful for quick tests).

    Returns
    -------
    nx.DiGraph
        Directed graph with node and edge attributes as described above.
    """
    logger.info("Building network graph from UNSW-NB15 …")

    # ── Accumulators (plain dicts — faster than updating nx per row) ──────────
    # node_info[ip] = {is_attacker, attack_cats, total_flows}
    node_info: dict[str, dict] = defaultdict(lambda: {
        "is_attacker": False,
        "attack_cats": set(),
        "total_flows": 0,
    })

    # edge_info[(src, dst)] = {weight, attack_cats, has_attack, proto_counts,
    #                          total_bytes}
    edge_info: dict[tuple, dict] = defaultdict(lambda: {
        "weight":       0,
        "attack_cats":  set(),
        "has_attack":   False,
        "proto_counts": defaultdict(int),
        "total_bytes":  0,
    })

    total_rows = 0
    attack_rows = 0

    for fpath in _csv_files():
        logger.info("  Reading %s …", fpath.name)
        with open(fpath, newline="", encoding="utf-8-sig", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) <= _COL_LABEL:
                    continue

                src  = row[_COL_SRCIP].strip().lstrip("\ufeff")
                dst  = row[_COL_DSTIP].strip().lstrip("\ufeff")
                proto = row[_COL_PROTO].strip().lower()
                label = row[_COL_LABEL].strip()
                cat   = row[_COL_ATTACK_CAT].strip()

                if not src or not dst:
                    continue

                is_attack = (label == "1")
                if is_attack:
                    attack_rows += 1

                # ── Node updates ──────────────────────────────────────────
                for ip in (src, dst):
                    node_info[ip]["total_flows"] += 1
                if is_attack:
                    node_info[src]["is_attacker"] = True
                    if cat:
                        node_info[src]["attack_cats"].add(cat)

                # ── Edge updates ──────────────────────────────────────────
                key = (src, dst)
                ei = edge_info[key]
                ei["weight"] += 1
                ei["proto_counts"][proto] += 1
                if is_attack:
                    ei["has_attack"] = True
                    if cat:
                        ei["attack_cats"].add(cat)

                # Bytes (may be empty string)
                try:
                    ei["total_bytes"] += int(row[_COL_SBYTES].strip() or 0)
                    ei["total_bytes"] += int(row[_COL_DBYTES].strip() or 0)
                except (ValueError, IndexError):
                    pass

                total_rows += 1
                if max_rows and total_rows >= max_rows:
                    logger.info("  max_rows=%d reached — stopping early.", max_rows)
                    break
            else:
                continue  # inner loop finished normally
            break          # max_rows triggered the inner break

    logger.info(
        "Parsed %d rows  (%d attack rows, %.1f%%)",
        total_rows, attack_rows,
        100 * attack_rows / max(total_rows, 1),
    )
    logger.info(
        "Unique nodes: %d   Unique edges: %d",
        len(node_info), len(edge_info),
    )

    # ── Build nx.DiGraph ──────────────────────────────────────────────────────
    G = nx.DiGraph()

    # Add nodes
    for ip, attrs in node_info.items():
        G.add_node(
            ip,
            is_attacker   = attrs["is_attacker"],
            attack_cats   = sorted(attrs["attack_cats"]),   # list for JSON-safety
            total_flows   = attrs["total_flows"],
            label         = "ATTACKER" if attrs["is_attacker"] else "NORMAL",
        )

    # Add edges (convert defaultdicts to plain dicts for nx)
    for (src, dst), attrs in edge_info.items():
        G.add_edge(
            src, dst,
            weight       = attrs["weight"],
            attack_cats  = sorted(attrs["attack_cats"]),
            has_attack   = attrs["has_attack"],
            proto_counts = dict(attrs["proto_counts"]),
            total_bytes  = attrs["total_bytes"],
        )

    logger.info(
        "Graph built: %d nodes, %d edges",
        G.number_of_nodes(), G.number_of_edges(),
    )
    return G


def graph_summary(G: nx.DiGraph) -> dict:
    """Return a plain-dict summary suitable for logging or dashboard display."""
    attacker_nodes = [n for n, d in G.nodes(data=True) if d.get("is_attacker")]
    attack_edges   = [(u, v) for u, v, d in G.edges(data=True) if d.get("has_attack")]

    return {
        "total_nodes":     G.number_of_nodes(),
        "total_edges":     G.number_of_edges(),
        "attacker_nodes":  len(attacker_nodes),
        "attack_edges":    len(attack_edges),
        "is_directed":     G.is_directed(),
        "avg_out_degree":  round(
            sum(d for _, d in G.out_degree()) / max(G.number_of_nodes(), 1), 2
        ),
    }


# ── CLI quick-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    G = build_graph()
    summary = graph_summary(G)

    print("\n── Graph Summary ──────────────────────────────────────────────")
    for k, v in summary.items():
        print(f"  {k:<22} {v}")

    print("\n── Attacker Node Details ──────────────────────────────────────")
    for node, data in G.nodes(data=True):
        if data.get("is_attacker"):
            print(f"  {node}")
            print(f"    attack_cats  : {data['attack_cats']}")
            print(f"    total_flows  : {data['total_flows']}")
            print(f"    out_degree   : {G.out_degree(node)}")
            print(f"    in_degree    : {G.in_degree(node)}")
    print("───────────────────────────────────────────────────────────────\n")
