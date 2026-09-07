"""
Phase 5 — Graph Analytics
==========================
Runs graph algorithms on the NetworkX DiGraph produced by graph_builder.py.

Algorithms:
  1. Degree Centrality   — in + out degree normalized by (n-1)
                           High score → likely scanner / C&C server
  2. In-Degree Centrality — how many unique sources target this IP
                           High score → likely victim / honeypot
  3. PageRank            — probabilistic influence score (directed)
                           High score → influential node in attack flow
  4. Louvain Community Detection
                         — clusters IPs that communicate heavily together
                           Reveals botnets / coordinated attack groups
                         — Louvain is defined on undirected graphs, so we
                           convert to undirected (preserving edge weights)
                           before running community detection, then map
                           community labels back to the directed graph.

Outputs (all returned as plain dicts for easy MongoDB insertion):
  - centrality_scores   : {ip: {degree, in_degree, out_degree, pagerank}}
  - communities         : {community_id: [ip, ...]}
  - top_nodes           : list of top-N most dangerous nodes with all scores
  - flagged_malicious   : nodes with is_attacker=True, sorted by PageRank

Usage:
    from backend.graph.graph_builder import build_graph
    from backend.graph.graph_analytics import run_analytics
    G = build_graph()
    results = run_analytics(G, top_n=20)
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

logger = logging.getLogger(__name__)


def run_analytics(G: nx.DiGraph, top_n: int = 20) -> dict[str, Any]:
    """
    Run all graph algorithms on G and return structured results.

    Parameters
    ----------
    G     : nx.DiGraph produced by graph_builder.build_graph()
    top_n : number of top nodes to include in ranked lists

    Returns
    -------
    dict with keys:
        centrality_scores, communities, top_nodes, flagged_malicious,
        community_stats, algorithm_meta
    """
    n = G.number_of_nodes()
    if n == 0:
        raise ValueError("Graph has no nodes — run build_graph() first.")

    logger.info("Running graph analytics on %d nodes, %d edges …",
                n, G.number_of_edges())

    results: dict[str, Any] = {}

    # ── 1. Degree Centrality ──────────────────────────────────────────────────
    logger.info("  Computing degree centrality …")
    deg_cent    = nx.degree_centrality(G)           # uses total degree
    in_deg_cent = nx.in_degree_centrality(G)
    out_deg_cent= nx.out_degree_centrality(G)

    # ── 2. PageRank ───────────────────────────────────────────────────────────
    logger.info("  Computing PageRank …")
    # Use edge weight so high-traffic connections carry more influence
    pagerank = nx.pagerank(G, alpha=0.85, weight="weight", max_iter=200)

    # ── 3. Merge centrality scores ────────────────────────────────────────────
    centrality_scores: dict[str, dict] = {}
    for node in G.nodes():
        node_data = G.nodes[node]
        centrality_scores[node] = {
            "ip":           node,
            "degree":       round(deg_cent.get(node, 0.0),     6),
            "in_degree":    round(in_deg_cent.get(node, 0.0),  6),
            "out_degree":   round(out_deg_cent.get(node, 0.0), 6),
            "pagerank":     round(pagerank.get(node, 0.0),     8),
            "raw_in_deg":   G.in_degree(node),
            "raw_out_deg":  G.out_degree(node),
            "total_flows":  node_data.get("total_flows", 0),
            "is_attacker":  node_data.get("is_attacker", False),
            "attack_cats":  node_data.get("attack_cats", []),
            "label":        node_data.get("label", "NORMAL"),
        }

    results["centrality_scores"] = centrality_scores

    # ── 4. Louvain Community Detection ────────────────────────────────────────
    logger.info("  Running Louvain community detection …")

    # Convert to undirected, summing weights for bidirectional edges
    G_und = G.to_undirected(reciprocal=False)

    # python-louvain returns {node: community_id}
    try:
        import community as community_louvain  # python-louvain package
        partition = community_louvain.best_partition(
            G_und, weight="weight", random_state=42
        )
        modularity = community_louvain.modularity(partition, G_und, weight="weight")
        logger.info("  Louvain modularity: %.4f", modularity)
    except ImportError:
        # Fallback: Greedy modularity (built into networkx)
        logger.warning(
            "python-louvain not installed — falling back to nx greedy_modularity_communities"
        )
        from networkx.algorithms.community import greedy_modularity_communities
        comm_sets = list(greedy_modularity_communities(G_und, weight="weight"))
        partition = {}
        for cid, node_set in enumerate(comm_sets):
            for node in node_set:
                partition[node] = cid
        modularity = None

    # Map community id back to directed graph nodes
    nx.set_node_attributes(G, partition, "community")

    # Group nodes by community
    communities: dict[int, list[str]] = {}
    for node, cid in partition.items():
        communities.setdefault(cid, []).append(node)

    # Enrich each community with stats
    community_stats = []
    for cid, members in communities.items():
        attackers  = [m for m in members if G.nodes[m].get("is_attacker")]
        edge_count = sum(
            1 for u, v in G.edges()
            if partition.get(u) == cid and partition.get(v) == cid
        )
        # Collect all attack categories seen in this community
        cats: set[str] = set()
        for m in members:
            cats.update(G.nodes[m].get("attack_cats", []))

        community_stats.append({
            "community_id":   cid,
            "size":           len(members),
            "attacker_count": len(attackers),
            "attacker_ips":   attackers,
            "internal_edges": edge_count,
            "attack_cats":    sorted(cats),
            "is_malicious":   len(attackers) > 0,
        })

    community_stats.sort(key=lambda x: x["size"], reverse=True)
    results["communities"]     = communities
    results["community_stats"] = community_stats
    results["modularity"]      = modularity

    # Write community id into centrality_scores for cross-referencing
    for node, score in centrality_scores.items():
        score["community_id"] = partition.get(node, -1)

    # ── 5. Top-N most dangerous nodes ────────────────────────────────────────
    logger.info("  Ranking top %d nodes …", top_n)

    # Danger score = weighted combination of pagerank + out_degree_centrality
    # (attackers that send many connections to many targets rank high)
    def danger_score(s: dict) -> float:
        return (s["pagerank"] * 0.5) + (s["out_degree"] * 0.3) + (s["degree"] * 0.2)

    ranked = sorted(
        centrality_scores.values(),
        key=danger_score,
        reverse=True,
    )
    top_nodes = []
    for rank, node_scores in enumerate(ranked[:top_n], start=1):
        entry = dict(node_scores)
        entry["rank"] = rank
        entry["danger_score"] = round(danger_score(node_scores), 8)
        top_nodes.append(entry)

    results["top_nodes"] = top_nodes

    # ── 6. Flagged malicious nodes ────────────────────────────────────────────
    flagged = [
        s for s in centrality_scores.values()
        if s["is_attacker"]
    ]
    flagged.sort(key=lambda s: s["pagerank"], reverse=True)
    results["flagged_malicious"] = flagged

    # ── 7. Algorithm metadata ─────────────────────────────────────────────────
    results["algorithm_meta"] = {
        "nodes":          n,
        "edges":          G.number_of_edges(),
        "communities":    len(communities),
        "modularity":     modularity,
        "attacker_nodes": len(flagged),
        "top_n":          top_n,
        "algorithms":     ["degree_centrality", "pagerank", "louvain"],
    }

    logger.info(
        "Analytics complete: %d communities, %d attackers flagged",
        len(communities), len(flagged),
    )
    return results


def print_summary(results: dict) -> None:
    """Pretty-print analytics results to stdout."""
    meta = results["algorithm_meta"]
    print("\n── Graph Analytics Summary ────────────────────────────────────")
    print(f"  Nodes           : {meta['nodes']}")
    print(f"  Edges           : {meta['edges']}")
    print(f"  Communities     : {meta['communities']}")
    print(f"  Modularity      : {meta['modularity']}")
    print(f"  Attacker nodes  : {meta['attacker_nodes']}")

    print("\n── Top 10 Most Dangerous Nodes ─────────────────────────────────")
    header = f"  {'Rank':<5} {'IP':<22} {'PageRank':<12} {'OutDeg':<10} {'Danger':<10} {'Attacker':<10} {'Community'}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for n in results["top_nodes"][:10]:
        print(
            f"  {n['rank']:<5} {n['ip']:<22} {n['pagerank']:<12.6f} "
            f"{n['raw_out_deg']:<10} {n['danger_score']:<10.6f} "
            f"{'YES' if n['is_attacker'] else 'no':<10} {n['community_id']}"
        )

    print("\n── Flagged Malicious Nodes ─────────────────────────────────────")
    for node in results["flagged_malicious"]:
        print(f"  {node['ip']:<22}  pagerank={node['pagerank']:.6f}  "
              f"cats={node['attack_cats']}  community={node['community_id']}")

    print("\n── Community Summary (top 5 by size) ───────────────────────────")
    for c in results["community_stats"][:5]:
        mal = "⚠ MALICIOUS" if c["is_malicious"] else "  benign"
        print(f"  Community {c['community_id']:<4}  "
              f"size={c['size']:<6}  attackers={c['attacker_count']}  "
              f"cats={c['attack_cats']}  {mal}")
    print("────────────────────────────────────────────────────────────────\n")


# ── CLI ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from backend.graph.graph_builder import build_graph
    G = build_graph()
    results = run_analytics(G, top_n=20)
    print_summary(results)
