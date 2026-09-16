"""
Phase 5 — Orchestrator
=======================
Single entry point for Phase 5.  Run modes:

  python run_phase5.py build     — build graph only, print summary
  python run_phase5.py analyse   — build + run analytics, print results
  python run_phase5.py write     — build + analyse + write to MongoDB
  python run_phase5.py export    — build + analyse + export PyVis HTML only
  python run_phase5.py all       — build + analyse + write + export (default)

Options:
  --max-rows N   cap dataset rows (useful for quick testing, e.g. 50000)
  --top-n N      number of top nodes to report (default 20)
  --output PATH  PyVis HTML output path (default backend/graph/graph_export.html)

Environment variables:
  MONGO_URI      MongoDB connection string (default mongodb://localhost:27017/)
  MONGO_DB       database name (default threvia)

Usage examples:
  # Quick test (50k rows, no Mongo)
  python backend/graph/run_phase5.py analyse --max-rows 50000

  # Full run: build + write MongoDB + export HTML
  python backend/graph/run_phase5.py all

  # From workspace root:
  python -m backend.graph.run_phase5 all
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# ── Ensure workspace root is on sys.path ──────────────────────────────────────
_WORKSPACE = Path(__file__).resolve().parents[2]
if str(_WORKSPACE) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE))

from backend.graph.graph_builder import build_graph, graph_summary
from backend.graph.graph_analytics import run_analytics, print_summary
from backend.graph.graph_writer import GraphWriter

logger = logging.getLogger(__name__)


# ── Sub-commands ───────────────────────────────────────────────────────────────

def cmd_build(args: argparse.Namespace) -> None:
    G = build_graph(max_rows=args.max_rows)
    summary = graph_summary(G)
    print("\n── Graph Summary ──────────────────────────────────────")
    for k, v in summary.items():
        print(f"  {k:<22} {v}")
    print()


def cmd_analyse(args: argparse.Namespace) -> None:
    G = build_graph(max_rows=args.max_rows)
    results = run_analytics(G, top_n=args.top_n)
    print_summary(results)


def cmd_write(args: argparse.Namespace) -> None:
    G = build_graph(max_rows=args.max_rows)
    results = run_analytics(G, top_n=args.top_n)
    print_summary(results)
    with GraphWriter() as writer:
        writer.write_to_mongo(G, results)
    logger.info("Phase 5 results written to MongoDB.")


def cmd_export(args: argparse.Namespace) -> None:
    G = build_graph(max_rows=args.max_rows)
    results = run_analytics(G, top_n=args.top_n)
    output = Path(args.output) if args.output else None
    writer = GraphWriter()
    out_path = writer.export_pyvis(G, results, output_path=output)
    if out_path:
        print(f"\nPyVis graph exported → {out_path}")
        print("Open that file in a browser to view the interactive network graph.")


def cmd_all(args: argparse.Namespace) -> None:
    t0 = time.time()

    # 1. Build graph
    logger.info("Step 1/3 — Building graph …")
    G = build_graph(max_rows=args.max_rows)
    summary = graph_summary(G)
    logger.info(
        "Graph: %d nodes, %d edges, %d attacker nodes",
        summary["total_nodes"], summary["total_edges"], summary["attacker_nodes"],
    )

    # 2. Run analytics
    logger.info("Step 2/3 — Running analytics …")
    results = run_analytics(G, top_n=args.top_n)
    print_summary(results)

    # 3. Write to MongoDB + export HTML + JSON
    logger.info("Step 3/3 — Persisting results …")
    output = Path(args.output) if args.output else None
    with GraphWriter() as writer:
        writer.write_to_mongo(G, results)
        html_path = writer.export_pyvis(G, results, output_path=output)
        json_path = writer.export_json(G, results)  # NEW: Export JSON

    elapsed = time.time() - t0
    print("\n══════════════════════════════════════════════════════════")
    print(f"  Phase 5 complete in {elapsed:.1f}s")
    print(f"  MongoDB: graph_nodes, graph_edges, graph_communities, graph_meta")
    if html_path:
        print(f"  PyVis HTML: {html_path}")
    if json_path:
        print(f"  JSON export: {json_path}")
    print("══════════════════════════════════════════════════════════\n")


# ── CLI ────────────────────────────────────────────────────────────────────────

_COMMANDS = {
    "build":   cmd_build,
    "analyse": cmd_analyse,
    "write":   cmd_write,
    "export":  cmd_export,
    "all":     cmd_all,
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Threvia Phase 5 — Graph Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", required=True)

    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--max-rows", type=int, default=None,
                        help="Cap dataset rows for quick testing")
    shared.add_argument("--top-n", type=int, default=20,
                        help="Top N nodes to report (default 20)")
    shared.add_argument("--output", type=str, default=None,
                        help="PyVis HTML output path")

    for cmd in _COMMANDS:
        sub.add_parser(cmd, parents=[shared],
                       help=f"Run phase5 {cmd} step")

    return p


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    args = _build_parser().parse_args()
    _COMMANDS[args.command](args)
