"""
Phase 4 — Orchestrator
=======================
Single entry point for Phase 4.  Supports three run modes:

  python run_phase4.py bloom      — build/rebuild Bloom Filter only
  python run_phase4.py simulate   — start the stream simulator only
  python run_phase4.py detect     — start the Spark streaming detector only
  python run_phase4.py all        — run simulator + detector together (two threads)

Typical first-run sequence:
    1.  python run_phase4.py bloom       # build & save the filter (~30 s)
    2a. python run_phase4.py simulate    # terminal A
    2b. python run_phase4.py detect      # terminal B
  or just:
    1.  python run_phase4.py bloom
    2.  python run_phase4.py all

Environment variables (all optional):
    STREAM_HOST, STREAM_PORT, STREAM_RPS, STREAM_LOOP
    SPARK_MASTER, SPIKE_THRESHOLD, WINDOW_SECONDS
    MONGO_URI, MONGO_DB
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from pathlib import Path

# ── Make sure the workspace root is on sys.path ────────────────────────────────
_WORKSPACE = Path(__file__).resolve().parents[2]   # c:\Users\91966\Threvia
if str(_WORKSPACE) not in sys.path:
    sys.path.insert(0, str(_WORKSPACE))

from backend.realtime.bloom_filter import ThreatBloomFilter
from backend.realtime.stream_simulator import StreamSimulator
from backend.realtime.alert_writer import AlertWriter

import os

logger = logging.getLogger(__name__)


# ── Sub-commands ───────────────────────────────────────────────────────────────

def cmd_bloom(args: argparse.Namespace) -> None:
    """Build (or rebuild) and persist the Bloom Filter."""
    force = getattr(args, "force", False)
    filter_path = Path(__file__).parent / "bloom_filter.pkl"

    if filter_path.exists() and not force:
        logger.info("Saved filter found at %s", filter_path)
        bf = ThreatBloomFilter.load()
        logger.info("Loaded filter: %d IPs", bf.ip_count)
        _verify_filter(bf)
        return

    bf = ThreatBloomFilter()
    bf.build_from_dataset()
    bf.save()
    _verify_filter(bf)


def cmd_simulate(args: argparse.Namespace) -> None:
    """Start the stream simulator (blocks until client disconnects)."""
    host = os.getenv("STREAM_HOST", "0.0.0.0")
    port = int(os.getenv("STREAM_PORT", "9999"))
    rps  = int(os.getenv("STREAM_RPS", str(getattr(args, "rps", 200))))
    loop = os.getenv("STREAM_LOOP", "1") != "0"

    sim = StreamSimulator(host=host, port=port, rows_per_second=rps, loop=loop)
    logger.info(
        "Starting stream simulator on %s:%d at %d rows/s (loop=%s)",
        host, port, rps, loop,
    )
    sim.run()


def cmd_detect(_args: argparse.Namespace) -> None:
    """Start the Spark Structured Streaming detector (blocks indefinitely)."""
    # Import here to avoid loading PySpark unless needed
    from backend.realtime.streaming_detector import run_streaming_detector
    run_streaming_detector()


def cmd_all(args: argparse.Namespace) -> None:
    """Run simulator and detector concurrently (simulator in background thread)."""
    # Ensure Bloom Filter is ready first
    filter_path = Path(__file__).parent / "bloom_filter.pkl"
    if not filter_path.exists():
        logger.info("No saved filter — building now (this may take ~30 s) …")
        bf = ThreatBloomFilter()
        bf.build_from_dataset()
        bf.save()
    else:
        logger.info("Bloom Filter found at %s — skipping rebuild.", filter_path)

    # Start simulator in a daemon thread (dies when main thread exits)
    sim_thread = threading.Thread(target=cmd_simulate, args=(args,), daemon=True, name="SimulatorThread")
    sim_thread.start()

    # Give the simulator a moment to bind the socket before the detector connects
    logger.info("Simulator thread started — waiting 3 s before starting detector …")
    time.sleep(3)

    # Detector runs in the main thread (blocks until KeyboardInterrupt)
    cmd_detect(args)


# ── Utilities ──────────────────────────────────────────────────────────────────

def _verify_filter(bf: ThreatBloomFilter) -> None:
    """Quick sanity-check against known UNSW-NB15 attacker IPs."""
    known_bad = ["175.45.176.0", "175.45.176.1", "175.45.176.2", "175.45.176.3"]
    known_good = ["8.8.8.8", "1.1.1.1", "192.168.1.100"]

    print("\n── Bloom Filter Verification ──────────────────────────────")
    all_ok = True
    for ip in known_bad:
        hit = bf.check(ip)
        tag = "✓ FLAGGED" if hit else "✗ MISSED (false negative!)"
        if not hit:
            all_ok = False
        print(f"  {ip:<22} {tag}")
    for ip in known_good:
        hit = bf.check(ip)
        tag = "✗ FALSE POSITIVE" if hit else "✓ clean"
        print(f"  {ip:<22} {tag}")

    print(f"\n  IPs in filter : {bf.ip_count}")
    print(f"  Error rate    : {bf.error_rate}")
    print(f"  Result        : {'PASS ✓' if all_ok else 'FAIL ✗ — check dataset path'}")
    print("───────────────────────────────────────────────────────────\n")


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threvia Phase 4 — Real-Time Layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # bloom
    p_bloom = sub.add_parser("bloom", help="Build/verify the Bloom Filter")
    p_bloom.add_argument("--force", action="store_true",
                         help="Rebuild even if a saved filter exists")

    # simulate
    p_sim = sub.add_parser("simulate", help="Start the stream simulator")
    p_sim.add_argument("--rps", type=int, default=200,
                       help="Rows per second (default 200)")

    # detect
    sub.add_parser("detect", help="Start the Spark streaming detector")

    # all
    p_all = sub.add_parser("all", help="Run simulator + detector together")
    p_all.add_argument("--rps", type=int, default=200,
                       help="Simulator rows per second (default 200)")

    return parser


_COMMANDS = {
    "bloom":    cmd_bloom,
    "simulate": cmd_simulate,
    "detect":   cmd_detect,
    "all":      cmd_all,
}


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    args = _build_parser().parse_args()
    _COMMANDS[args.command](args)
