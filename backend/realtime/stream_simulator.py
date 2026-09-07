"""
Phase 4B — Stream Simulator
============================
Replays UNSW-NB15 rows as a controlled-rate stream by writing newline-delimited
JSON to a socket.  Spark Structured Streaming connects as the socket source.

Design:
  - Reads all 4 UNSW-NB15 CSV files in order, row by row
  - Serialises each row as a JSON object and pushes it over TCP
  - Configurable replay speed (rows/second) and loop behaviour
  - The server listens on 0.0.0.0:9999 (STREAM_HOST / STREAM_PORT env vars)

Run standalone:
    python stream_simulator.py              # default 200 rows/s
    python stream_simulator.py --rps 500   # faster

Environment variables:
    STREAM_HOST     bind address (default 0.0.0.0)
    STREAM_PORT     TCP port     (default 9999)
    STREAM_RPS      rows/second  (default 200)
    STREAM_LOOP     1 = loop dataset forever (default 1)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import socket
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_BACKEND = _HERE.parent
_DATA_DIR = _BACKEND / "data" / "UNSW-NB15" / "CSV Files"

# ── Column names (from NUSW-NB15_features.csv) ────────────────────────────────
COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state",
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "service", "Sload", "Dload", "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
    "trans_depth", "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime",
    "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

# Fields kept in the streamed JSON (reduce payload size)
_KEEP = {"srcip", "dstip", "sport", "dsport", "proto", "service",
         "sbytes", "dbytes", "Spkts", "Dpkts", "dur",
         "attack_cat", "label"}


def _csv_files() -> list[Path]:
    files = sorted(_DATA_DIR.glob("UNSW-NB15_*.csv"))
    if not files:
        raise FileNotFoundError(f"No UNSW-NB15 CSVs in {_DATA_DIR}")
    return files


def _row_to_dict(row: list[str]) -> dict | None:
    """Convert a raw CSV row to a trimmed dict, or None if malformed."""
    if len(row) < len(COLUMNS):
        return None
    full = {COLUMNS[i]: row[i].strip() for i in range(len(COLUMNS))}
    record = {k: v for k, v in full.items() if k in _KEEP}
    # Add a wall-clock timestamp so Spark can use event-time windowing
    record["event_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return record


class StreamSimulator:
    """
    TCP server that accepts one client and streams UNSW-NB15 rows as JSON lines.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        rows_per_second: int = 200,
        loop: bool = True,
    ):
        self.host = host
        self.port = port
        self.rows_per_second = rows_per_second
        self.loop = loop
        self._sleep = 1.0 / rows_per_second

    # ── Public ─────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the server and block until the client disconnects."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(1)
            logger.info(
                "Stream simulator listening on %s:%d  (%d rows/s)",
                self.host, self.port, self.rows_per_second,
            )
            while True:
                conn, addr = srv.accept()
                logger.info("Client connected: %s", addr)
                try:
                    self._stream(conn)
                except BrokenPipeError:
                    logger.info("Client disconnected: %s", addr)
                except Exception as exc:
                    logger.error("Stream error: %s", exc)
                finally:
                    conn.close()

    # ── Internals ──────────────────────────────────────────────────────────────

    def _stream(self, conn: socket.socket) -> None:
        sent = 0
        passes = 0
        files = _csv_files()

        while True:
            passes += 1
            logger.info("Starting dataset pass #%d", passes)
            for fpath in files:
                with open(fpath, newline="", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        record = _row_to_dict(row)
                        if record is None:
                            continue
                        line = json.dumps(record) + "\n"
                        conn.sendall(line.encode("utf-8"))
                        sent += 1
                        if sent % 10_000 == 0:
                            logger.info("  Streamed %d rows", sent)
                        time.sleep(self._sleep)

            if not self.loop:
                logger.info("Dataset exhausted. Total rows streamed: %d", sent)
                break

        logger.info("Stream complete. Total: %d rows", sent)


# ── CLI ────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="UNSW-NB15 stream simulator")
    p.add_argument("--host", default=os.getenv("STREAM_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("STREAM_PORT", "9999")))
    p.add_argument("--rps", type=int, default=int(os.getenv("STREAM_RPS", "200")),
                   help="Rows per second to emit")
    p.add_argument("--no-loop", action="store_true",
                   help="Stop after one pass through the dataset")
    return p.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    args = _parse_args()
    sim = StreamSimulator(
        host=args.host,
        port=args.port,
        rows_per_second=args.rps,
        loop=not args.no_loop,
    )
    sim.run()
