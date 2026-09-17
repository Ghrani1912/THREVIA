"""
Phase 4B — Stream Simulator (CIC-2017 Edition)
================================================
Replays CIC-IDS-2017 Friday Parquet flows as a controlled-rate stream by
writing newline-delimited JSON to a TCP socket.  Spark Structured Streaming
connects as the socket source.

Why CIC-2017 (not UNSW-NB15)?
  The production RF / KMeans models were trained on CIC-2017 feature columns.
  Replaying CIC-2017 flows lets Pipeline C score each record with real features
  instead of zero-filled placeholders.

Data source:
  hdfs://namenode:8020/threvia/corpus/friday_ddos_test   (CIC-2017 Friday Parquet)
  hdfs://namenode:8020/threvia/corpus/friday_bot_test    (CIC-2017 Friday Parquet)
  hdfs://namenode:8020/threvia/corpus/friday_benign_c2   (CIC-2017 Friday Parquet)
  (read directly from HDFS via pyspark in a background thread on startup)

Design:
  - Reads all three Friday corpora into memory (they fit: ~350 K rows total)
  - Shuffles rows once, then replays indefinitely
  - Serialises each row as a JSON object with all CANONICAL_FEATURE_COLS fields
  - Injects a live event_time wall-clock timestamp per row
  - Also emits srcip / dstip meta fields for the Bloom Filter pipeline

Run standalone:
    python stream_simulator.py              # default 200 rows/s
    python stream_simulator.py --rps 500   # faster

Environment variables:
    STREAM_HOST     bind address (default 0.0.0.0)
    STREAM_PORT     TCP port     (default 9999)
    STREAM_RPS      rows/second  (default 200)
    STREAM_LOOP     1 = loop dataset forever (default 1)
    HDFS_CORPUS     HDFS base path (default hdfs://namenode:8020/threvia/corpus)
    SPARK_MASTER    Spark master URL used to read Parquet (default spark://spark-master:7077)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import socket
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── HDFS paths ──────────────────────────────────────────────────────────────
_HDFS_CORPUS  = os.getenv("HDFS_CORPUS", "hdfs://namenode:8020/threvia/corpus")
_SPARK_MASTER = os.getenv("SPARK_MASTER", "spark://spark-master:7077")

_FRIDAY_PATHS = [
    # Use FIXED balanced demo (150K rows, real attacks from training data)
    f"{_HDFS_CORPUS}/demo_balanced_150k_fixed",
]

# Metadata / identity columns emitted alongside feature columns
_META_COLS = {
    "Source IP", "Destination IP", "Destination Port",
    "Flow ID", "Protocol", "Timestamp", "Label",
}

# ── Feature column list (must match CANONICAL_FEATURE_COLS in schema_maps.py)
# We emit all of them so the streaming detector can feed them directly to the
# pre-trained scaler pipeline without any fill-in.
FEATURE_COLS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Columns to emit in the JSON stream (features + meta)
_EMIT_COLS = set(FEATURE_COLS) | {"Source IP", "Destination IP", "Label", "is_attack"}


def _load_rows_from_hdfs() -> list[dict[str, Any]]:
    """
    Use PySpark to read the three Friday Parquet corpora and return them as a
    list of plain Python dicts.  Called once at startup.
    """
    try:
        from pyspark.sql import SparkSession
    except ImportError:
        raise RuntimeError("PySpark not found. Install pyspark or run inside the Spark container.")

    logger.info("Loading Friday CIC-2017 corpora from HDFS …")
    spark = (
        SparkSession.builder
        .master(_SPARK_MASTER)
        .appName("Threvia-StreamSimulator-Loader")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.driver.memory", "1g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    dfs = []
    for path in _FRIDAY_PATHS:
        try:
            df = spark.read.parquet(path)
            # Keep only columns we will emit (avoids JSON bloat)
            keep = [c for c in df.columns if c in _EMIT_COLS]
            dfs.append(df.select(keep))
            logger.info("  Loaded %s", path)
        except Exception as exc:
            logger.warning("  Could not load %s: %s", path, exc)

    if not dfs:
        spark.stop()
        raise RuntimeError("No Friday Parquet data could be loaded from HDFS.")

    combined = dfs[0]
    for df in dfs[1:]:
        combined = combined.unionByName(df, allowMissingColumns=True)

    rows = [row.asDict() for row in combined.collect()]
    spark.stop()
    logger.info("Loaded %d total flows for simulation.", len(rows))
    return rows


def _sanitise(val: Any) -> Any:
    """Convert Spark Row values to JSON-serialisable types."""
    if val is None:
        return 0.0
    if isinstance(val, (int, float, str, bool)):
        return val
    return float(val)


def _row_to_json(row: dict[str, Any]) -> str:
    """Serialise a flow dict to a JSON line."""
    import random
    record: dict[str, Any] = {k: _sanitise(v) for k, v in row.items()}
    
    # Generate realistic IPs with attack clustering for spike detection
    attack_label = record.get("Label", "BENIGN")
    if attack_label == "BENIGN":
        # BENIGN: diverse private IPs
        src_ip = f"{random.choice([10, 192, 172])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    else:
        # ATTACKS: cluster into ~20 attacker IPs for spike detection
        attacker_pool = [
            "45.142.212.61", "45.142.212.62", "45.142.212.63", "45.142.212.64", "45.142.212.65",
            "76.119.135.10", "76.119.135.11", "76.119.135.12", "76.119.135.13", "76.119.135.14",
            "153.92.47.88", "153.92.47.89", "153.92.47.90", "153.92.47.91", "153.92.47.92",
            "198.50.200.100", "198.50.200.101", "198.50.200.102", "198.50.200.103", "198.50.200.104",
        ]
        src_ip = random.choice(attacker_pool)  # Pick from pool for clustering
    
    dst_ip = f"{random.choice([192, 10, 172])}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    # Normalise identity columns used by existing pipelines.
    # NOTE: capture the class BEFORE popping -- `record.pop("Label")` removes the
    # key, so any later `record.get("Label")` silently falls back to "BENIGN".
    # That bug shipped every attack flow with attack_cat="BENIGN", which is what
    # made per-attack-type FP attribution on the stream untrustworthy.
    true_label = str(record.get("Label", "BENIGN"))
    record["srcip"]      = record.pop("Source IP", src_ip)
    record["dstip"]      = record.pop("Destination IP", dst_ip)
    record["label"]      = str(record.pop("is_attack", record.pop("Label", "0")))
    record["attack_cat"] = true_label
    record["event_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return json.dumps(record)


class StreamSimulator:
    """
    TCP server that accepts one client and streams CIC-2017 Friday rows as
    JSON lines.  The dataset is loaded from HDFS at construction time.
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

        logger.info("Loading dataset from HDFS …")
        self._rows = _load_rows_from_hdfs()
        # Shuffle once so we get a natural mix of classes from the start
        random.shuffle(self._rows)
        logger.info("Dataset ready: %d flows", len(self._rows))

    # ── Public ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start file-based streaming immediately, and optionally serve TCP."""
        import os
        
        stream_dir = "/tmp/threvia_stream"
        os.makedirs(stream_dir, exist_ok=True)
        logger.info("Created stream directory: %s", stream_dir)
        
        # Start TCP server in background (optional, for backward compatibility)
        import threading
        tcp_thread = threading.Thread(target=self._tcp_server, daemon=True)
        tcp_thread.start()
        
        # Start file streaming immediately
        self._stream_to_files()
    
    def _tcp_server(self) -> None:
        """Background TCP server for backward compatibility."""
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
                    # Just keep connection open, files are written by main thread
                    conn.recv(1024)
                except:
                    pass
                finally:
                    logger.info("Client disconnected: %s", addr)
                    conn.close()
    
    def _stream_to_files(self) -> None:
        """Write JSON files to /tmp/threvia_stream for Spark file streaming"""
        import os
        sent = 0
        passes = 0
        file_num = 0
        
        stream_dir = "/tmp/threvia_stream"

        while True:
            passes += 1
            logger.info("Starting dataset pass #%d (%d rows)", passes, len(self._rows))
            
            batch_size = 1000  # Write 1000 rows per file
            batch = []
            
            for row in self._rows:
                line = _row_to_json(row)
                batch.append(line)
                
                sent += 1
                
                # Write batch to file
                if len(batch) >= batch_size:
                    file_num += 1
                    temp_path = f"{stream_dir}/.tmp_{file_num}.json"
                    final_path = f"{stream_dir}/batch_{file_num:06d}.json"
                    
                    with open(temp_path, 'w') as f:
                        f.write('\n'.join(batch) + '\n')
                    os.rename(temp_path, final_path)
                    
                    batch = []
                
                if sent % 10_000 == 0:
                    logger.info("  Streamed %d rows", sent)
                time.sleep(self._sleep)
            
            # Write remaining batch
            if batch:
                file_num += 1
                temp_path = f"{stream_dir}/.tmp_{file_num}.json"
                final_path = f"{stream_dir}/batch_{file_num:06d}.json"
                
                with open(temp_path, 'w') as f:
                    f.write('\n'.join(batch) + '\n')
                os.rename(temp_path, final_path)

            if not self.loop:
                logger.info("Dataset exhausted. Total rows streamed: %d", sent)
                break

        logger.info("Stream complete. Total: %d rows", sent)


# ── CLI ─────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CIC-2017 stream simulator")
    p.add_argument("--host", default=os.getenv("STREAM_HOST", "0.0.0.0"))
    p.add_argument("--port", type=int, default=int(os.getenv("STREAM_PORT", "9999")))
    p.add_argument("--rps",  type=int, default=int(os.getenv("STREAM_RPS",  "200")),
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
