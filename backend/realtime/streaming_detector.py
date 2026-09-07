"""
Phase 4B — Spark Structured Streaming Detector
================================================
Connects to the stream_simulator's TCP socket, parses JSON rows,
and runs two detection pipelines:

  1. Bloom Filter check   — every row whose src_ip is in the filter
                            is flagged immediately and written to MongoDB.

  2. Windowed spike alert — a 60-second tumbling window counts connections
                            per src_ip.  When the count exceeds SPIKE_THRESHOLD
                            (default 50), a severity-graded alert is emitted
                            to MongoDB.

Severity mapping (connections per window):
  ≥ 500   → Critical
  ≥ 200   → High
  ≥  50   → Medium
  (below threshold — no alert)

The job runs in local[*] mode so it works without a separate Spark cluster.
To submit to the running Spark master instead, change SPARK_MASTER to
"spark://spark-master:7077" in the environment.

Environment variables:
    STREAM_HOST       simulator host (default localhost)
    STREAM_PORT       simulator port (default 9999)
    SPARK_MASTER      spark master URL (default local[*])
    SPIKE_THRESHOLD   min connections/window for alert (default 50)
    WINDOW_SECONDS    tumbling window size in seconds (default 60)
    MONGO_URI         MongoDB connection string
    MONGO_DB          database name (default threvia)

Dependencies: pyspark>=3.3, pybloom-live, pymongo
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    DoubleType,
    StringType,
    StructField,
    StructType,
)

from backend.realtime.bloom_filter import ThreatBloomFilter
from backend.realtime.alert_writer import AlertWriter

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
STREAM_HOST = os.getenv("STREAM_HOST", "localhost")
STREAM_PORT = int(os.getenv("STREAM_PORT", "9999"))
SPARK_MASTER = os.getenv("SPARK_MASTER", "local[*]")
SPIKE_THRESHOLD = int(os.getenv("SPIKE_THRESHOLD", "50"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "threvia")

# JSON schema emitted by stream_simulator
_SCHEMA = StructType([
    StructField("srcip",       StringType(), True),
    StructField("dstip",       StringType(), True),
    StructField("sport",       StringType(), True),
    StructField("dsport",      StringType(), True),
    StructField("proto",       StringType(), True),
    StructField("service",     StringType(), True),
    StructField("sbytes",      StringType(), True),
    StructField("dbytes",      StringType(), True),
    StructField("Spkts",       StringType(), True),
    StructField("Dpkts",       StringType(), True),
    StructField("dur",         StringType(), True),
    StructField("attack_cat",  StringType(), True),
    StructField("label",       StringType(), True),
    StructField("event_time",  StringType(), True),
])


def _severity(count: int) -> str:
    if count >= 500:
        return "Critical"
    if count >= 200:
        return "High"
    return "Medium"


# ── Bloom foreachBatch handler ─────────────────────────────────────────────────

def _bloom_batch_handler(bloom: ThreatBloomFilter, writer: AlertWriter):
    """
    Returns a foreachBatch function that checks every row against the
    Bloom Filter and bulk-writes hits to MongoDB.
    """
    def handler(batch_df, batch_id: int):
        rows = batch_df.collect()
        if not rows:
            return

        hits = []
        for row in rows:
            if bloom.check(row["srcip"] or ""):
                hits.append({
                    "src_ip":     row["srcip"],
                    "dst_ip":     row["dstip"],
                    "proto":      row["proto"],
                    "service":    row["service"],
                    "attack_cat": row["attack_cat"],
                    "label":      row["label"],
                    "event_time": row["event_time"],
                })

        if hits:
            written = writer.write_bloom_hits_bulk(hits)
            logger.info("Batch %d: %d/%d rows flagged by Bloom Filter",
                        batch_id, written, len(rows))

    return handler


# ── Spike foreachBatch handler ─────────────────────────────────────────────────

def _spike_batch_handler(writer: AlertWriter):
    """
    Returns a foreachBatch function for the windowed aggregation stream.
    Rows that exceed SPIKE_THRESHOLD are written as spike alerts.
    """
    def handler(batch_df, batch_id: int):
        rows = batch_df.collect()
        alerts = []
        for row in rows:
            count = int(row["connection_count"])
            if count >= SPIKE_THRESHOLD:
                severity = _severity(count)
                alerts.append({
                    "src_ip":           row["srcip"],
                    "window_start":     str(row["window_start"]),
                    "window_end":       str(row["window_end"]),
                    "connection_count": count,
                    "total_bytes":      float(row["total_bytes"] or 0.0),
                    "attack_label":     row["majority_label"] or "unknown",
                    "severity":         severity,
                })

        if alerts:
            written = writer.write_spike_alerts_bulk(alerts)
            logger.info("Batch %d: %d spike alerts written (threshold=%d)",
                        batch_id, written, SPIKE_THRESHOLD)

    return handler


# ── Main streaming job ─────────────────────────────────────────────────────────

def run_streaming_detector() -> None:
    """
    Start the Spark Structured Streaming job.
    Blocks indefinitely; press Ctrl-C to stop.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── 1. Load / build Bloom Filter ──────────────────────────────────────────
    logger.info("Loading Bloom Filter …")
    bloom = ThreatBloomFilter.load_or_build()
    logger.info("Bloom Filter ready: %d malicious IPs", bloom.ip_count)

    # ── 2. Connect to MongoDB ─────────────────────────────────────────────────
    writer = AlertWriter(mongo_uri=MONGO_URI, db_name=MONGO_DB)
    writer.connect()

    # ── 3. Build SparkSession ─────────────────────────────────────────────────
    spark = (
        SparkSession.builder
        .master(SPARK_MASTER)
        .appName("Threvia-Phase4-StreamingDetector")
        .config("spark.sql.streaming.checkpointLocation", "/tmp/threvia_checkpoint")
        .config("spark.sql.shuffle.partitions", "4")   # keep low for local mode
        .config("spark.driver.memory", "2g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    # ── 4. Read from TCP socket ───────────────────────────────────────────────
    raw_stream = (
        spark.readStream
        .format("socket")
        .option("host", STREAM_HOST)
        .option("port", STREAM_PORT)
        .load()
    )

    # Parse JSON lines
    parsed = (
        raw_stream
        .select(F.from_json(F.col("value"), _SCHEMA).alias("data"))
        .select("data.*")
    )

    # Cast numeric fields
    typed = parsed.withColumn("sbytes_num", F.col("sbytes").cast(DoubleType())) \
                  .withColumn("dbytes_num", F.col("dbytes").cast(DoubleType())) \
                  .withColumn("event_ts",   F.to_timestamp("event_time", "yyyy-MM-dd HH:mm:ss"))

    # ── 5. Pipeline A: Bloom Filter hits (row-level) ──────────────────────────
    bloom_query = (
        typed
        .writeStream
        .outputMode("append")
        .foreachBatch(_bloom_batch_handler(bloom, writer))
        .option("checkpointLocation", "/tmp/threvia_checkpoint_bloom")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info("Bloom Filter streaming query started.")

    # ── 6. Pipeline B: Windowed spike detection ───────────────────────────────
    windowed = (
        typed
        .withWatermark("event_ts", "30 seconds")
        .groupBy(
            F.col("srcip"),
            F.window("event_ts", f"{WINDOW_SECONDS} seconds"),
        )
        .agg(
            F.count("*").alias("connection_count"),
            F.sum("sbytes_num").alias("total_bytes"),
            # Majority label in this window (highest count wins)
            F.first("label").alias("majority_label"),
        )
        .select(
            F.col("srcip"),
            F.col("window.start").alias("window_start"),
            F.col("window.end").alias("window_end"),
            F.col("connection_count"),
            F.col("total_bytes"),
            F.col("majority_label"),
        )
        .filter(F.col("connection_count") >= SPIKE_THRESHOLD)
    )

    spike_query = (
        windowed
        .writeStream
        .outputMode("update")
        .foreachBatch(_spike_batch_handler(writer))
        .option("checkpointLocation", "/tmp/threvia_checkpoint_spike")
        .trigger(processingTime=f"{WINDOW_SECONDS} seconds")
        .start()
    )
    logger.info(
        "Spike detection query started (window=%ds, threshold=%d).",
        WINDOW_SECONDS, SPIKE_THRESHOLD,
    )

    # ── 7. Block until terminated ─────────────────────────────────────────────
    logger.info(
        "Streaming detector running. Connect stream_simulator to %s:%d.",
        STREAM_HOST, STREAM_PORT,
    )
    try:
        spark.streams.awaitAnyTermination()
    except KeyboardInterrupt:
        logger.info("Interrupted by user — stopping queries …")
    finally:
        bloom_query.stop()
        spike_query.stop()
        writer.close()
        spark.stop()
        logger.info("Streaming detector stopped cleanly.")


if __name__ == "__main__":
    run_streaming_detector()
