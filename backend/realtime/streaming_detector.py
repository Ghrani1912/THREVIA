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
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel

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
ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.25"))  # Lowered for CIC-2017 DDoS

# Model paths
MODELS_BASE = "hdfs://namenode:8020/threvia/models_clean"
SCALER_PATH = f"{MODELS_BASE}/scaler_pipeline"
RF_BINARY_PATH = f"{MODELS_BASE}/rf_binary"
RF_BOT_PATH = f"{MODELS_BASE}/rf_bot_binary"

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


# ── ML foreachBatch handler ────────────────────────────────────────────────────

def _ml_batch_handler(scaler, rf_binary, rf_bot, writer: AlertWriter, threshold: float):
    """
    Returns a foreachBatch function for ML-based classification.
    Applies scaler → binary RF → bot RF and writes alerts above threshold.
    """
    from pyspark.ml.linalg import Vectors, VectorUDT
    from pyspark.sql.functions import udf
    
    # UDF to extract probability of attack class (index 1)
    @udf("double")
    def extract_prob_attack(probability):
        if probability is not None:
            # probability is a DenseVector or SparseVector
            return float(probability[1])
        return 0.0
    
    def handler(batch_df, batch_id: int):
        if batch_df.count() == 0:
            return
        
        logger.info("Batch %d: processing %d rows", batch_id, batch_df.count())
        
        try:
            # Apply scaler
            scaled_df = scaler.transform(batch_df)
            logger.info("Batch %d: scaler OK, rows=%d", batch_id, scaled_df.count())
            
            # Binary classification (attack vs benign)
            predictions = rf_binary.transform(scaled_df)
            logger.info("Batch %d: binary classifier OK", batch_id)
            
            # Extract probability as a column
            predictions_with_prob = predictions.withColumn(
                "p_attack", 
                extract_prob_attack(F.col("probability"))
            )
            
            # Filter to attacks above threshold
            attacks = predictions_with_prob.filter(
                F.col("p_attack") >= threshold
            )
            
            attack_count = attacks.count()
            logger.info("Batch %d: %d flows above threshold %.2f", 
                       batch_id, attack_count, threshold)
            
            if attack_count == 0:
                logger.info("Batch %d: no ML alerts (all flows below T=%.2f)", 
                           batch_id, threshold)
                return
            
            # Bot sub-classification
            # Drop existing prediction/probability columns from binary classifier
            attacks_clean = attacks.drop("prediction", "probability", "rawPrediction")
            bot_predictions = rf_bot.transform(attacks_clean)
            logger.info("Batch %d: bot classifier OK", batch_id)
            
            # Collect and write alerts
            rows = bot_predictions.select(
                "srcip", "dstip", "label", "attack_cat", "event_time",
                "p_attack",
                F.col("prediction").alias("is_bot")
            ).collect()
            
            alerts = []
            for row in rows:
                p_attack = float(row["p_attack"])
                is_bot = int(row["is_bot"])
                
                # Determine attack type
                if is_bot == 1:
                    attack_type = "Bot"
                else:
                    # Check ground truth label (for labeled data)
                    true_label = row["label"]
                    true_cat = row["attack_cat"]
                    
                    if "DDoS" in true_cat or "DoS" in true_cat or "DDoS" in true_label:
                        attack_type = "DDoS"
                    elif true_label and true_label != "BENIGN" and true_label != "0":
                        # Other attack types from ground truth
                        attack_type = true_label
                    elif p_attack > 0.65:
                        # High confidence non-bot attack likely DDoS
                        attack_type = "DDoS"
                    else:
                        attack_type = "Unknown"
                
                # Determine severity based on confidence
                if p_attack >= 0.85:
                    severity = "Critical"
                elif p_attack >= 0.65:
                    severity = "High"
                elif p_attack >= 0.40:
                    severity = "Medium"
                else:
                    severity = "Low"
                
                alerts.append({
                    "src_ip": row["srcip"],
                    "dst_ip": row["dstip"],
                    "attack_type": attack_type,
                    "confidence": p_attack,
                    "severity": severity,
                    "ground_truth_label": row["label"],
                    "ground_truth_cat": row["attack_cat"],
                    "event_time": row["event_time"],
                })
            
            if alerts:
                written = writer.write_ml_alerts_bulk(alerts)
                logger.info("Batch %d: %d ML alerts written (%s types)",
                           batch_id, written, 
                           ", ".join(set(a["attack_type"] for a in alerts)))
        
        except Exception as e:
            logger.error("Batch %d ML handler error: %s", batch_id, e, exc_info=True)
    
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

    # ── 4. Load ML models (requires active Spark session) ────────────────────
    logger.info("Loading ML models from HDFS …")
    scaler = PipelineModel.load(SCALER_PATH)
    rf_binary = RandomForestClassificationModel.load(RF_BINARY_PATH)
    rf_bot = RandomForestClassificationModel.load(RF_BOT_PATH)
    logger.info("ML models ready (threshold=%.2f)", ML_THRESHOLD)

    # ── 5. Read from file stream ──────────────────────────────────────────────
    # Infer schema from existing files
    logger.info("Inferring schema from existing stream files …")
    sample_schema = spark.read.json("/tmp/threvia_stream").schema
    logger.info("Schema inferred: %d columns", len(sample_schema.fields))
    
    # Read JSON files with inferred schema
    raw_stream = (
        spark.readStream
        .format("json")
        .schema(sample_schema)
        .option("maxFilesPerTrigger", 1)
        .load("/tmp/threvia_stream")
    )

    # Data is already parsed, just add timestamp
    parsed = raw_stream.withColumn(
        "event_ts", 
        F.to_timestamp("event_time", "yyyy-MM-dd HH:mm:ss")
    )

    # ── 6. Pipeline A: Bloom Filter hits (row-level) ──────────────────────────
    bloom_query = (
        parsed
        .writeStream
        .outputMode("append")
        .foreachBatch(_bloom_batch_handler(bloom, writer))
        .option("checkpointLocation", "/tmp/threvia_checkpoint_bloom")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info("Bloom Filter streaming query started.")

    # ── 7. Pipeline B: Windowed spike detection ───────────────────────────────
    windowed = (
        parsed
        .withWatermark("event_ts", "30 seconds")
        .groupBy(
            F.col("srcip"),
            F.window("event_ts", f"{WINDOW_SECONDS} seconds"),
        )
        .agg(
            F.count("*").alias("connection_count"),
            F.sum("Flow Bytes/s").alias("total_bytes"),
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

    # ── 8. Pipeline C: ML-based classification ────────────────────────────────
    # Use the same parsed stream for ML
    ml_query = (
        parsed
        .writeStream
        .outputMode("append")
        .foreachBatch(_ml_batch_handler(scaler, rf_binary, rf_bot, writer, ML_THRESHOLD))
        .option("checkpointLocation", "/tmp/threvia_checkpoint_ml")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info("ML classification query started (threshold=%.2f).", ML_THRESHOLD)

    # ── 9. Block until terminated ─────────────────────────────────────────────
    logger.info(
        "Streaming detector running. Reading from /tmp/threvia_stream/.",
    )
    try:
        spark.streams.awaitAnyTermination()
    except KeyboardInterrupt:
        logger.info("Interrupted by user — stopping queries …")
    finally:
        bloom_query.stop()
        spike_query.stop()
        ml_query.stop()
        writer.close()
        spark.stop()
        logger.info("Streaming detector stopped cleanly.")


if __name__ == "__main__":
    run_streaming_detector()
