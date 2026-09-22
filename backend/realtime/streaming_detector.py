"""
Phase 4B — Spark Structured Streaming Detector
================================================
Connects to the stream_simulator's TCP socket, parses JSON rows,
and runs three detection pipelines:

  1. Bloom Filter check   — every row whose src_ip is in the filter
                            is flagged immediately and written to MongoDB.

  2. Windowed spike alert — a 60-second tumbling window counts connections
                            per src_ip.  When the count exceeds SPIKE_THRESHOLD
                            (default 50), a severity-graded alert is emitted
                            to MongoDB.

  3. ML classification    — scaler → binary RF (attack?) → Bot specialist.
                            Alerts are written per flow above the policy
                            threshold.

Severity mapping (connections per window) — see
``detection_policy.spike_severity_for``, which owns this ladder:
  ≥ 500   → Critical   (SPIKE_CRITICAL_CONNECTIONS)
  ≥ 200   → High       (SPIKE_HIGH_CONNECTIONS)
  ≥  50   → Medium     (SPIKE_THRESHOLD — the gate *below* this, no alert is
                        emitted at all, so Medium is the ladder's floor)

Pipeline C decision policy
--------------------------
Pipeline C's thresholds live in ``backend/realtime/detection_policy.py`` rather
than in this file, because the values previously hardcoded here were the direct
cause of most of the pipeline's false positives:

  * ``ML_THRESHOLD`` defaulted to ``0.25`` — and the documented run command
    pinned it there with ``export ML_THRESHOLD=0.25`` — *below* the untuned 0.50
    baseline.  Measured on the streamed corpus: FPR 42.7% at 0.25 vs 3.3% at
    0.65, at a 1.4 pp recall cost.
  * The Bot specialist's verdict came from its hard ``prediction`` while its
    probability was discarded — so the bucket was unmeasurable and untunable.
    (Its unconditional raw 0.50 cut was later *measured* to be the optimum:
    95.6% precision at 100% Bot recall. The intuitive fixes — gating on
    "binary RF unsure" or Bayesian prior correction — both measured worse: 5.3%
    and 0% Bot recall respectively. See ``detection_policy.py``.)
  * ``attack_type`` was derived from the stream's ground-truth ``label`` /
    ``attack_cat`` columns, so FP counts were measured against the answer key
    rather than against model behaviour.

The policy now: alert at P(attack) ≥ ``attack_threshold``; accept the Bot
verdict when the raw rf_bot score clears ``bot_threshold`` (prior correction
available but off — see above); persist ``p_bot`` on every alert; and label
attacks from model output only.  Run ``backend/ml/calibrate_thresholds.py`` or
``backend/ml/measure_stream_fpr.py`` to argue from your own data instead of
accepting the defaults.

Environment variables:
    STREAM_HOST              simulator host (default localhost)
    STREAM_PORT              simulator port (default 9999)
    SPARK_MASTER             spark master URL (default local[*])
    THREVIA_MODELS_DIR       gate model dir (default models_clean_v3; set to
                             .../models_clean to roll back to the v1 gate)
    THREVIA_SHARED_DIR       scaler + imputer medians + rf_bot_binary dir
                             (default models_clean; shared by every gate)
    THREVIA_BOT_MODEL        explicit path to the Tier-2 Bot specialist
    SPIKE_THRESHOLD          min connections/window for alert (default 50)
    WINDOW_SECONDS           tumbling window size in seconds (default 60)
    MONGO_URI                MongoDB connection string
    MONGO_DB                 database name (default threvia)
    ML_THRESHOLD             P(attack) cut, overrides the policy default
    BOT_THRESHOLD            raw rf_bot cut (default 0.50, the measured optimum)
    CHECKPOINT_BASE          checkpoint root, overridable to run a second
                             detector against the same stream (A/B)
    MAX_FILES_PER_TRIGGER    files per micro-batch (default 4); the simulator
                             writes ~200 rows/s while one 1,000-row file per 10 s
                             trigger drains at 100 rows/s, so 1 falls behind
    NOMINAL_SAMPLE_RATE      fraction of benign flows mirrored to the
                             nominal_flows collection (default 0.02, 0 = off)
    ALERT_TTL_HOURS          retention for alert/nominal collections (default 72)

Dependencies: pyspark>=3.3, pybloom-live, pymongo
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StringType,
    StructField,
    StructType,
)
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.functions import vector_to_array

from backend.realtime.bloom_filter import ThreatBloomFilter
from backend.realtime.alert_writer import AlertWriter
from backend.realtime.detection_policy import (
    SPIKE_CRITICAL_CONNECTIONS,
    SPIKE_HIGH_CONNECTIONS,
    Thresholds,
    classify_flow,
    load_thresholds,
    spike_severity_for,
)

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
STREAM_HOST = os.getenv("STREAM_HOST", "localhost")
STREAM_PORT = int(os.getenv("STREAM_PORT", "9999"))
SPARK_MASTER = os.getenv("SPARK_MASTER", "local[*]")
SPIKE_THRESHOLD = int(os.getenv("SPIKE_THRESHOLD", "50"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB = os.getenv("MONGO_DB", "threvia")

# Checkpoint root. Overridable so two detectors can run side by side against the
# same stream (e.g. an operating-point A/B) without stealing each other's files.
CHECKPOINT_BASE = os.getenv("CHECKPOINT_BASE", "/tmp/threvia_checkpoint")

# Files consumed per micro-batch. The simulator emits 200 rows/s while one
# 1,000-row file per 10 s trigger drains at 100 rows/s, so the default of 1 makes
# the detector fall permanently behind live traffic. Raise it to keep up.
MAX_FILES_PER_TRIGGER = int(os.getenv("MAX_FILES_PER_TRIGGER", "4"))

# Benign flows below the alert threshold are normally scored and dropped, which
# is why the radar never showed nominal traffic. This mirrors a uniform sample
# of them into the nominal_flows collection (0 disables). At the default 0.02
# and ~130 rejected flows/trigger, that's ~3 docs/s of baseline traffic.
NOMINAL_SAMPLE_RATE = float(os.getenv("NOMINAL_SAMPLE_RATE", "0.02"))

# Model paths.
#
# The gate model (the binary RF the alert decision is made on, plus the
# multiclass head that only describes it) is versioned: models_clean_v3 won the
# matched-FPR comparison in backend/ml/eval_bot_behind_gate.py, so it is the
# default here.  The scaler, imputer medians and Bot specialist are NOT
# versioned — every retrain reuses the ones in models_clean — so they resolve
# against SHARED_DIR and keep working when the gate is rolled back.
#
# ALERT THRESHOLD TRAVELS WITH THE GATE MODEL.  v3's scores sit much lower than
# v1's: at the v1 operating cut of T=0.65 v3 flags 0.16% of the clean BENIGN
# holdout (v1: 3.65%) and passes exactly 0 of 570 held-out Bot flows to the
# Tier-2 specialist.  Always pair a gate with the cut derived for it by
# backend/ml/calibrate_thresholds.py (-> backend/realtime/thresholds.json).
_SHARED_DEFAULT = "hdfs://namenode:8020/threvia/models_clean"
MODELS_BASE = os.getenv(
    "THREVIA_MODELS_DIR",
    os.getenv("GATE_MODELS_DIR", "hdfs://namenode:8020/threvia/models_clean_v3"),
)
SHARED_DIR = os.getenv("THREVIA_SHARED_DIR", _SHARED_DEFAULT)
SCALER_PATH = f"{SHARED_DIR}/scaler_pipeline"
RF_BINARY_PATH = f"{MODELS_BASE}/rf_binary"
RF_BOT_PATH = os.getenv("THREVIA_BOT_MODEL", f"{SHARED_DIR}/rf_bot_binary")
# Optional: used only to *describe* an attack, never to decide that it is one.
RF_MULTI_PATH = f"{MODELS_BASE}/rf_multiclass"
LABEL_MAP_PATH = f"{MODELS_BASE}/label_index_map"

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
    """Grade a windowed connection count.

    Delegates to ``detection_policy.spike_severity_for`` so the dashboard legend
    and the detector cannot disagree about where the spike bands sit; the
    cutoffs used to be inlined here, which is exactly how they drifted.
    """
    return spike_severity_for(count)


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
                    # The label above comes from the simulator's ground-truth
                    # column, not from a classifier.  Tagged so per-label counts
                    # are not mistaken for detection performance.
                    "label_source":     "stream_ground_truth",
                    "severity":         severity,
                })

        if alerts:
            written = writer.write_spike_alerts_bulk(alerts)
            logger.info("Batch %d: %d spike alerts written (threshold=%d)",
                        batch_id, written, SPIKE_THRESHOLD)

    return handler


# ── ML foreachBatch handler ────────────────────────────────────────────────────

def _ml_batch_handler(
    scaler,
    rf_binary,
    rf_bot,
    writer: AlertWriter,
    thresholds: Thresholds,
    rf_multi=None,
    label_map: dict[int, str] | None = None,
    nominal_sample_rate: float = 0.0,
):
    """
    Returns a foreachBatch function for ML-based classification.

    Flow: scaler → binary RF → Bot specialist → policy verdict.  A uniform
    sample of below-threshold flows is mirrored to the nominal collection so
    baseline traffic is visible to dashboards.

    The Bot specialist is *scored* for every above-threshold flow (it is a
    narrow map, and scoring is cheap) but the policy only lets its verdict count
    inside the low-confidence band.  See ``detection_policy`` for the rationale.
    """
    def handler(batch_df, batch_id: int):
        # Cache first: every .count() below would otherwise re-scan and re-score
        # the batch. On a 1g driver this is the difference between one pass over
        # the data and five.
        batch_df = batch_df.cache()
        if batch_df.count() == 0:
            batch_df.unpersist()
            return

        logger.info("Batch %d: processing %d rows", batch_id, batch_df.count())

        try:
            # Apply scaler
            scaled_df = scaler.transform(batch_df)

            # Binary classification (attack vs benign).
            # vector_to_array avoids shipping numpy to the executors.
            scored = (
                rf_binary.transform(scaled_df)
                .withColumn("_prob_arr", vector_to_array("probability"))
                .withColumn("p_attack", F.col("_prob_arr")[1])
                .drop("_prob_arr")
            )

            # Filter to attacks above the policy threshold
            attacks = (
                scored
                .filter(F.col("p_attack") >= thresholds.attack_threshold)
                .withColumnRenamed("label", "gt_label")
                .withColumnRenamed("attack_cat", "gt_cat")
            )

            attack_count = attacks.count()
            logger.info(
                "Batch %d: %d/%d flows above P(attack) >= %.2f",
                batch_id, attack_count, batch_df.count(), thresholds.attack_threshold,
            )

            # Mirror a sample of the REJECTED flows as nominal traffic, so the
            # benign majority of the stream is observable (radar green dots).
            if nominal_sample_rate > 0 and attack_count < batch_df.count():
                nominal = (
                    scored.filter(F.col("p_attack") < thresholds.attack_threshold)
                    .select("srcip", "dstip", "p_attack", "label", "attack_cat", "event_time")
                    .sample(withReplacement=False, fraction=nominal_sample_rate, seed=batch_id)
                    .withColumnRenamed("srcip", "src_ip")
                    .withColumnRenamed("dstip", "dst_ip")
                    .withColumnRenamed("label", "ground_truth_label")
                    .withColumnRenamed("attack_cat", "ground_truth_cat")
                    .withColumn("observation", F.lit("nominal"))
                    .withColumn("severity", F.lit("Nominal"))
                    .collect()
                )
                if nominal:
                    writer.write_nominal_flows_bulk([r.asDict() for r in nominal])
                    logger.info(
                        "Batch %d: %d nominal flows mirrored",
                        batch_id, len(nominal),
                    )

            if attack_count == 0:
                batch_df.unpersist()
                return

            # Drop the binary classifier's outputs so the downstream models can
            # reuse the column names.  p_attack survives as its own column.
            staged = attacks.drop("prediction", "probability", "rawPrediction")

            # Optional multiclass pass — supplies a descriptive attack type.
            if rf_multi is not None:
                staged = (
                    rf_multi.transform(staged)
                    .withColumn("_multi_idx", F.col("prediction").cast("int"))
                    .drop("prediction", "probability", "rawPrediction")
                )
            else:
                staged = staged.withColumn("_multi_idx", F.lit(None).cast("int"))

            # Bot specialist.  Its hard `prediction` is deliberately discarded:
            # a 0.5 cut on a 50/50-trained posterior is not a deployment
            # decision.  Only the probability is carried forward.
            final = (
                rf_bot.transform(staged)
                .withColumn("_bot_arr", vector_to_array("probability"))
                .withColumn("p_bot", F.col("_bot_arr")[1])
                .drop("_bot_arr")
            )

            rows = final.select(
                "srcip", "dstip", "event_time",
                "p_attack", "p_bot", "_multi_idx",
                "gt_label", "gt_cat",
            ).collect()

            alerts = []
            for row in rows:
                rec = row.asDict()

                # Descriptive hint only — never a ground-truth column.
                hint = None
                if label_map and rec.get("_multi_idx") is not None:
                    hint = label_map.get(int(rec["_multi_idx"]))

                verdict = classify_flow(
                    rec.get("p_attack"),
                    rec.get("p_bot"),
                    thresholds,
                    attack_type_hint=hint,
                )
                if verdict is None:          # below threshold after all
                    continue

                alerts.append({
                    "src_ip":            rec.get("srcip"),
                    "dst_ip":            rec.get("dstip"),
                    "attack_type":       verdict["attack_type"],
                    "confidence":        verdict["confidence"],
                    "severity":          verdict["severity"],
                    "p_bot":             rec.get("p_bot"),
                    "p_bot_calibrated":  verdict["p_bot_calibrated"],
                    "bot_routed":        verdict["bot_routed"],
                    # Deliberate mitigation (Step 6): the multiclass RF's
                    # "Infiltration" label was false 980/986 times on the
                    # streamed corpus (76% of all remaining FPs).  Such flows
                    # go to the manual-review collection, not the alert feed.
                    "auto_alert":        verdict["auto_alert"],
                    # Simulator answer key, retained for the CSV export only.
                    # Never used to label the alert.
                    "ground_truth_label": rec.get("gt_label"),
                    "ground_truth_cat":   rec.get("gt_cat"),
                    "event_time":        rec.get("event_time"),
                })

            if alerts:
                auto, review = [], []
                for a in alerts:
                    (auto if a.get("auto_alert", True) else review).append(a)
                if auto:
                    written = writer.write_ml_alerts_bulk(auto)
                    logger.info(
                        "Batch %d: %d ML alerts from %d above-threshold flows (%s)",
                        batch_id, written, len(auto),
                        ", ".join(sorted({a["attack_type"] for a in auto})),
                    )
                if review:
                    rv = writer.write_manual_review_bulk(review)
                    logger.info(
                        "Batch %d: %d flows routed to manual review (%s)",
                        batch_id, rv,
                        ", ".join(sorted({a["attack_type"] for a in review})),
                    )

        except Exception as e:
            logger.error("Batch %d ML handler error: %s", batch_id, e, exc_info=True)
        finally:
            batch_df.unpersist()

    return handler


# ── Optional model helpers ─────────────────────────────────────────────────────

def _try_load_multiclass(spark):
    """Best-effort load of the multiclass RF. Absence is not fatal."""
    try:
        model = RandomForestClassificationModel.load(RF_MULTI_PATH)
        logger.info("Multiclass RF loaded from %s", RF_MULTI_PATH)
        return model
    except Exception as exc:  # noqa: BLE001
        logger.warning("Multiclass RF unavailable (%s) — attack_type will be generic", exc)
        return None


def _try_load_label_map(spark) -> dict[int, str] | None:
    """Load the StringIndexer label ordering saved by save_label_index_map.py."""
    try:
        rows = spark.read.parquet(LABEL_MAP_PATH).collect()
        mapping = {int(r["idx"]): str(r["label"]) for r in rows}
        logger.info("Label index map loaded: %s", mapping)
        return mapping
    except Exception as exc:  # noqa: BLE001
        logger.warning("Label index map unavailable (%s) — attack_type will be generic", exc)
        return None


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
        .config("spark.sql.streaming.checkpointLocation", CHECKPOINT_BASE)
        .config("spark.sql.shuffle.partitions", "4")   # keep low for local mode
        .config("spark.driver.memory", "2g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    # ── 4. Load ML models (requires active Spark session) ────────────────────
    logger.info("Loading gate model from %s (shared artifacts: %s) …",
                MODELS_BASE, SHARED_DIR)
    logger.info("Tier-2 Bot specialist: %s", RF_BOT_PATH)
    scaler = PipelineModel.load(SCALER_PATH)
    rf_binary = RandomForestClassificationModel.load(RF_BINARY_PATH)
    rf_bot = RandomForestClassificationModel.load(RF_BOT_PATH)

    # ── 5. Resolve the decision policy (must happen before any scoring) ──────
    thresholds = load_thresholds()
    logger.info("%s", thresholds.describe())
    # The built-in cuts are on the v1 score scale.  A versioned gate is not, so
    # running one against the defaults is exactly the mistake that produced the
    # old 0.25 operating point — except now it fails silently in the other
    # direction: v3 at the v1 cut of 0.65 flags 0.16% of the clean BENIGN
    # holdout and passes 0 of 570 held-out Bot flows to the Tier-2 specialist.
    # Warn unless the cut came from a calibration artifact or was set explicitly.
    _file_source = thresholds.source.split("+env(")[0]
    _from_artifact = (
        _file_source not in ("defaults", "caller")
        and Path(_file_source).is_file()
    )
    if (not _from_artifact
            and "+env(" not in thresholds.source
            and Path(MODELS_BASE).name != Path(SHARED_DIR).name):
        logger.warning(
            "No calibrated threshold artifact resolved (source=%s) and the gate "
            "(%s) is not the model the built-in cuts were measured on (%s). "
            "The score scales differ, so this pair is not an operating point "
            "anyone chose. Run backend/ml/calibrate_thresholds.py with "
            "MODELS_DIR=%s first.",
            thresholds.source, MODELS_BASE, SHARED_DIR, MODELS_BASE,
        )

    rf_multi = _try_load_multiclass(spark)
    label_map = _try_load_label_map(spark) if rf_multi is not None else None

    # ── 6. Read from file stream ──────────────────────────────────────────────
    # Infer schema from existing files
    logger.info("Inferring schema from existing stream files …")
    sample_schema = spark.read.json("/tmp/threvia_stream").schema
    logger.info("Schema inferred: %d columns", len(sample_schema.fields))

    # Read JSON files with inferred schema
    raw_stream = (
        spark.readStream
        .format("json")
        .schema(sample_schema)
        .option("maxFilesPerTrigger", MAX_FILES_PER_TRIGGER)
        .load("/tmp/threvia_stream")
    )

    # Data is already parsed, just add timestamp
    parsed = raw_stream.withColumn(
        "event_ts",
        F.to_timestamp("event_time", "yyyy-MM-dd HH:mm:ss")
    )

    # ── 7. Pipeline A: Bloom Filter hits (row-level) ──────────────────────────
    bloom_query = (
        parsed
        .writeStream
        .outputMode("append")
        .foreachBatch(_bloom_batch_handler(bloom, writer))
        .option("checkpointLocation", f"{CHECKPOINT_BASE}_bloom")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info("Bloom Filter streaming query started.")

    # ── 8. Pipeline B: Windowed spike detection ───────────────────────────────
    # ONE windowed aggregation only. `mode(label)` gives the genuine majority the
    # original `F.first("label")` merely claimed -- first() returns an arbitrary
    # row, so mixed windows were silently mislabelled.
    #
    # Do NOT restructure this into a chained aggregation (e.g. group by
    # (srcip, window, label) then aggregate again).  Spark rejects that with
    # "Detected pattern of possible 'correctness' issue due to global watermark",
    # and because all three queries live in one SparkSession the exception takes
    # down the ML and Bloom pipelines with it.  mode() is available from 3.4.
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
            F.expr("mode(label)").alias("majority_label"),
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
        .option("checkpointLocation", f"{CHECKPOINT_BASE}_spike")
        .trigger(processingTime=f"{WINDOW_SECONDS} seconds")
        .start()
    )
    logger.info(
        "Spike detection query started (window=%ds, threshold=%d).",
        WINDOW_SECONDS, SPIKE_THRESHOLD,
    )

    # ── 9. Pipeline C: ML-based classification ────────────────────────────────
    ml_query = (
        parsed
        .writeStream
        .outputMode("append")
        .foreachBatch(
            _ml_batch_handler(
                scaler, rf_binary, rf_bot, writer, thresholds,
                rf_multi=rf_multi, label_map=label_map,
                nominal_sample_rate=NOMINAL_SAMPLE_RATE,
            )
        )
        .option("checkpointLocation", f"{CHECKPOINT_BASE}_ml")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info(
        "ML classification query started (P(attack) >= %.2f).",
        thresholds.attack_threshold,
    )

    # ── 10. Block until terminated ────────────────────────────────────────────
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
