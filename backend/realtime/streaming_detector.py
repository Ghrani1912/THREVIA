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

Online / continual learning
---------------------------
The gate model was trained and evaluated on one corpus, so its score scale and its
operating point are properties of that corpus.  ``online_learning.py`` sits between
the model's score and the alert decision and adapts both to the traffic actually
being seen: a label-free controller holds the alert *rate* at a budget by tracking
the recent score distribution, and a bounded logistic residual learns from analyst
verdicts plus the stream's benign majority.  Enabled by default
(``ONLINE_LEARNING=off`` disables it entirely, which is the correct way to run a
matched A/B against the frozen model).  The layer is an exact identity until
evidence exists, its cut can never leave the calibrated band, and its residual can
never exceed ``ONLINE_LEARNING_MAX_SHIFT`` logits -- see that module for why each
bound is there rather than a tuning knob.

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
    ONLINE_LEARNING          on/off for the adaptive layer (default on)
    ONLINE_LEARNING_STATE    checkpoint path (default <CHECKPOINT_BASE>_learning.json)
    ONLINE_LEARNING_TARGET_RATE  alert-rate budget (default 0.025)
    ONLINE_LEARNING_MAX_SHIFT    cap on the log-odds residual (default 1.5)
    FEEDBACK_POLL_SECONDS    how often to read new analyst verdicts (default 20)
    ONLINE_LEARNING_PRIME    optional JSON file of known-benign scores (or
                             {"scores": [...]}) used to seed the drift reference

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

import json
import time

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
from backend.realtime.online_learning import (
    OnlineLearningConfig,
    OnlineLearningPolicy,
)

logger = logging.getLogger(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
STREAM_HOST = os.getenv("STREAM_HOST", "localhost")
STREAM_PORT = int(os.getenv("STREAM_PORT", "9999"))
SPARK_MASTER = os.getenv("SPARK_MASTER", "local[*]")
SPIKE_THRESHOLD = int(os.getenv("SPIKE_THRESHOLD", "50"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
# Host-side default (compose publishes MongoDB on host 27018). Inside the
# compose network MONGO_URI is set to mongodb://mongodb:27017/, which wins.
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")
MONGO_DB = os.getenv("MONGO_DB", "threvia")

# Checkpoint root. Overridable so two detectors can run side by side against the
# same stream (e.g. an operating-point A/B) without stealing each other's files.
CHECKPOINT_BASE = os.getenv("CHECKPOINT_BASE", "/tmp/threvia_checkpoint")

# How often the detector reads new analyst verdicts from MongoDB. The online layer
# learns from them on the driver, between micro-batches; 20 s is fast enough that a
# verdict visibly changes the operating point within a couple of sweeps, and slow
# enough that the read is a rounding error next to the batch itself.
FEEDBACK_POLL_SECONDS = float(os.getenv("FEEDBACK_POLL_SECONDS", "20"))
FEEDBACK_FETCH_LIMIT = int(os.getenv("FEEDBACK_FETCH_LIMIT", "500"))

# Files consumed per micro-batch. The simulator emits 200 rows/s while one
# 1,000-row file per 10 s trigger drains at 100 rows/s, so the default of 1 makes
# the detector fall permanently behind live traffic. Raise it to keep up.
MAX_FILES_PER_TRIGGER = int(os.getenv("MAX_FILES_PER_TRIGGER", "4"))

# Benign flows below the alert threshold are normally scored and dropped, which
# is why the radar never showed nominal traffic. This mirrors a uniform sample
# of them into the nominal_flows collection (0 disables). At the default 0.02
# and ~130 rejected flows/trigger, that's ~3 docs/s of baseline traffic.
NOMINAL_SAMPLE_RATE = float(os.getenv("NOMINAL_SAMPLE_RATE", "0.02"))

# The adaptive layer is ON by default: a detector whose operating point cannot
# follow the traffic it is watching is the failure this project is about, and
# leaving it off by default would mean shipping the frozen-model behaviour and
# calling it fixed.  Set ONLINE_LEARNING=off for a matched A/B against the frozen
# model -- that comparison is the only way to show the layer earns its place.
ONLINE_LEARNING_ENABLED = os.getenv("ONLINE_LEARNING", "on").strip().lower() not in (
    "0", "false", "no", "off",
)

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

class FeedbackPoller:
    """Polls MongoDB for new analyst verdicts and feeds them to the online layer.

    Lives on the driver, between micro-batches, because it touches a Python object
    (the learning policy) that only exists there.  Reading the verdicts is
    idempotent: the policy de-duplicates by document id, so the poller does not
    need a high-water mark to avoid double-learning a verdict.
    """

    def __init__(self, writer: AlertWriter, policy: OnlineLearningPolicy,
                 interval: float = FEEDBACK_POLL_SECONDS,
                 limit: int = FEEDBACK_FETCH_LIMIT):
        self._writer = writer
        self._policy = policy
        self._interval = max(1.0, float(interval))
        self._limit = int(limit)
        self._last = 0.0

    def poll(self) -> int:
        now = time.monotonic()
        if now - self._last < self._interval:
            return 0
        self._last = now
        try:
            rows = self._writer.fetch_recent_feedback(limit=self._limit)
        except Exception as exc:  # noqa: BLE001 - feedback must never kill the stream
            logger.warning("Feedback poll failed (%s) — continuing without it", exc)
            return 0
        if not rows:
            return 0
        learned = self._policy.learn_feedback(rows)
        if learned:
            logger.info("Learned from %d new analyst verdicts", learned)
        return learned


def _ml_batch_handler(
    scaler,
    rf_binary,
    rf_bot,
    writer: AlertWriter,
    thresholds: Thresholds,
    rf_multi=None,
    label_map: dict[int, str] | None = None,
    nominal_sample_rate: float = 0.0,
    learning: OnlineLearningPolicy | None = None,
    feedback_poller: "FeedbackPoller | None" = None,
):
    """
    Returns a foreachBatch function for ML-based classification.

    Flow: scaler → binary RF → (online layer) → Bot specialist → policy verdict.
    A uniform sample of below-threshold flows is mirrored to the nominal
    collection so baseline traffic is visible to dashboards.

    The Bot specialist is *scored* for every flow above the online layer's cheap
    prefilter (a narrow map, and scoring is cheap) but the policy only lets its
    verdict count inside the low-confidence band.  See ``detection_policy``.

    ``learning``, when supplied, changes exactly three things: which score the
    decision is made on (the residual-corrected one), where the alert threshold
    sits (the rate-controlled one), and what is written to the learning
    collections.  It cannot change the model, the features, or the severity
    ladder -- see ``online_learning`` for the bounds that guarantee that.
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

        # New analyst verdicts are consumed before the batch is scored, so a
        # verdict applied in the dashboard is reflected in the very next sweep.
        learned_feedback = feedback_poller.poll() if feedback_poller is not None else 0

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

            # The decision point and the score it is compared against both come
            # from the online layer.  ``effective`` is the calibrated policy with
            # its operating point (and the matching severity rung) replaced.
            effective = thresholds
            if learning is not None:
                effective = learning.apply_to_thresholds(thresholds)
                # Every flow in the batch, not just the alerts: the budget is a
                # fraction of scored traffic, and a pool of alerts cannot measure
                # a rate.  This is one extra pass over an already-cached frame.
                batch_scores = [
                    float(r["p_attack"])
                    for r in scored.select("p_attack").collect()
                    if r["p_attack"] is not None
                ]
                record = learning.observe(
                    batch_scores, batch_id=batch_id, learned_feedback=learned_feedback,
                )
                # The benign majority is the only large source of negatives the
                # stream offers; the layer applies its own margin and drift guard.
                learned_nominal = learning.learn_nominal_negatives(batch_scores)
                logger.info(
                    "Batch %d: online learning cut=%.4f (calibrated %.4f%s) "
                    "PSI=%.3f drift=%s residual=%+.3f logits (%d updates, %d verdicts, "
                    "%d nominal negatives)",
                    batch_id, record["threshold"], record["calibrated_threshold"],
                    " SATURATED" if record["budget_saturated"] else "",
                    record["psi"], record["drift"], record["shift_mean"],
                    record["calibrator_updates"], record["learned_feedback"],
                    learned_nominal,
                )
            else:
                record = None

            def flush_learning(alert_total: int) -> None:
                """Persist what the layer learned from this batch.

                Called on both exits (including the empty-batch path): a batch with
                no alerts is still evidence about the score distribution, and
                dropping those batches would blind the drift monitor exactly when
                traffic is quiet.
                """
                if learning is None or record is None:
                    return
                rec = learning.note_alerts(alert_total) or record
                writer.write_learning_telemetry(rec)
                writer.write_learning_state(learning.snapshot())
                if (batch_id % max(1, learning.config.save_every_batches)) == 0:
                    learning.save()

            # Filter to the flows that could possibly clear the adaptive gate.
            # ``prefilter_threshold`` is the loosest cut that cannot drop a row the
            # exact (residual-corrected) test would keep, so the Bot specialist
            # stays off rows that cannot alert without changing the answer.
            gate = (learning.prefilter_threshold() if learning is not None
                    else thresholds.attack_threshold)
            attacks = (
                scored
                .filter(F.col("p_attack") >= gate)
                .withColumnRenamed("label", "gt_label")
                .withColumnRenamed("attack_cat", "gt_cat")
            )

            attack_count = attacks.count()
            logger.info(
                "Batch %d: %d/%d flows above prefilter P(attack) >= %.4f (gate %.4f)",
                batch_id, attack_count, batch_df.count(), gate, effective.attack_threshold,
            )

            # Mirror a sample of the REJECTED flows as nominal traffic, so the
            # benign majority of the stream is observable (radar green dots).
            if nominal_sample_rate > 0 and attack_count < batch_df.count():
                nominal = (
                    scored.filter(F.col("p_attack") < effective.attack_threshold)
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
                flush_learning(0)
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

                # The decision itself.  With the online layer enabled the score is
                # the model's raw output with a bounded residual applied and the cut
                # is the rate-controlled one; with it disabled both are the frozen
                # artifacts, which is the matched A/B baseline.
                if learning is not None:
                    # The adaptive path: the bounded residual re-ranks the score and
                    # the rate-controlled cut decides, with the audit trail carried
                    # by the policy itself (raw score, adapted score, cut used).
                    verdict = learning.classify(
                        rec.get("p_attack"), rec.get("p_bot"), thresholds,
                        attack_type_hint=hint,
                    )
                else:
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
                    # confidence is the score the verdict was made on (adapted), so
                    # severity and the decision stay consistent with each other.
                    "confidence":        verdict["confidence"],
                    "severity":          verdict["severity"],
                    # Audit trail of the adaptation.  ``p_attack_raw`` is what the
                    # model said; the difference is what the online layer added,
                    # and ``threshold_used`` is where the cut sat for this flow.
                    "p_attack_raw":      verdict.get("p_attack_raw"),
                    "p_attack_adapted":  verdict.get("p_attack_adapted"),
                    "score_shift":       verdict.get("score_shift"),
                    "threshold_used":    verdict.get("threshold_used",
                                                      effective.attack_threshold),
                    "calibrated_threshold": thresholds.attack_threshold,
                    "learning_updates":  verdict.get("learning_updates", 0),
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

            # The realized rate counts alerts that reached the feed; a flow parked
            # for manual review is not an alert and must not inflate the rate the
            # budget is compared against.
            alert_total = sum(1 for a in alerts if a.get("auto_alert", True))
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

            # The realized rate is known only now, so it is folded into the record
            # after the gate has run; without it the dashboard would plot a budget
            # against nothing.
            flush_learning(alert_total)

        except Exception as e:
            logger.error("Batch %d ML handler error: %s", batch_id, e, exc_info=True)
        finally:
            batch_df.unpersist()

    return handler


# ── Optional model helpers ─────────────────────────────────────────────────────

def _load_prime_scores(path: str) -> list[float]:
    """Read scores used to seed the drift baseline.

    Accepts either a bare JSON array of probabilities or ``{"scores": [...]}``.
    The intended source is the calibration artifact's *benign* holdout scores, so
    the first drift measurement compares live traffic against the population the
    deployed cut was derived from rather than against the first live batch.
    """
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("scores") or []
    out: list[float] = []
    for value in data or []:
        try:
            out.append(float(value))
        except (TypeError, ValueError):
            continue
    return out


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

    # ── 5b. Online / continual-learning layer ────────────────────────────────
    # The gate, the scaler and the severity ladder are all frozen artifacts derived
    # from one corpus.  This layer is the part that keeps working when the traffic
    # stops looking like that corpus; see backend/realtime/online_learning.py.
    learning: OnlineLearningPolicy | None = None
    feedback_poller: FeedbackPoller | None = None
    if ONLINE_LEARNING_ENABLED:
        learn_cfg = OnlineLearningConfig.from_env()
        if not learn_cfg.state_path:
            # Tied to the checkpoint root so a second detector (an A/B, a replay)
            # does not inherit the first one's learned state.
            learn_cfg.state_path = f"{CHECKPOINT_BASE}_learning.json"
        learning = OnlineLearningPolicy.load_or_new(thresholds=thresholds, config=learn_cfg)
        prime_path = os.getenv("ONLINE_LEARNING_PRIME")
        if prime_path and learning.reference.source == "empty":
            try:
                primed = learning.prime_reference(
                    _load_prime_scores(prime_path), source=f"prime:{Path(prime_path).name}"
                )
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Could not read ONLINE_LEARNING_PRIME %s (%s)", prime_path, exc)
            else:
                if primed == 0:
                    logger.warning("ONLINE_LEARNING_PRIME %s held no usable scores", prime_path)
        lo, hi = learning.threshold_bounds()
        logger.info(
            "Online learning %s: cut %.4f (anchor %.4f, band %.4f-%.4f), budget %.3f, "
            "residual cap %.2f logits, %d labelled verdicts, %d drift re-anchors, state %s",
            "ENABLED" if learning.enabled else "disabled",
            learning.effective_threshold(), learning.calibrated_threshold, lo, hi,
            learning.config.target_alert_rate, learning.config.max_logit_shift,
            learning.feedback_learned, learning.drift.reanchors, learn_cfg.state_path,
        )
        if learning.enabled:
            feedback_poller = FeedbackPoller(writer, learning)
    else:
        logger.info("Online learning disabled (ONLINE_LEARNING=off) — frozen operating point")

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
                learning=learning, feedback_poller=feedback_poller,
            )
        )
        .option("checkpointLocation", f"{CHECKPOINT_BASE}_ml")
        .trigger(processingTime="10 seconds")
        .start()
    )
    logger.info(
        "ML classification query started (P(attack) >= %.4f%s).",
        learning.effective_threshold() if learning else thresholds.attack_threshold,
        ", rate-controlled" if learning else "",
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
