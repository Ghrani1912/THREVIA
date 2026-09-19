"""
measure_stream_fpr.py — measure the false-positive rate on the streamed dataset
===============================================================================
Answers one question with numbers instead of argument: *on the exact corpus the
stream simulator replays, how much does the operating point change the false
positive rate?*

It replays the same pipeline the streaming detector runs — ``scaler_pipeline``
then ``rf_binary`` — but as a batch over the identical Parquet the simulator
loads (``/threvia/corpus/demo_balanced_150k_fixed``).  Every threshold therefore
sees byte-identical input, which a live A/B cannot guarantee because the
simulator shuffles and loops.

It also reproduces the old and new Bot attribution rules so the "28.10%" figure
can be traced to its cause.

Usage (inside the Spark container)::

    docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \\
      /opt/spark/bin/spark-submit --master local[2] --driver-memory 1g \\
      /workspace/backend/ml/measure_stream_fpr.py"
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "/workspace")

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.functions import vector_to_array

HDFS = "hdfs://namenode:8020/threvia"
DATASET = f"{HDFS}/corpus/demo_balanced_150k_fixed"   # what the simulator loads
# The gate model is versioned; the scaler and Bot specialist are shared by every
# gate.  Same env names the detector uses, so this replays the deployed pipeline.
SHARED_DIR = os.getenv("THREVIA_SHARED_DIR", f"{HDFS}/models_clean")
GATE_DIR = os.getenv("THREVIA_MODELS_DIR", f"{HDFS}/models_clean_v3")
SCALER = f"{SHARED_DIR}/scaler_pipeline"
RF_BIN = f"{GATE_DIR}/rf_binary"
RF_BOT = os.getenv("THREVIA_BOT_MODEL", f"{SHARED_DIR}/rf_bot_binary")

# Old hardcoded runtime value (the launch command's `export ML_THRESHOLD=0.25`).
OLD_THRESHOLD = 0.25
# The cut the pipeline actually runs is resolved from the policy (thresholds.json
# when present).  Hardcoding it here is how this document drifted away from the
# deployment once already: the deployed value is a property of the gate model's
# score scale, not a constant.
from backend.realtime.detection_policy import load_thresholds  # noqa: E402
_POLICY = load_thresholds()
NEW_THRESHOLD = round(float(_POLICY.attack_threshold), 4)
# Kept as a labelled reference point for continuity with the 3.26%-at-0.65 table.
REFERENCE_THRESHOLD = 0.65

GT_COL = "is_attack"
LABEL_COL = "Label"

# The corpus carries no is_attack column -- ground truth is the Label string.
BENIGN_NAMES = ("BENIGN", "NORMAL")


def sep(msg: str = "") -> None:
    print("\n" + "=" * 78 + (f"\n  {msg}\n" + "=" * 78 if msg else ""))


def sigmoid_needed(prevalence: float, threshold: float = 0.5) -> float:
    """Raw score a 50/50-trained model needs to clear `threshold` at `prevalence`."""
    import math

    def logit(p: float) -> float:
        p = min(1 - 1e-9, max(1e-9, p))
        return math.log(p / (1 - p))

    return 1.0 / (1.0 + math.exp(-(logit(threshold) - logit(prevalence))))


def main() -> int:
    from backend.realtime.detection_policy import (
        Thresholds,
        calibrate_probability,
    )
    from backend.realtime.stream_simulator import _EMIT_COLS

    spark = (
        SparkSession.builder
        .appName("Threvia-MeasureStreamFPR")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "1g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    sep("Loading the streamed dataset and models")
    print(f"  Gate model      : {RF_BIN}")
    print(f"  Shared artifacts: {SHARED_DIR}")
    print(f"  Policy          : {_POLICY.describe()}")
    raw = spark.read.parquet(DATASET)
    print(f"  Dataset columns : {len(raw.columns)}")

    # Mirror the simulator exactly: it keeps only _EMIT_COLS before serialising.
    keep = [c for c in raw.columns if c in _EMIT_COLS]
    df = raw.select(keep)
    print(f"  Emitted columns : {len(keep)} (same selection as stream_simulator)")

    # Ground truth from the Label string. The simulator's JSON turns this into
    # `label`, and (because of an eager-default bug) leaves `attack_cat`
    # permanently "BENIGN" -- see the note printed below.
    df = df.withColumn(
        GT_COL,
        F.when(F.upper(F.trim(F.col(LABEL_COL))).isin(*BENIGN_NAMES), F.lit(0))
         .otherwise(F.lit(1)),
    )
    print(f"  Ground truth    : derived from `{LABEL_COL}` (corpus has no `is_attack`)")

    scaler = PipelineModel.load(SCALER)
    rf_bin = RandomForestClassificationModel.load(RF_BIN)
    rf_bot = RandomForestClassificationModel.load(RF_BOT)

    sep("Ground-truth mix of the streamed corpus")
    n_total = df.count()
    n_benign = df.filter(F.col(GT_COL) == 0).count()
    n_attack = n_total - n_benign
    print(f"  Total flows : {n_total:,}")
    print(f"  BENIGN      : {n_benign:,}  ({n_benign / n_total * 100:.2f}%)")
    print(f"  ATTACK      : {n_attack:,}  ({n_attack / n_total * 100:.2f}%)")
    print("  Class mix of the demo, by Label:")
    df.groupBy(LABEL_COL).count().orderBy(F.desc("count")).show(20, truncate=False)

    sep("Scoring (scaler -> rf_binary, exactly as Pipeline C does)")
    scaled = scaler.transform(df)
    scored = (
        rf_bin.transform(scaled)
        .withColumn("_p", vector_to_array("probability"))
        .withColumn("p_attack", F.col("_p")[1])
        # scaled_features is retained because rf_bot consumes the same vector.
        .select(GT_COL, LABEL_COL, "p_attack", "scaled_features")
        .cache()
    )

    # ── Threshold comparison ─────────────────────────────────────────────────
    sep(f"FPR on the streamed corpus — old runtime T={OLD_THRESHOLD} vs policy T={NEW_THRESHOLD}")

    def stats(t: float) -> dict:
        above = scored.filter(F.col("p_attack") >= t)
        alerts = above.count()
        fp = above.filter(F.col(GT_COL) == 0).count()
        tp = alerts - fp
        return {
            "t": t,
            "alerts": alerts,
            "fp": fp,
            "tp": tp,
            "fpr_pct": fp / n_benign * 100.0 if n_benign else 0.0,
            "recall_pct": tp / n_attack * 100.0 if n_attack else 0.0,
            "precision_pct": tp / alerts * 100.0 if alerts else 0.0,
        }

    grid = sorted(set([0.25, 0.40, 0.50, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]
                      + [NEW_THRESHOLD, REFERENCE_THRESHOLD]))
    hdr = (f"  {'T':>6} | {'ALERTS':>10} | {'FP FLOWS':>10} | {'FPR%':>8} | "
           f"{'RECALL%':>8} | {'PRECISION%':>10}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    rows = []
    for t in grid:
        s = stats(t)
        rows.append(s)
        flag = ""
        if abs(t - OLD_THRESHOLD) < 1e-9:
            flag = "  <-- OLD runtime (your TERM 2 command)"
        if abs(t - NEW_THRESHOLD) < 1e-9:
            flag = "  <-- DEPLOYED (resolved policy, threshold artifact)"
        if abs(t - REFERENCE_THRESHOLD) < 1e-9 and abs(t - NEW_THRESHOLD) > 1e-9:
            flag = "  <-- previous v1 operating point (reference)"
        print(f"  {t:>6.2f} | {s['alerts']:>10,} | {s['fp']:>10,} | "
              f"{s['fpr_pct']:>7.2f}% | {s['recall_pct']:>7.2f}% | "
              f"{s['precision_pct']:>9.2f}%{flag}")

    old = next(r for r in rows if abs(r["t"] - OLD_THRESHOLD) < 1e-9)
    new = next(r for r in rows if abs(r["t"] - NEW_THRESHOLD) < 1e-9)

    sep(f"Effect of moving the operating point {OLD_THRESHOLD} -> {NEW_THRESHOLD:.4f}")
    fp_cut = old["fp"] - new["fp"]
    alert_cut = old["alerts"] - new["alerts"]
    print(f"  FPR            : {old['fpr_pct']:.2f}%  ->  {new['fpr_pct']:.2f}%"
          f"   ({new['fpr_pct'] - old['fpr_pct']:+.2f} pp)")
    print(f"  False-positive flows : {old['fp']:,}  ->  {new['fp']:,}"
          f"   (-{fp_cut:,}, {fp_cut / old['fp'] * 100 if old['fp'] else 0:.1f}% fewer)")
    print(f"  Total alerts   : {old['alerts']:,}  ->  {new['alerts']:,}   (-{alert_cut:,})")
    print(f"  Recall         : {old['recall_pct']:.2f}%  ->  {new['recall_pct']:.2f}%"
          f"   ({new['recall_pct'] - old['recall_pct']:+.2f} pp)")
    print(f"  Precision      : {old['precision_pct']:.2f}%  ->  {new['precision_pct']:.2f}%"
          f"   ({new['precision_pct'] - old['precision_pct']:+.2f} pp)")

    # ── Bot attribution: why "BOT CLUSTER FPR 28.10%" happened ───────────────
    sep("Bot attribution — old rule vs new gated+calibrated rule")
    print("  The Bot specialist only ever rewrites attack_type; it never changes")
    print("  whether an alert fires.  So it moves *attribution*, not alert count.")
    print()

    bot_scored = (
        rf_bot.transform(scored)
        .withColumn("_bp", vector_to_array("probability"))
        .withColumn("p_bot", F.col("_bp")[1])
        .select(GT_COL, LABEL_COL, "p_attack", "p_bot")
        .cache()
    )

    th = Thresholds()          # built-in policy (the gating experiments' baseline)
    th.attack_threshold = NEW_THRESHOLD
    gate = th.bot_route_max_confidence
    if gate is None:
        # Gating was measured harmful and is off by default (see
        # detection_policy.py): Bot flows are flagged confidently, so a
        # "binary RF unsure" rule discards most of them. Report the ungated
        # rule only rather than inventing a band.
        gate = 1.0

    # OLD: unconditional, hard prediction (p_bot >= 0.5), checked first.
    old_bot_all = bot_scored.filter(F.col("p_attack") >= OLD_THRESHOLD)
    old_labelled_bot = old_bot_all.filter(F.col("p_bot") >= 0.50).count()
    old_bot_benign = old_bot_all.filter(
        (F.col("p_bot") >= 0.50) & (F.col(GT_COL) == 0)
    ).count()

    # NEW: only inside the low-confidence band, and only on the corrected posterior.
    shift = th.effective_bot_logit_shift()
    new_pool = bot_scored.filter(
        (F.col("p_attack") >= NEW_THRESHOLD) & (F.col("p_attack") <= F.lit(gate))
    )
    new_bot_benign = new_pool.filter(
        (F.col("p_bot") >= F.lit(th.raw_bot_score_needed())) & (F.col(GT_COL) == 0)
    ).count()
    new_labelled_bot = new_pool.filter(
        F.col("p_bot") >= F.lit(th.raw_bot_score_needed())
    ).count()

    print(f"  OLD rule (unconditional, hard 0.5 cut on a 50/50 posterior):")
    print(f"    flows labelled 'Bot'        : {old_labelled_bot:,}")
    print(f"    ...of which truly BENIGN    : {old_bot_benign:,}"
          f"  ({old_bot_benign / old_labelled_bot * 100 if old_labelled_bot else 0:.2f}% of the Bot bucket)")
    print()
    print(f"  NEW rule (routed only when P(attack) <= {gate}, prior-corrected at")
    print(f"  {th.bot_deploy_prevalence:.3f} prevalence -> raw cut {th.raw_bot_score_needed():.3f}):")
    print(f"    flows eligible for the Bot specialist : {new_pool.count():,} of {new['alerts']:,} alerts")
    print(f"    flows labelled 'Bot'        : {new_labelled_bot:,}")
    print(f"    ...of which truly BENIGN    : {new_bot_benign:,}"
          f"  ({new_bot_benign / new_labelled_bot * 100 if new_labelled_bot else 0:.2f}% of the Bot bucket)")
    print()
    print(f"  Prior correction: raw rf_bot 0.50 -> {calibrate_probability(0.50, th.bot_train_prevalence, th.bot_deploy_prevalence):.4f}"
          f" at deployment prevalence (logit shift {shift:+.3f})")

    # ── What Bot prevalence and cut does this corpus actually imply? ─────────
    sep("Bot cut sweep — choosing an operating point from data")
    flagged = bot_scored.filter(F.col("p_attack") >= NEW_THRESHOLD)
    n_flagged = flagged.count()
    n_bot_true = flagged.filter(F.col(GT_COL) == 1).filter(
        F.upper(F.trim(F.col(LABEL_COL))) == "BOT"
    ).count()
    print(f"  Flows above T={NEW_THRESHOLD}          : {n_flagged:,}")
    print(f"  ...truly Bot                    : {n_bot_true:,}")
    prev = n_bot_true / n_flagged if n_flagged else 0.0
    print(f"  => empirical P(Bot | flagged)   : {prev:.4f}  ({prev * 100:.2f}%)")
    print()
    print("  A posterior >= 0.5 at that prevalence requires a raw rf_bot score of")
    print(f"  {sigmoid_needed(prev):.4f}, which is why the 0.05 default fired 0 times.")
    print("  Sweeping the RAW cut instead — pick a precision the analysts accept:")
    print()

    bot_truth = flagged.withColumn(
        "_is_bot", F.when(F.upper(F.trim(F.col(LABEL_COL))) == "BOT", 1).otherwise(0)
    ).cache()

    print("  ungated        = old behaviour (Bot consulted for every flagged flow)")
    print(f"  gated <= {gate} = Tier-2 as designed (only when the binary RF is unsure)")
    print()
    hdr2 = (f"  {'RAW CUT':>8} | {'RULE':>12} | {'LABELLED':>9} | {'TRULY BOT':>9} | "
            f"{'PREC%':>7} | {'BOT RECALL%':>11} | {'TRUE BOTS LOST':>14}")
    print(hdr2)
    print("  " + "-" * (len(hdr2) - 2))
    for cut in (0.50, 0.60, 0.70, 0.80, 0.90, 0.95):
        for rule, cond in (
            ("ungated", F.col("p_bot") >= cut),
            (f"gated<={gate}", (F.col("p_bot") >= cut) & (F.col("p_attack") <= F.lit(gate))),
        ):
            sel = bot_truth.filter(cond)
            labelled = sel.count()
            true_bot = sel.filter(F.col("_is_bot") == 1).count()
            prec = true_bot / labelled * 100 if labelled else 0.0
            rec = true_bot / n_bot_true * 100 if n_bot_true else 0.0
            lost = n_bot_true - true_bot
            print(f"  {cut:>8.2f} | {rule:>12} | {labelled:>9,} | {true_bot:>9,} | "
                  f"{prec:>6.2f}% | {rec:>10.2f}% | {lost:>14,}")

    print()
    print("  Interpretation: rf_bot's 'probability' is a tree-vote fraction, not a")
    print("  calibrated posterior, so the raw cut IS the operating point and a Bayesian")
    print("  prior correction over-corrects it into silence. Cut must be chosen by")
    print("  sweeping precision/recall, which is what this table does.")

    sep("Alert-document volume (aggregation by src_ip)")
    print("  NOTE: this simulator generates a RANDOM source IP for every BENIGN row")
    print("  (`_row_to_json`: 3 x 254^3 possible addresses), so no two benign false")
    print("  positives share a src_ip.  Aggregation therefore collapses nothing on")
    print("  this synthetic stream -- it only helps on real traffic where a host")
    print("  emits many flows.  Measured here so the claim is not overstated:")
    print()
    print(f"  Alert flows at T={NEW_THRESHOLD}: {new['alerts']:,} -> documents: {new['alerts']:,}")
    print(f"  Alert flows at T={OLD_THRESHOLD}: {old['alerts']:,} -> documents: {old['alerts']:,}")
    print("  The threshold change is what reduces volume here; aggregation is a")
    print("  real-traffic optimisation and this replay cannot demonstrate it.")

    sep("DONE")
    spark.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
