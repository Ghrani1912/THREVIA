"""
calibrate_thresholds.py — derive the Phase 4 detection operating point from data
================================================================================
Writes ``backend/realtime/thresholds.json``, which ``backend/realtime/
detection_policy.py`` loads at runtime.  Re-run whenever the models are
retrained.

Why this exists
---------------
The detector's threshold was hardcoded in the streaming job and never tied to a
measurement.  It sat at 0.25 — *below* the untuned 0.50 baseline and nowhere
near the 0.65 that ``threshold_test.py`` recommended (FPR 12.87% → 3.65%).  A
threshold that nobody computes is a threshold nobody chose.

This script inverts the usual workflow: instead of sweeping thresholds and
eyeballing a trade-off table, you state the false-positive rate your analysts
can absorb and it returns the tightest operating point that honours it.

    T* = quantile(1 - target_FPR) of P(attack) over BENIGN holdout flows

FPR is monotone decreasing in T, so that quantile is exactly the lowest
threshold meeting the target — i.e. the one that keeps the most attack recall.
The attack holdouts are then scored at T* to report what the choice costs.

The Bot specialist's cut is derived differently, and deliberately
---------------------------------------------------------------
``rf_bot``'s ``probability`` is a Random Forest *tree-vote fraction*, not a
calibrated posterior, so the raw cut **is** the operating point.  Re-basing it
onto deployment odds via Bayes was implemented, measured, and rejected: at the
observed ``P(Bot | flagged) = 0.0222`` it demands a raw score of 0.9778, which
the model never emits -> zero Bot detections (see the module docstring of
``backend/realtime/detection_policy.py``).  So this script sweeps the raw cut and
picks the one with the best Bot recall subject to a precision floor you set.

Use ``README.md``-style judgement here: the trade is 0.50 -> 95.56% precision at
100% recall, versus 0.60 -> 100% precision at 60.66% recall.

Usage
-----
    docker exec threvia-spark-master spark-submit \\
        --master spark://spark-master:7077 \\
        --driver-memory 2g --executor-memory 2g \\
        /workspace/backend/ml/calibrate_thresholds.py --target-fpr 1.0

Writes to ``/workspace/backend/realtime/thresholds.json`` by default, which is
bind-mounted to ``./backend/realtime/thresholds.json`` on the host.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.functions import vector_to_array

sys.path.insert(0, "/workspace")
sys.path.insert(0, "/workspace/backend/ml")

# ── HDFS paths ────────────────────────────────────────────────────────────────
HDFS = "hdfs://namenode:8020/threvia"
HDFS_BENIGN_C2 = f"{HDFS}/corpus/friday_benign_c2"
HDFS_DDOS_TEST = f"{HDFS}/corpus/friday_ddos_test"
HDFS_BOT_TEST = f"{HDFS}/corpus/friday_bot_test"
HDFS_ATTACKS = [HDFS_DDOS_TEST, HDFS_BOT_TEST]
HDFS_SCALER = f"{HDFS}/models_clean/scaler_pipeline"
HDFS_RF_BIN = f"{HDFS}/models_clean/rf_binary"
HDFS_MEDIANS = f"{HDFS}/models_clean/imputer_medians"

DEFAULT_OUT = "/workspace/backend/realtime/thresholds.json"

LABEL_COL = "Label"
BINARY_COL = "is_attack"

# Grid used only to *report* context around the computed operating point.
CONTEXT_GRID = [0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85]


def sep(msg: str = "") -> None:
    print("\n" + "=" * 78 + (f"\n  {msg}\n" + "=" * 78 if msg else ""))


def parse_args():
    p = argparse.ArgumentParser(description="Derive the Phase 4 detection threshold.")
    p.add_argument("--target-fpr", type=float, default=1.0,
                   help="headline false-positive rate to honour, in percent (default 1.0)")
    p.add_argument("--min-recall", type=float, default=95.0,
                   help="warn if any attack holdout falls below this recall, in percent")
    p.add_argument("--benign", default=HDFS_BENIGN_C2,
                   help="path to the BENIGN holdout parquet")
    p.add_argument("--attacks", default=",".join(HDFS_ATTACKS),
                   help="comma-separated attack holdout parquet paths")
    p.add_argument("--bot-holdout", default=HDFS_BOT_TEST,
                   help="labelled holdout containing Bot rows, for the Bot cut sweep")
    p.add_argument("--bot-min-precision", type=float, default=95.0,
                   help="precision floor for the Bot cut, in percent (default 95.0)")
    p.add_argument("--bot-min-recall", type=float, default=50.0,
                   help="recall floor for the Bot cut, in percent (default 50.0). "
                        "Without this, a cut that detects almost no Bots can still "
                        "win on precision alone.")
    p.add_argument("--out", default=DEFAULT_OUT,
                   help=f"where to write thresholds.json (default {DEFAULT_OUT})")
    # spark-submit passes its own trailing arguments through.
    args, _unknown = p.parse_known_args()
    return args


def load_scaler_and_medians(spark, medians_path: str):
    ext_pipe = PipelineModel.load(HDFS_SCALER)
    fill_map: dict = {}
    try:
        med_row = spark.read.parquet(medians_path).first()
        fill_map = dict(med_row.asDict()) if med_row else {}
        print(f"  Imputer medians loaded: {len(fill_map)} columns")
    except Exception as exc:  # noqa: BLE001
        print(f"  WARNING: could not load imputer medians ({exc}) - falling back to 0.0")
    return ext_pipe, fill_map


def prep(spark, raw_df, ext_pipe, label_udf, fill_map):
    """Apply the training corpus' cleaning/scaling to an external holdout."""
    # The Friday-Morning CSV carries a duplicate 'Fwd Header Length' column that
    # Spark renames on read.  diagnose_fpr.py showed that leaving it unrenamed
    # silently breaks the scaler and fabricates a much worse FPR.
    if "Fwd Header Length34" in raw_df.columns:
        print("  Renamed Fwd Header Length34 -> Fwd Header Length (duplicate-col fix)")
        raw_df = raw_df.withColumnRenamed("Fwd Header Length34", "Fwd Header Length")
    if "Fwd Header Length55" in raw_df.columns:
        raw_df = raw_df.drop("Fwd Header Length55")
    if "Fwd Header Length" not in raw_df.columns and "Fwd Header Length34" not in raw_df.columns:
        pass

    skip = {LABEL_COL, BINARY_COL, "attack_type_idx", "weight",
            "Timestamp", "Flow ID", "Source IP", "Destination IP", "Protocol"}
    feat_cols = [c for c in raw_df.columns if c not in skip]

    from train_clean_corpus import clean_and_scale_external
    return clean_and_scale_external(spark, raw_df, feat_cols, ext_pipe, label_udf, fill_map=fill_map)


def score(spark, rf_bin, scaled_df):
    return (
        rf_bin.transform(scaled_df)
        .withColumn("_prob_arr", vector_to_array("probability"))
        .withColumn("p_attack", F.col("_prob_arr")[1])
        .select(BINARY_COL, "p_attack")
        .cache()
    )


def main() -> int:
    args = parse_args()
    attack_paths = [p.strip() for p in args.attacks.split(",") if p.strip()]

    spark = (
        SparkSession.builder
        .appName("Threvia-CalibrateThresholds")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    from pyspark.sql.types import StringType
    from backend.processing.schema_maps import LABEL_NORMALISE
    from backend.realtime.detection_policy import DEFAULTS

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )

    sep("Loading models")
    ext_pipe, fill_map = load_scaler_and_medians(spark, HDFS_MEDIANS)
    rf_bin = RandomForestClassificationModel.load(HDFS_RF_BIN)

    sep("Scoring the BENIGN holdout")
    raw_benign = spark.read.parquet(args.benign)
    benign_scaled = prep(spark, raw_benign, ext_pipe, label_udf, fill_map)
    benign_preds = score(spark, rf_bin, benign_scaled)

    # Guard against an attack row sneaking into a "benign" split: a single
    # mislabelled attack row cannot move the quantile, but a mislabelled file can.
    if BINARY_COL in benign_preds.columns:
        n_benign = benign_preds.filter(F.col(BINARY_COL) == 0).count()
        if n_benign == 0:
            print("  ERROR: benign holdout contains no BENIGN rows.")
            return 2
        benign_preds = benign_preds.filter(F.col(BINARY_COL) == 0)
    n_benign = benign_preds.count()
    print(f"  BENIGN holdout flows: {n_benign:,}")
    if n_benign < 10_000:
        print("  WARNING: holdout is small; the threshold will be noisy.")

    sep("Scoring attack holdouts")
    attack_preds: dict[str, object] = {}
    for path in attack_paths:
        try:
            raw = spark.read.parquet(path)
            scaled = prep(spark, raw, ext_pipe, label_udf, fill_map)
            preds = score(spark, rf_bin, scaled).cache()
            attack_preds[path.rsplit("/", 1)[-1]] = preds
            print(f"  {path.rsplit('/', 1)[-1]:<28} {preds.count():>10,} flows")
        except Exception as exc:  # noqa: BLE001
            print(f"  SKIPPED {path}: {exc}")

    # ── Derive the threshold ──────────────────────────────────────────────────
    sep("Deriving the operating point")
    q = max(0.0, min(0.999, 1.0 - args.target_fpr / 100.0))
    threshold = float(benign_preds.approxQuantile("p_attack", [q], 0.001)[0])
    print(f"  Target FPR          : {args.target_fpr:.2f}%")
    print(f"  Quantile of BENIGN  : {q:.4f}")
    print(f"  => attack_threshold : {threshold:.4f}")

    def fpr_at(t: float) -> float:
        return benign_preds.filter(F.col("p_attack") >= t).count() / n_benign * 100.0

    def recall_at(t: float) -> dict[str, float]:
        out = {}
        for name, preds in attack_preds.items():
            total = preds.count()
            if total:
                hit = preds.filter(F.col("p_attack") >= t).count()
                out[name] = hit / total * 100.0
        return out

    sep("Context — FPR and recall across the grid")
    names = list(attack_preds)
    header = f"  {'T':>6} | {'FPR%':>7} | " + " | ".join(f"{n[:14]:>14}" for n in names)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for t in sorted(set(CONTEXT_GRID + [round(threshold, 4)])):
        rec = recall_at(t)
        marker = "  <-- chosen" if abs(t - threshold) < 1e-9 else ""
        cells = " | ".join(f"{rec.get(n, float('nan')):>13.2f}%" for n in names)
        print(f"  {t:>6.3f} | {fpr_at(t):>6.2f}% | {cells}{marker}")

    chosen_recall = recall_at(threshold)
    chosen_fpr = fpr_at(threshold)
    print()
    print(f"  Chosen T={threshold:.4f} → FPR {chosen_fpr:.2f}%, "
          + ", ".join(f"{k} recall {v:.2f}%" for k, v in chosen_recall.items()))

    warnings: list[str] = []
    for name, rec in chosen_recall.items():
        if rec < args.min_recall:
            warnings.append(
                f"{name} recall {rec:.2f}% is below the {args.min_recall:.0f}% floor — "
                f"lower --target-fpr or retrain with capped class weights "
                f"(see FINAL_MODEL_EVALUATION.md: Sql Injection carried a 22,420x weight)"
            )

    # ── Bot specialist raw cut ────────────────────────────────────────────────
    sep("Bot specialist raw cut")
    print("  rf_bot's probability is a tree-vote fraction, not a calibrated")
    print("  posterior, so the raw cut IS the operating point.  Bayes re-basing was")
    print("  measured to over-correct it into silence, so sweep instead.")
    print()

    from backend.realtime.detection_policy import DEFAULTS

    bot_cut = DEFAULTS["bot_threshold"]
    bot_prev = DEFAULTS["bot_deploy_prevalence"]
    try:
        rf_bot = RandomForestClassificationModel.load(f"{HDFS}/models_clean/rf_bot_binary")
        raw_bot = spark.read.parquet(args.bot_holdout)
        bot_with_label = prep(spark, raw_bot, ext_pipe, label_udf, fill_map).withColumn(
            "is_bot",
            F.when(F.upper(F.trim(F.col(LABEL_COL))) == "BOT", F.lit(1)).otherwise(F.lit(0)),
        )
        combined = (
            bot_with_label.select("is_bot", "scaled_features")
            .unionByName(benign_scaled.select("scaled_features").withColumn("is_bot", F.lit(0)))
        )
        scored_bot = (
            rf_bot.transform(combined)
            .withColumn("_bp", vector_to_array("probability"))
            .withColumn("p_bot", F.col("_bp")[1])
            .select("is_bot", "p_bot")
            .cache()
        )
        n_bot_pos = scored_bot.filter(F.col("is_bot") == 1).count()
        prev = n_bot_pos / scored_bot.count() if scored_bot.count() else 0.0
        print(f"  Holdout rows : {scored_bot.count():,}  (Bot={n_bot_pos:,}, "
              f"P(Bot)={prev:.4f})")
        print()
        hdr = f"  {'RAW CUT':>8} | {'LABELLED':>9} | {'TRULY BOT':>9} | {'PREC%':>7} | {'BOT RECALL%':>11}"
        print(hdr)
        print("  " + "-" * (len(hdr) - 2))
        best = None
        for cut in (0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90):
            sel = scored_bot.filter(F.col("p_bot") >= cut)
            labelled = sel.count()
            tp = sel.filter(F.col("is_bot") == 1).count()
            prec = tp / labelled * 100.0 if labelled else 0.0
            rec = tp / n_bot_pos * 100.0 if n_bot_pos else 0.0
            print(f"  {cut:>8.2f} | {labelled:>9,} | {tp:>9,} | {prec:>6.2f}% | {rec:>10.2f}%")
            # Best F1 subject to BOTH floors.  A precision-only floor happily
            # accepts a cut that detects almost no Bots (0.80 measured 100%
            # precision at 4.04% recall), which is the failure mode this sweep
            # exists to prevent.
            if labelled and prec >= args.bot_min_precision and rec >= args.bot_min_recall:
                f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
                if best is None or f1 > best[1]:
                    best = (cut, f1, rec, prec)
        if best:
            bot_cut = best[0]
            print(f"\n  Chosen Bot cut: {bot_cut:.2f} (precision {best[3]:.2f}%, "
                  f"recall {best[2]:.2f}%, F1 {best[1]:.3f})")
        else:
            warnings.append(
                f"no raw rf_bot cut holds BOTH {args.bot_min_precision:.0f}% precision "
                f"and {args.bot_min_recall:.0f}% recall on {args.bot_holdout}; keeping the "
                f"default {bot_cut:.2f}. Holdouts disagree: the streamed demo corpus "
                f"measured 95.56% precision at 100% Bot recall for a 0.50 cut, while "
                f"this Friday holdout is much harder. Treat this as a signal to retrain "
                f"the Bot specialist rather than a reason to raise the cut."
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Bot cut sweep skipped ({exc}); keeping {bot_cut:.2f}")

    # ── Emit ──────────────────────────────────────────────────────────────────
    config = {
        "_comment": "Generated by backend/ml/calibrate_thresholds.py — loaded by "
                    "backend/realtime/detection_policy.py at runtime.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_fpr_pct": args.target_fpr,
        "measured_fpr_pct": round(chosen_fpr, 4),
        "measured_recall_pct": {k: round(v, 4) for k, v in chosen_recall.items()},
        "benign_holdout_rows": n_benign,
        "benign_holdout_path": args.benign,
        "attack_holdout_paths": attack_paths,
        "thresholds": {
            "attack_threshold": round(threshold, 6),
            "bot_threshold": round(bot_cut, 6),
            "bot_train_prevalence": DEFAULTS["bot_train_prevalence"],
            # Only consulted when apply_prevalence_correction is enabled, which is
            # off by default because it silences the Bot model. See
            # backend/realtime/detection_policy.py.
            "bot_deploy_prevalence": bot_prev,
            "apply_prevalence_correction": False,
            # None = consult the Bot specialist for every flagged flow. Gating on
            # "binary RF unsure" was measured to discard 857 of 905 true Bots.
            "bot_route_max_confidence": None,
        },
    }
    try:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
            fh.write("\n")
        print(f"\n  Wrote {args.out}")
    except OSError as exc:
        print(f"\n  ERROR writing {args.out}: {exc}")
        warnings.append(f"could not write {args.out}")
        return 3

    sep("WARNINGS" if warnings else "DONE")
    for w in warnings:
        print(f"  ! {w}")
    if not warnings:
        print("  No warnings.")

    print("\n  Restart the streaming detector to pick this up "
          "(the policy is resolved once, at job start).")
    spark.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
