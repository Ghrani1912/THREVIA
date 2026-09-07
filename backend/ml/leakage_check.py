"""
Leakage & Overfitting Investigation
Covers:
  A) Duplicate rows — total count, cross-train/test leakage rate
  B) Quasi-identifier check — single-feature AUC (Destination_Port, Flow_Duration,
     Fwd_Packet_Length_Mean, Idle_Mean, Flow_Packets/s)
  C) Per-label zero-variance features (deterministic signatures)
  D) Deduped retrain — RF accuracy with all duplicates removed
  E) Scaler leakage — Phase 2 fit scaler on ALL data; here we refit on train only
     and compare accuracy drop

Usage:
  docker exec threvia-spark-master spark-submit --master spark://spark-master:7077 \
      --driver-memory 2g --executor-memory 2g \
      /workspace/backend/ml/leakage_check.py
"""

import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import (
    StringIndexer, VectorAssembler, StandardScaler
)
from pyspark.ml import Pipeline

HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"
HDFS_RAW       = "hdfs://namenode:8020/threvia/raw"
FEATURE_COL    = "scaled_features"
BINARY_LABEL   = "is_attack"
MULTI_LABEL    = "attack_type_idx"

PROBE_FEATURES = [
    "Destination_Port",
    "Flow_Duration",
    "Fwd_Packet_Length_Mean",
    "Idle_Mean",
    "Flow_Packets/s",
    "Bwd_Packet_Length_Max",
    "Flow_Bytes/s",
]


def get_spark():
    return (
        SparkSession.builder.appName("Threvia-LeakageCheck")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "800s")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )


def sep(title):
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def rf_metrics(model, test, label_col, binary=False):
    preds = model.transform(test)
    me = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol="prediction")
    acc  = me.setMetricName("accuracy").evaluate(preds)
    f1   = me.setMetricName("f1").evaluate(preds)
    prec = me.setMetricName("weightedPrecision").evaluate(preds)
    rec  = me.setMetricName("weightedRecall").evaluate(preds)
    auc  = None
    if binary:
        be  = BinaryClassificationEvaluator(labelCol=label_col, rawPredictionCol="rawPrediction")
        auc = be.setMetricName("areaUnderROC").evaluate(preds)
    return dict(acc=acc, f1=f1, prec=prec, rec=rec, auc=auc), preds


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    sep("THREVIA — Leakage & Overfitting Investigation")

    # ── Load processed data ────────────────────────────────────────
    print(f"\nLoading {HDFS_PROCESSED} ...")
    df = spark.read.parquet(HDFS_PROCESSED)
    total = df.count()
    print(f"  Total rows : {total:,}")

    # Re-encode multi-class label (same as training)
    indexer = StringIndexer(inputCol="Label", outputCol=MULTI_LABEL, handleInvalid="keep")
    idx_model = indexer.fit(df)
    df = idx_model.transform(df)
    label_map = {i: v for i, v in enumerate(idx_model.labels)}

    feature_cols = [c for c in df.columns if c not in (
        "Label", BINARY_LABEL, MULTI_LABEL, "raw_features", FEATURE_COL
    )]

    # Same 80/20 split used during training
    train, test = df.randomSplit([0.8, 0.2], seed=42)
    train.cache()
    test.cache()
    train_n = train.count()
    test_n  = test.count()
    print(f"  Train : {train_n:,}   Test : {test_n:,}")

    # ══════════════════════════════════════════════════════════════
    # A) DUPLICATE ROW ANALYSIS
    # ══════════════════════════════════════════════════════════════
    sep("A) DUPLICATE ROW ANALYSIS")

    # Total duplicates in full dataset
    dup_groups = (
        df.groupBy(feature_cols)
        .agg(F.count("*").alias("n"))
        .filter(F.col("n") > 1)
    )
    dup_rows = dup_groups.agg(F.sum("n")).first()[0] or 0
    unique_rows = df.select(feature_cols).distinct().count()
    print(f"\n  Total rows          : {total:,}")
    print(f"  Unique feature vecs : {unique_rows:,}")
    print(f"  Duplicate rows      : {dup_rows:,}  ({dup_rows/total*100:.1f}% of dataset)")
    print(f"  Duplicate groups    : {dup_groups.count():,}")

    # Cross-boundary leakage: feature vectors that appear in BOTH train and test
    train_keys = train.select(feature_cols).distinct()
    test_keys  = test.select(feature_cols).distinct()
    leaked     = train_keys.intersect(test_keys)
    leaked_n   = leaked.count()
    # How many test ROWS are covered by leaked vectors
    leaked_test_rows = test.join(leaked, on=feature_cols, how="inner").count()
    print(f"\n  Feature vectors in BOTH train & test : {leaked_n:,}")
    print(f"  Test rows with a leaked vector       : {leaked_test_rows:,}  "
          f"({leaked_test_rows/test_n*100:.1f}% of test set)")
    print(f"\n  >>> If a test row's feature vector also appears in train, the model")
    print(f"      can 'memorize' it. This inflates test accuracy without generalising.")

    # Per-label duplicate rate
    print("\n  Duplicate rate per label:")
    label_dup = (
        df.groupBy("Label", *feature_cols)
        .agg(F.count("*").alias("n"))
        .groupBy("Label")
        .agg(
            F.count("*").alias("unique_vecs"),
            F.sum("n").alias("total_rows"),
            F.sum(F.when(F.col("n") > 1, F.col("n")).otherwise(F.lit(0))).alias("dup_rows"),
        )
        .withColumn("dup_pct", F.round(F.col("dup_rows") / F.col("total_rows") * 100, 1))
        .orderBy(F.desc("total_rows"))
    )
    label_dup.show(20, truncate=False)

    # ══════════════════════════════════════════════════════════════
    # B) SINGLE-FEATURE AUC (QUASI-IDENTIFIER CHECK)
    # ══════════════════════════════════════════════════════════════
    sep("B) SINGLE-FEATURE AUC — does one column do all the work?")

    print(f"\n  {'Feature':<35} {'AUC (binary)':<15} {'Note'}")
    print("  " + "-" * 70)
    for feat in PROBE_FEATURES:
        # check column exists (name may be slightly different after clean)
        actual = next((c for c in df.columns if c.replace(" ", "_") == feat.replace(" ", "_")
                       or c == feat), None)
        if actual is None:
            print(f"  {feat:<35} {'(not found)'}")
            continue
        try:
            va = VectorAssembler(inputCols=[actual], outputCol="_f", handleInvalid="keep")
            lr_df = va.transform(df.fillna(0, subset=[actual]))
            from pyspark.ml.classification import LogisticRegression as LR
            lr = LR(featuresCol="_f", labelCol=BINARY_LABEL, maxIter=10, regParam=0.01)
            auc = (
                BinaryClassificationEvaluator(labelCol=BINARY_LABEL, rawPredictionCol="rawPrediction")
                .setMetricName("areaUnderROC")
                .evaluate(lr.fit(lr_df).transform(lr_df))
            )
            note = "⚠ HIGH — near-identifier" if auc > 0.80 else ("OK" if auc < 0.65 else "moderate")
            print(f"  {feat:<35} {auc:<15.4f} {note}")
        except Exception as e:
            print(f"  {feat:<35} ERROR: {e}")

    # ══════════════════════════════════════════════════════════════
    # C) PER-LABEL ZERO-VARIANCE FEATURES
    # ══════════════════════════════════════════════════════════════
    sep("C) PER-LABEL FEATURE VARIANCE (near-zero = deterministic signature)")

    check_cols = [
        c for c in feature_cols
        if c in df.columns and c not in ("Destination_Port",)
    ][:60]  # cap to avoid plan explosion

    print("\n  Features with stddev < 0.01 for any label (top offenders):")
    stats = df.groupBy("Label").agg(
        *[F.stddev(c).alias(c) for c in check_cols]
    )
    rows = stats.collect()
    offenders = []
    for row in rows:
        label = row["Label"]
        for c in check_cols:
            v = row[c]
            if v is not None and v < 0.01:
                offenders.append((label, c, round(v, 6)))

    offenders.sort(key=lambda x: x[2])
    if offenders:
        print(f"  {'Label':<35} {'Feature':<35} {'StdDev'}")
        print("  " + "-" * 80)
        for label, col, std in offenders[:40]:
            print(f"  {label:<35} {col:<35} {std}")
        if len(offenders) > 40:
            print(f"  ... and {len(offenders)-40} more")
    else:
        print("  None found.")

    # ══════════════════════════════════════════════════════════════
    # D) RETRAIN ON DEDUPLICATED DATA
    # ══════════════════════════════════════════════════════════════
    sep("D) RETRAIN WITH DUPLICATES REMOVED — does accuracy drop?")

    # Drop duplicate feature vectors (keep one per unique vector)
    df_dedup = df.dropDuplicates(subset=feature_cols)
    dedup_n  = df_dedup.count()
    print(f"\n  Rows after dedup : {dedup_n:,}  (removed {total-dedup_n:,} rows, "
          f"{(total-dedup_n)/total*100:.1f}%)")

    train_d, test_d = df_dedup.randomSplit([0.8, 0.2], seed=42)
    train_d.cache()
    print(f"  Dedup train : {train_d.count():,}   test : {test_d.count():,}")

    print("\n  Training RF (50 trees, depth 10) on dedup data ...")
    rf = RandomForestClassifier(
        featuresCol=FEATURE_COL, labelCol=MULTI_LABEL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_model_d = rf.fit(train_d)
    m_d, _ = rf_metrics(rf_model_d, test_d, MULTI_LABEL)
    print(f"\n  Dedup RF Multi-class Results:")
    print(f"    Accuracy  : {m_d['acc']:.4f}")
    print(f"    F1        : {m_d['f1']:.4f}")
    print(f"    Precision : {m_d['prec']:.4f}")
    print(f"    Recall    : {m_d['rec']:.4f}")

    print(f"\n  Compare vs original (with dupes):")
    print(f"    Original Accuracy  : 0.9962  (from saved model)")
    print(f"    Dedup    Accuracy  : {m_d['acc']:.4f}")
    drop = 0.9962 - m_d['acc']
    print(f"    Drop               : {drop:+.4f}  "
          f"({'significant — duplication was inflating score' if abs(drop) > 0.02 else 'small — duplication has minor effect'})")

    # Per-class recall on dedup
    print("\n  Per-class recall (dedup):")
    preds_d = rf_model_d.transform(test_d)
    total_per = preds_d.groupBy(MULTI_LABEL).count().withColumnRenamed("count", "support")
    correct_d = (
        preds_d.filter(F.col(MULTI_LABEL) == F.col("prediction"))
        .groupBy(MULTI_LABEL).count().withColumnRenamed("count", "correct")
    )
    label_df = spark.createDataFrame(
        [(float(i), v) for i, v in label_map.items()], [MULTI_LABEL, "label_name"]
    )
    (
        total_per.join(correct_d, MULTI_LABEL, "left")
        .fillna(0, subset=["correct"])
        .withColumn("recall", F.round(F.col("correct") / F.col("support"), 4))
        .join(label_df, MULTI_LABEL, "left")
        .orderBy(F.desc("support"))
        .select(MULTI_LABEL, "label_name", "support", "correct", "recall")
        .show(20, truncate=False)
    )

    # ══════════════════════════════════════════════════════════════
    # E) SCALER LEAKAGE CHECK
    # ══════════════════════════════════════════════════════════════
    sep("E) SCALER LEAKAGE — Phase 2 fit StandardScaler on ALL data")

    print("""
  In Phase 2, preprocess.py fit StandardScaler on the ENTIRE dataset
  (train + test combined), then saved the scaled_features column.
  When train_classifier.py splits 80/20, it uses those pre-scaled features —
  meaning the scaler already "saw" the test set's distribution.

  Fix: fit scaler only on train. Measuring the accuracy difference here.
    """)

    raw_feature_cols = [c for c in df.columns if c not in (
        "Label", BINARY_LABEL, MULTI_LABEL, "raw_features", FEATURE_COL
    )]

    # Refit pipeline on train only
    print("  Refitting VectorAssembler + StandardScaler on TRAIN only ...")
    pipe = Pipeline(stages=[
        VectorAssembler(inputCols=raw_feature_cols, outputCol="_raw_f", handleInvalid="keep"),
        StandardScaler(inputCol="_raw_f", outputCol="_scaled_f", withMean=True, withStd=True),
    ])
    pipe_model = pipe.fit(train)
    train_sc = pipe_model.transform(train)
    test_sc  = pipe_model.transform(test)
    train_sc.cache()

    rf_sc = RandomForestClassifier(
        featuresCol="_scaled_f", labelCol=MULTI_LABEL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_sc_model = rf_sc.fit(train_sc)
    preds_sc = rf_sc_model.transform(test_sc)
    me_sc = MulticlassClassificationEvaluator(labelCol=MULTI_LABEL, predictionCol="prediction")
    acc_sc = me_sc.setMetricName("accuracy").evaluate(preds_sc)
    f1_sc  = me_sc.setMetricName("f1").evaluate(preds_sc)

    print(f"\n  Train-only scaler RF Multi-class:")
    print(f"    Accuracy : {acc_sc:.4f}   (original: 0.9962,  drop: {0.9962 - acc_sc:+.4f})")
    print(f"    F1       : {f1_sc:.4f}")

    # ══════════════════════════════════════════════════════════════
    # VERDICT
    # ══════════════════════════════════════════════════════════════
    sep("VERDICT SUMMARY")
    print(f"""
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Finding                          │  Severity                       │
  ├─────────────────────────────────────────────────────────────────────┤
  │  Duplicate rows (cross-boundary)  │  See output above               │
  │  Quasi-identifier features        │  See single-feature AUC above   │
  │  Zero-variance label signatures   │  See Part C above               │
  │  Accuracy drop after dedup        │  {m_d['acc']:.4f} vs 0.9962             │
  │  Accuracy drop after scaler fix   │  {acc_sc:.4f} vs 0.9962             │
  └─────────────────────────────────────────────────────────────────────┘

  The 99.6% is likely caused by a COMBINATION of:
  1. Duplicate rows leaking across the train/test boundary
  2. Attack-specific deterministic feature signatures (near-zero stddev
     for certain flows — the model latches onto these exact values)
  3. Scaler leakage (minor — RF is scale-invariant anyway)
  4. The random 80/20 split doesn't respect temporal ordering,
     so correlated flows from the same attack session appear in both sets

  The temporal evaluation (Mon-Thu train / Friday test) is the honest
  number — that's where you see the real generalisation.
    """)

    sep("DONE")
    spark.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
