"""
Phase 3 — Temporal Train/Test Evaluation (Rigorous)

Addresses three concerns with the initial random-split evaluation:
  1. Global scaler leakage  — StandardScaler was fit on ALL data in Phase 2.
                             Here we fit scaler ONLY on train.
  2. Temporal leakage       — Random 80/20 splits let correlated flows from
                             the same attack session appear in both train/test.
                             Here we use a strict day-based split.
  3. Class imbalance        — Reports per-class precision/recall alongside
                             weighted averages so we see minority-class perf.

Split:
  TRAIN : Monday, Tuesday, Wednesday, Thursday (all day files)
  TEST  : Friday (3 files — DDoS, PortScan, Bot/Benign morning)

Reads raw CSVs from HDFS, applies preprocessing fitted ONLY on train.

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      /workspace/backend/ml/temporal_eval.py
"""

import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import StandardScaler, StringIndexer, VectorAssembler
from pyspark.ml import Pipeline

HDFS_RAW    = "hdfs://namenode:8020/threvia/raw"
HDFS_MODELS = "hdfs://namenode:8020/threvia/models"
LABEL_COL   = "Label"
BINARY_COL  = "is_attack"
MULTI_COL   = "attack_type_idx"

# Files belonging to each split (as they appear in HDFS /threvia/raw)
FRIDAY_FILES = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
}


def get_spark():
    return (
        SparkSession.builder.appName("Threvia-TemporalEval")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "600s")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )


def clean_columns(df):
    """Strip whitespace from CICIDS2017 column names and deduplicate."""
    seen, new_cols = set(), []
    for c in df.columns:
        c2 = c.strip().replace(" ", "_")
        base, i = c2, 2
        while c2 in seen:
            c2 = f"{base}_{i}"
            i += 1
        seen.add(c2)
        new_cols.append(c2)
    return df.toDF(*new_cols)


def replace_inf_with_null(df, cols):
    """Replace inf/-inf/NaN with null for a list of columns."""
    return df.select([
        F.when(F.isnan(F.col(c)) | F.col(c).isin(float("inf"), float("-inf")), None)
        .otherwise(F.col(c)).alias(c)
        if c in cols else F.col(c)
        for c in df.columns
    ])


def sep(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")
    sep("THREVIA — Temporal Evaluation (Mon–Thu → Friday)")

    # ── 1. Read all raw CSVs, tag with source filename ─────────────
    print(f"\n[1/7] Reading raw CSVs + tagging source day ...")
    df_raw = (
        spark.read.option("header", True)
        .option("inferSchema", True)
        .csv(HDFS_RAW)
        .withColumn("_src_file",
                    F.regexp_extract(F.input_file_name(), r"([^/]+)$", 1))
    )
    df_raw = clean_columns(df_raw)

    total = df_raw.count()
    print(f"    Total rows loaded : {total:,}")

    # ── 2. Class distribution check ────────────────────────────────
    sep("CLASS DISTRIBUTION CHECK")
    label_dist = (
        df_raw.groupBy(LABEL_COL).count()
        .withColumn("pct", F.round(F.col("count") / total * 100, 2))
        .orderBy(F.desc("count"))
    )
    label_dist.show(20, truncate=False)

    benign_n  = df_raw.filter(F.upper(F.trim(F.col(LABEL_COL))) == "BENIGN").count()
    attack_n  = total - benign_n
    print(f"    BENIGN : {benign_n:,}  ({benign_n/total*100:.1f}%)")
    print(f"    ATTACK : {attack_n:,}  ({attack_n/total*100:.1f}%)")
    print(f"    Imbalance ratio : {benign_n/attack_n:.1f}x (benign:attack)")

    # ── 3. Day-based split ─────────────────────────────────────────
    sep("TEMPORAL SPLIT")
    friday_condition = F.col("_src_file").isin(list(FRIDAY_FILES))

    train_raw = df_raw.filter(~friday_condition)
    test_raw  = df_raw.filter(friday_condition)

    print(f"\n    TRAIN (Mon–Thu) : {train_raw.count():,} rows")
    print(f"    TEST  (Friday)  : {test_raw.count():,} rows")

    print("\n    Friday label distribution:")
    (
        test_raw.groupBy(LABEL_COL).count()
        .orderBy(F.desc("count"))
        .show(20, truncate=False)
    )

    # ── 4. Preprocessing — fit ONLY on train ───────────────────────
    print("\n[4/7] Preprocessing — fitting pipeline on TRAIN only ...")
    feature_cols = [c for c in train_raw.columns
                    if c not in (LABEL_COL, "_src_file")]

    # Cast to double + replace inf on train
    for c in feature_cols:
        train_raw = train_raw.withColumn(c, F.col(c).cast("double"))
        test_raw  = test_raw.withColumn(c, F.col(c).cast("double"))

    train_raw = replace_inf_with_null(train_raw, feature_cols)
    test_raw  = replace_inf_with_null(test_raw, feature_cols)

    # Impute only null-containing columns — fit medians on TRAIN
    cols_with_nulls = [c for c in feature_cols
                       if train_raw.filter(F.col(c).isNull()).count() > 0]
    if cols_with_nulls:
        medians = (
            train_raw.select(
                [F.percentile_approx(F.col(c), 0.5, 1000).alias(c)
                 for c in cols_with_nulls]
            ).first().asDict()
        )
        fill_map = {c: float(medians[c]) for c in cols_with_nulls if medians[c] is not None}
        train_raw = train_raw.fillna(fill_map, subset=cols_with_nulls)
        test_raw  = test_raw.fillna(fill_map, subset=cols_with_nulls)
        print(f"    Imputed {len(cols_with_nulls)} column(s) using TRAIN medians: {cols_with_nulls}")
    else:
        print("    No null columns — skipping imputation.")

    # Add binary label
    def add_binary(df):
        return df.withColumn(
            BINARY_COL,
            F.when(F.upper(F.trim(F.col(LABEL_COL))) == "BENIGN", F.lit(0))
            .otherwise(F.lit(1))
        )
    train_raw = add_binary(train_raw)
    test_raw  = add_binary(test_raw)

    # StringIndexer for multi-class — fit on TRAIN
    indexer = StringIndexer(inputCol=LABEL_COL, outputCol=MULTI_COL, handleInvalid="keep")
    indexer_model = indexer.fit(train_raw)
    train_raw = indexer_model.transform(train_raw)
    test_raw  = indexer_model.transform(test_raw)
    print(f"    Label map (train): {dict(enumerate(indexer_model.labels))}")

    # VectorAssembler + StandardScaler — fit on TRAIN
    assembler = VectorAssembler(inputCols=feature_cols, outputCol="raw_features",
                                handleInvalid="keep")
    scaler    = StandardScaler(inputCol="raw_features", outputCol="scaled_features",
                               withMean=True, withStd=True)
    pipe = Pipeline(stages=[assembler, scaler])
    pipe_model = pipe.fit(train_raw)   # ← TRAIN ONLY

    train = pipe_model.transform(train_raw)
    test  = pipe_model.transform(test_raw)

    train.cache()
    print(f"\n    Pipeline fit on train. Transforming done.")

    # ── 5. Train Random Forest (binary) ───────────────────────────
    sep("A) Binary RF — Train Mon–Thu / Test Friday")
    rf_bin = RandomForestClassifier(
        featuresCol="scaled_features", labelCol=BINARY_COL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_bin_model = rf_bin.fit(train)
    preds_bin = rf_bin_model.transform(test)

    bin_eval   = BinaryClassificationEvaluator(labelCol=BINARY_COL,
                                               rawPredictionCol="rawPrediction")
    multi_eval = MulticlassClassificationEvaluator(labelCol=BINARY_COL,
                                                   predictionCol="prediction")

    auc  = bin_eval.setMetricName("areaUnderROC").evaluate(preds_bin)
    acc  = multi_eval.setMetricName("accuracy").evaluate(preds_bin)
    prec = multi_eval.setMetricName("weightedPrecision").evaluate(preds_bin)
    rec  = multi_eval.setMetricName("weightedRecall").evaluate(preds_bin)
    f1   = multi_eval.setMetricName("f1").evaluate(preds_bin)

    print(f"\n    AUC-ROC   : {auc:.4f}")
    print(f"    Accuracy  : {acc:.4f}")
    print(f"    Precision : {prec:.4f}")
    print(f"    Recall    : {rec:.4f}")
    print(f"    F1-Score  : {f1:.4f}")

    # Per-class breakdown (TP/FP/FN for attack vs benign)
    print("\n    Confusion matrix (Binary: 0=BENIGN, 1=attack):")
    (
        preds_bin.groupBy(BINARY_COL, "prediction").count()
        .orderBy(BINARY_COL, "prediction")
        .show()
    )

    # ── 6. Train Random Forest (multi-class) ──────────────────────
    sep("B) Multi-class RF — Train Mon–Thu / Test Friday")
    rf_multi = RandomForestClassifier(
        featuresCol="scaled_features", labelCol=MULTI_COL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_multi_model = rf_multi.fit(train)
    preds_multi = rf_multi_model.transform(test)

    m_eval = MulticlassClassificationEvaluator(labelCol=MULTI_COL,
                                               predictionCol="prediction")
    acc_m  = m_eval.setMetricName("accuracy").evaluate(preds_multi)
    prec_m = m_eval.setMetricName("weightedPrecision").evaluate(preds_multi)
    rec_m  = m_eval.setMetricName("weightedRecall").evaluate(preds_multi)
    f1_m   = m_eval.setMetricName("f1").evaluate(preds_multi)

    print(f"\n    Accuracy  : {acc_m:.4f}")
    print(f"    Precision : {prec_m:.4f}")
    print(f"    Recall    : {rec_m:.4f}")
    print(f"    F1-Score  : {f1_m:.4f}")

    print("\n    Per-attack confusion (label idx vs prediction):")
    (
        preds_multi.groupBy(MULTI_COL, "prediction").count()
        .orderBy(MULTI_COL, "prediction")
        .show(100, truncate=False)
    )

    # Save temporal models to separate path so they don't overwrite Phase 3
    rf_bin_model.write().overwrite().save(f"{HDFS_MODELS}/rf_binary_temporal")
    rf_multi_model.write().overwrite().save(f"{HDFS_MODELS}/rf_multiclass_temporal")

    # ── 7. Final comparison ────────────────────────────────────────
    sep("SUMMARY — Random vs Temporal Split Comparison")
    print(f"""
    ┌─────────────────────────────────────────────────────────────────┐
    │              Binary RF — is_attack (0/1)                       │
    ├──────────────────────────┬────────────────┬────────────────────┤
    │ Evaluation               │ Random 80/20   │ Temporal Fri test  │
    ├──────────────────────────┼────────────────┼────────────────────┤
    │ Accuracy                 │   0.9958       │   {acc:.4f}            │
    │ F1                       │   0.9958       │   {f1:.4f}            │
    │ AUC-ROC                  │   0.9996       │   {auc:.4f}            │
    └──────────────────────────┴────────────────┴────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │              Multi-class RF — 15 attack types                  │
    ├──────────────────────────┬────────────────┬────────────────────┤
    │ Evaluation               │ Random 80/20   │ Temporal Fri test  │
    ├──────────────────────────┼────────────────┼────────────────────┤
    │ Accuracy                 │   0.9962       │   {acc_m:.4f}            │
    │ F1                       │   0.9955       │   {f1_m:.4f}            │
    └──────────────────────────┴────────────────┴────────────────────┘
    """)

    sep("TEMPORAL EVALUATION COMPLETE")
    spark.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
