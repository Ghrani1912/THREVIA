"""
Phase 3 — Spark MLlib Classification
Trains three classifiers on the cleaned CICIDS2017 dataset:
  1. Random Forest       (primary — best for imbalanced data)
  2. Logistic Regression (baseline)
  3. Gradient Boosted Trees (optional, slower but accurate)

Two classification tasks:
  A. Binary     : is_attack (0 = BENIGN, 1 = attack)
  B. Multi-class: attack_type_idx (encoded Label — 15 classes)

Reads from  : hdfs://namenode:8020/threvia/processed  (Parquet)
Writes to   : hdfs://namenode:8020/threvia/models/

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      /workspace/backend/ml/train_classifier.py
"""

import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import (
    RandomForestClassifier,
    LogisticRegression,
    GBTClassifier,
)
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import StringIndexer
from pyspark.ml import Pipeline

HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"
HDFS_MODELS    = "hdfs://namenode:8020/threvia/models"
FEATURE_COL    = "scaled_features"
BINARY_LABEL   = "is_attack"
MULTI_LABEL    = "attack_type_idx"


def get_spark():
    return (
        SparkSession.builder.appName("Threvia-Phase3-Classifier")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "600s")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )


def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def evaluate_binary(predictions, label_col=BINARY_LABEL):
    """Return AUC-ROC, accuracy, precision, recall, F1."""
    bin_eval  = BinaryClassificationEvaluator(labelCol=label_col, rawPredictionCol="rawPrediction")
    multi_eval = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol="prediction")

    auc       = bin_eval.setMetricName("areaUnderROC").evaluate(predictions)
    accuracy  = multi_eval.setMetricName("accuracy").evaluate(predictions)
    precision = multi_eval.setMetricName("weightedPrecision").evaluate(predictions)
    recall    = multi_eval.setMetricName("weightedRecall").evaluate(predictions)
    f1        = multi_eval.setMetricName("f1").evaluate(predictions)
    return dict(auc=auc, accuracy=accuracy, precision=precision, recall=recall, f1=f1)


def evaluate_multi(predictions, label_col=MULTI_LABEL):
    """Return accuracy, precision, recall, F1 for multi-class."""
    eval_ = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol="prediction")
    accuracy  = eval_.setMetricName("accuracy").evaluate(predictions)
    precision = eval_.setMetricName("weightedPrecision").evaluate(predictions)
    recall    = eval_.setMetricName("weightedRecall").evaluate(predictions)
    f1        = eval_.setMetricName("f1").evaluate(predictions)
    return dict(accuracy=accuracy, precision=precision, recall=recall, f1=f1)


def print_metrics(metrics: dict):
    for k, v in metrics.items():
        print(f"    {k:<12}: {v:.4f}")


def confusion_matrix(predictions, label_col, n_classes):
    """Print a simple confusion matrix using Spark groupBy."""
    cm = (
        predictions.groupBy(label_col, "prediction")
        .count()
        .orderBy(label_col, "prediction")
    )
    print(f"\n    Confusion matrix (label vs prediction), top rows:")
    cm.show(n_classes * n_classes, truncate=False)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    print_section("THREVIA Phase 3 — MLlib Classification")

    # ── Load processed data ────────────────────────────────────────
    print(f"\n[1/5] Loading processed Parquet from {HDFS_PROCESSED} ...")
    df = spark.read.parquet(HDFS_PROCESSED)
    total = df.count()
    print(f"    Total rows : {total:,}")
    print(f"    Features   : {FEATURE_COL} (StandardScaler output)")

    # ── Encode multi-class label ───────────────────────────────────
    print("\n[2/5] Encoding Label → attack_type_idx (StringIndexer) ...")
    indexer = StringIndexer(inputCol="Label", outputCol=MULTI_LABEL, handleInvalid="keep")
    indexer_model = indexer.fit(df)
    df = indexer_model.transform(df)
    label_map = {i: v for i, v in enumerate(indexer_model.labels)}
    print(f"    Labels ({len(label_map)}): {label_map}")

    # Save label mapping to HDFS as a small CSV for the dashboard
    label_df = spark.createDataFrame(
        [(int(i), v) for i, v in label_map.items()], ["idx", "label"]
    )
    label_df.coalesce(1).write.mode("overwrite").option("header", True).csv(
        f"{HDFS_MODELS}/label_map"
    )

    # ── Train / test split ─────────────────────────────────────────
    print("\n[3/5] Splitting 80/20 train/test (seed=42) ...")
    train, test = df.randomSplit([0.8, 0.2], seed=42)
    train.cache()
    print(f"    Train : {train.count():,}")
    print(f"    Test  : {test.count():,}")

    results = {}

    # ══════════════════════════════════════════════════════════════
    # A) BINARY CLASSIFICATION
    # ══════════════════════════════════════════════════════════════
    print_section("A) Binary Classification  (is_attack: 0=BENIGN, 1=attack)")

    # A1. Random Forest (binary)
    print("\n--- Random Forest (binary) ---")
    rf_bin = RandomForestClassifier(
        featuresCol=FEATURE_COL, labelCol=BINARY_LABEL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_bin_model = rf_bin.fit(train)
    rf_bin_preds = rf_bin_model.transform(test)
    m = evaluate_binary(rf_bin_preds)
    print_metrics(m)
    results["RF_binary"] = m
    rf_bin_model.write().overwrite().save(f"{HDFS_MODELS}/rf_binary")
    print(f"    Model saved → {HDFS_MODELS}/rf_binary")

    # A2. Logistic Regression (binary)
    print("\n--- Logistic Regression (binary) ---")
    lr_bin = LogisticRegression(
        featuresCol=FEATURE_COL, labelCol=BINARY_LABEL,
        maxIter=20, regParam=0.01,
    )
    lr_bin_model = lr_bin.fit(train)
    lr_bin_preds = lr_bin_model.transform(test)
    m = evaluate_binary(lr_bin_preds)
    print_metrics(m)
    results["LR_binary"] = m
    lr_bin_model.write().overwrite().save(f"{HDFS_MODELS}/lr_binary")
    print(f"    Model saved → {HDFS_MODELS}/lr_binary")

    # ══════════════════════════════════════════════════════════════
    # B) MULTI-CLASS CLASSIFICATION
    # ══════════════════════════════════════════════════════════════
    print_section("B) Multi-class Classification  (15 attack types)")

    # B1. Random Forest (multi-class)
    print("\n--- Random Forest (multi-class) ---")
    rf_multi = RandomForestClassifier(
        featuresCol=FEATURE_COL, labelCol=MULTI_LABEL,
        numTrees=50, maxDepth=10, seed=42,
    )
    rf_multi_model = rf_multi.fit(train)
    rf_multi_preds = rf_multi_model.transform(test)
    m = evaluate_multi(rf_multi_preds)
    print_metrics(m)
    results["RF_multiclass"] = m
    confusion_matrix(rf_multi_preds, MULTI_LABEL, min(len(label_map), 10))
    rf_multi_model.write().overwrite().save(f"{HDFS_MODELS}/rf_multiclass")
    print(f"    Model saved → {HDFS_MODELS}/rf_multiclass")

    # B2. Logistic Regression (multi-class OVR)
    print("\n--- Logistic Regression (multi-class) ---")
    lr_multi = LogisticRegression(
        featuresCol=FEATURE_COL, labelCol=MULTI_LABEL,
        maxIter=20, regParam=0.01, family="multinomial",
    )
    lr_multi_model = lr_multi.fit(train)
    lr_multi_preds = lr_multi_model.transform(test)
    m = evaluate_multi(lr_multi_preds)
    print_metrics(m)
    results["LR_multiclass"] = m
    lr_multi_model.write().overwrite().save(f"{HDFS_MODELS}/lr_multiclass")
    print(f"    Model saved → {HDFS_MODELS}/lr_multiclass")

    # ── Feature importance (RF binary) ────────────────────────────
    print_section("Feature Importance — Random Forest (binary)")
    feature_cols = [c for c in df.columns
                    if c not in ("Label", "is_attack", MULTI_LABEL,
                                 "raw_features", "scaled_features")]
    importances = rf_bin_model.featureImportances.toArray()
    top20 = sorted(zip(feature_cols, importances), key=lambda x: -x[1])[:20]
    print("\n    Top 20 most important features:")
    for name, score in top20:
        bar = "█" * int(score * 300)
        print(f"    {name:<35} {score:.4f}  {bar}")

    # ── Final summary table ────────────────────────────────────────
    print_section("PHASE 3 RESULTS SUMMARY")
    print(f"\n    {'Model':<25} {'Task':<12} {'Accuracy':>10} {'F1':>10} {'AUC':>10}")
    print("    " + "-" * 70)
    for name, m in results.items():
        task = "binary" if "binary" in name else "multi"
        auc  = f"{m.get('auc', 0):.4f}" if "auc" in m else "   N/A"
        print(f"    {name:<25} {task:<12} {m['accuracy']:>10.4f} {m['f1']:>10.4f} {auc:>10}")

    print("\n" + "=" * 70)
    print("PHASE 3 CLASSIFICATION COMPLETE")
    print(f"Models saved to: {HDFS_MODELS}")
    print("=" * 70)

    spark.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
