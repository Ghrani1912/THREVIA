"""
Quick results reader — loads saved models + test split, prints full
multi-class metrics + per-class breakdown.
No training, read-only.
"""
import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassificationModel, LogisticRegressionModel
from pyspark.ml.evaluation import MulticlassClassificationEvaluator, BinaryClassificationEvaluator
from pyspark.ml.feature import StringIndexer

HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"
HDFS_MODELS    = "hdfs://namenode:8020/threvia/models"
FEATURE_COL    = "scaled_features"
BINARY_LABEL   = "is_attack"
MULTI_LABEL    = "attack_type_idx"

def get_spark():
    return (
        SparkSession.builder.appName("Threvia-PrintResults")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )

def sep(title=""):
    print("\n" + "=" * 72)
    if title:
        print(f"  {title}")
        print("=" * 72)

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    sep("THREVIA Phase 3 — Saved Model Results")

    # ── Load processed data + reproduce same 80/20 split ──────────
    print(f"\nLoading processed Parquet ...")
    df = spark.read.parquet(HDFS_PROCESSED)
    total = df.count()
    print(f"  Total rows : {total:,}")

    # Re-encode label (same as training)
    indexer = StringIndexer(inputCol="Label", outputCol=MULTI_LABEL, handleInvalid="keep")
    indexer_model = indexer.fit(df)
    df = indexer_model.transform(df)
    label_map = {i: v for i, v in enumerate(indexer_model.labels)}
    print(f"  Label map  : {label_map}")

    # Same 80/20 split seed
    _, test = df.randomSplit([0.8, 0.2], seed=42)
    test.cache()
    print(f"  Test rows  : {test.count():,}")

    eval_bin   = BinaryClassificationEvaluator(labelCol=BINARY_LABEL, rawPredictionCol="rawPrediction")
    eval_multi = MulticlassClassificationEvaluator(labelCol=MULTI_LABEL, predictionCol="prediction")
    eval_bin2  = MulticlassClassificationEvaluator(labelCol=BINARY_LABEL, predictionCol="prediction")

    # ── Load label map CSV saved during training ───────────────────
    try:
        lm_df = spark.read.option("header", True).csv(f"{HDFS_MODELS}/label_map")
        print("\n  Label map from HDFS:")
        lm_df.orderBy("idx").show(20, truncate=False)
    except Exception as e:
        print(f"  (label_map CSV not found: {e})")

    # ══════════════════════════════════════════════════════════════
    # RANDOM FOREST — BINARY
    # ══════════════════════════════════════════════════════════════
    sep("1. Random Forest — Binary (is_attack 0/1)")
    rf_bin = RandomForestClassificationModel.load(f"{HDFS_MODELS}/rf_binary")
    preds = rf_bin.transform(test)

    auc  = eval_bin.setMetricName("areaUnderROC").evaluate(preds)
    acc  = eval_bin2.setMetricName("accuracy").evaluate(preds)
    prec = eval_bin2.setMetricName("weightedPrecision").evaluate(preds)
    rec  = eval_bin2.setMetricName("weightedRecall").evaluate(preds)
    f1   = eval_bin2.setMetricName("f1").evaluate(preds)
    print(f"\n  AUC-ROC   : {auc:.4f}")
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1        : {f1:.4f}")
    print("\n  Confusion matrix:")
    preds.groupBy(BINARY_LABEL, "prediction").count().orderBy(BINARY_LABEL, "prediction").show()

    # ══════════════════════════════════════════════════════════════
    # RANDOM FOREST — MULTI-CLASS
    # ══════════════════════════════════════════════════════════════
    sep("2. Random Forest — Multi-class (15 attack types)")
    rf_multi = RandomForestClassificationModel.load(f"{HDFS_MODELS}/rf_multiclass")
    preds_m = rf_multi.transform(test)

    acc_m  = eval_multi.setMetricName("accuracy").evaluate(preds_m)
    prec_m = eval_multi.setMetricName("weightedPrecision").evaluate(preds_m)
    rec_m  = eval_multi.setMetricName("weightedRecall").evaluate(preds_m)
    f1_m   = eval_multi.setMetricName("f1").evaluate(preds_m)
    print(f"\n  Accuracy  : {acc_m:.4f}")
    print(f"  Precision : {prec_m:.4f}")
    print(f"  Recall    : {rec_m:.4f}")
    print(f"  F1        : {f1_m:.4f}")

    # Per-class breakdown
    print("\n  Per-class results (label_idx → name, support, recall):")
    per_class = (
        preds_m
        .groupBy(MULTI_LABEL, "prediction")
        .count()
        .orderBy(MULTI_LABEL, "prediction")
    )

    # Build per-class recall table
    total_per_class = preds_m.groupBy(MULTI_LABEL).count().withColumnRenamed("count", "support")
    correct = (
        preds_m.filter(F.col(MULTI_LABEL) == F.col("prediction"))
        .groupBy(MULTI_LABEL).count().withColumnRenamed("count", "correct")
    )
    class_recall = (
        total_per_class.join(correct, MULTI_LABEL, "left")
        .fillna(0, subset=["correct"])
        .withColumn("recall", F.round(F.col("correct") / F.col("support"), 4))
        .orderBy(F.desc("support"))
    )
    # Add label name
    label_df = spark.createDataFrame(
        [(float(i), v) for i, v in label_map.items()], [MULTI_LABEL, "label_name"]
    )
    class_recall = class_recall.join(label_df, MULTI_LABEL, "left").orderBy(F.desc("support"))
    class_recall.select(MULTI_LABEL, "label_name", "support", "correct", "recall").show(20, truncate=False)

    # Full confusion matrix
    print("\n  Full confusion matrix (true_idx → pred_idx):")
    per_class.show(200, truncate=False)

    # ══════════════════════════════════════════════════════════════
    # LOGISTIC REGRESSION — BINARY
    # ══════════════════════════════════════════════════════════════
    sep("3. Logistic Regression — Binary")
    lr_bin = LogisticRegressionModel.load(f"{HDFS_MODELS}/lr_binary")
    preds_lr = lr_bin.transform(test)

    auc_lr  = eval_bin.setMetricName("areaUnderROC").evaluate(preds_lr)
    acc_lr  = eval_bin2.setMetricName("accuracy").evaluate(preds_lr)
    prec_lr = eval_bin2.setMetricName("weightedPrecision").evaluate(preds_lr)
    rec_lr  = eval_bin2.setMetricName("weightedRecall").evaluate(preds_lr)
    f1_lr   = eval_bin2.setMetricName("f1").evaluate(preds_lr)
    print(f"\n  AUC-ROC   : {auc_lr:.4f}")
    print(f"  Accuracy  : {acc_lr:.4f}")
    print(f"  Precision : {prec_lr:.4f}")
    print(f"  Recall    : {rec_lr:.4f}")
    print(f"  F1        : {f1_lr:.4f}")

    # ══════════════════════════════════════════════════════════════
    # LOGISTIC REGRESSION — MULTI-CLASS
    # ══════════════════════════════════════════════════════════════
    sep("4. Logistic Regression — Multi-class")
    lr_multi = LogisticRegressionModel.load(f"{HDFS_MODELS}/lr_multiclass")
    preds_lrm = lr_multi.transform(test)

    acc_lrm  = eval_multi.setMetricName("accuracy").evaluate(preds_lrm)
    prec_lrm = eval_multi.setMetricName("weightedPrecision").evaluate(preds_lrm)
    rec_lrm  = eval_multi.setMetricName("weightedRecall").evaluate(preds_lrm)
    f1_lrm   = eval_multi.setMetricName("f1").evaluate(preds_lrm)
    print(f"\n  Accuracy  : {acc_lrm:.4f}")
    print(f"  Precision : {prec_lrm:.4f}")
    print(f"  Recall    : {rec_lrm:.4f}")
    print(f"  F1        : {f1_lrm:.4f}")

    per_class_lr = (
        preds_lrm
        .groupBy(MULTI_LABEL, "prediction")
        .count()
        .orderBy(MULTI_LABEL, "prediction")
    )
    total_per_class_lr = preds_lrm.groupBy(MULTI_LABEL).count().withColumnRenamed("count", "support")
    correct_lr = (
        preds_lrm.filter(F.col(MULTI_LABEL) == F.col("prediction"))
        .groupBy(MULTI_LABEL).count().withColumnRenamed("count", "correct")
    )
    class_recall_lr = (
        total_per_class_lr.join(correct_lr, MULTI_LABEL, "left")
        .fillna(0, subset=["correct"])
        .withColumn("recall", F.round(F.col("correct") / F.col("support"), 4))
        .join(label_df, MULTI_LABEL, "left")
        .orderBy(F.desc("support"))
    )
    print("\n  Per-class recall:")
    class_recall_lr.select(MULTI_LABEL, "label_name", "support", "correct", "recall").show(20, truncate=False)

    # ══════════════════════════════════════════════════════════════
    # SUMMARY TABLE
    # ══════════════════════════════════════════════════════════════
    sep("SUMMARY TABLE")
    print(f"""
  ┌────────────────────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
  │ Model                      │ Task     │ Accuracy │    F1    │  Prec    │  Recall  │
  ├────────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
  │ Random Forest              │ Binary   │  {acc:.4f}  │  {f1:.4f}  │  {prec:.4f}  │  {rec:.4f}  │
  │ Random Forest              │ Multi    │  {acc_m:.4f}  │  {f1_m:.4f}  │  {prec_m:.4f}  │  {rec_m:.4f}  │
  │ Logistic Regression        │ Binary   │  {acc_lr:.4f}  │  {f1_lr:.4f}  │  {prec_lr:.4f}  │  {rec_lr:.4f}  │
  │ Logistic Regression        │ Multi    │  {acc_lrm:.4f}  │  {f1_lrm:.4f}  │  {prec_lrm:.4f}  │  {rec_lrm:.4f}  │
  └────────────────────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
    """)

    sep("DONE")
    spark.stop()
    sys.exit(0)

if __name__ == "__main__":
    main()
