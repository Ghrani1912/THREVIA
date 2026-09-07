"""
Advanced evaluation experiments — READ-ONLY (writes nothing to HDFS).

Parts (select with argv[1]):
  stratified  — A) Stratified-by-attack-type 80/20 split (every class in train+test)
  leakage     — B) Feature-leakage checks for the random-split 0.9996 AUC
  openset     — C) Open-set rejection: flag low-confidence preds as "unknown"
  clusters    — D) K-Means on Friday flows: do unseen attacks separate structurally?

Usage:
  docker exec threvia-spark-master bash -c \
    "/opt/spark/bin/spark-submit --master spark://spark-master:7077 \
     /workspace/backend/ml/advanced_eval.py <part>"
"""

import sys
from functools import reduce
import operator

from pyspark.sql import SparkSession, functions as F, Window
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import StringIndexer, VectorAssembler, StandardScaler
from pyspark.ml import Pipeline
from pyspark.ml.clustering import KMeans
from pyspark.ml.functions import vector_to_array

HDFS_RAW = "hdfs://namenode:8020/threvia/raw"
HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"

FRIDAY_FILES = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
}


def get_spark(name):
    return (
        SparkSession.builder.appName(name)
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


def load_and_preprocess(spark, friday_only=None):
    """Load raw CSVs, clean, impute with TRAIN-only medians, assemble+scale via
    pipeline fit on the provided training frame. Returns (train, test, feature_cols, labels).
    friday_only: None => all files; 'exclude' => Mon-Thu train; 'only' => Friday test."""
    df = (
        spark.read.option("header", True).option("inferSchema", True).csv(HDFS_RAW)
        .withColumn("_src", F.regexp_extract(F.input_file_name(), r"([^/]+)$", 1))
    )
    df = clean_columns(df)

    if friday_only == "exclude":
        df = df.filter(~F.col("_src").isin(list(FRIDAY_FILES)))
    elif friday_only == "only":
        df = df.filter(F.col("_src").isin(list(FRIDAY_FILES)))

    feature_cols = [c for c in df.columns if c not in ("Label", "_src")]
    for c in feature_cols:
        df = df.withColumn(c, F.col(c).cast("double"))
    df = df.select(
        [
            F.when(F.isnan(F.col(c)) | F.col(c).isin(float("inf"), float("-inf")), None)
            .otherwise(F.col(c)).alias(c)
            if c in feature_cols else F.col(c)
            for c in df.columns
        ]
    )

    # median imputation — caller splits BEFORE calling this for correctness
    return df, feature_cols


def impute_and_scale(train, test, feature_cols):
    """Fit medians/assembler/scaler on train only, apply to both."""
    null_cols = [c for c in feature_cols if train.filter(F.col(c).isNull()).count() > 0]
    if null_cols:
        medians = (
            train.select(
                [F.percentile_approx(F.col(c), 0.5, 1000).alias(c) for c in null_cols]
            ).first().asDict()
        )
        fill = {c: float(medians[c]) for c in null_cols if medians[c] is not None}
        train = train.fillna(fill, subset=null_cols)
        test = test.fillna(fill, subset=null_cols)

    train = train.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )
    test = test.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )

    indexer = StringIndexer(inputCol="Label", outputCol="attack_type_idx", handleInvalid="keep")
    idx_model = indexer.fit(train)
    train = idx_model.transform(train)
    test = idx_model.transform(test)  # unseen classes in test get NaN idx (skipped later)

    pipe = Pipeline(
        stages=[
            VectorAssembler(inputCols=feature_cols, outputCol="raw_features", handleInvalid="keep"),
            StandardScaler(inputCol="raw_features", outputCol="scaled_features",
                           withMean=True, withStd=True),
        ]
    ).fit(train)

    return pipe.transform(train), pipe.transform(test), idx_model.labels


def bin_metrics(preds):
    be = BinaryClassificationEvaluator(labelCol="is_attack", rawPredictionCol="rawPrediction")
    me = MulticlassClassificationEvaluator(labelCol="is_attack", predictionCol="prediction")
    return {
        "auc": be.setMetricName("areaUnderROC").evaluate(preds),
        "acc": me.setMetricName("accuracy").evaluate(preds),
        "prec": me.setMetricName("weightedPrecision").evaluate(preds),
        "rec": me.setMetricName("weightedRecall").evaluate(preds),
        "f1": me.setMetricName("f1").evaluate(preds),
    }


def multi_metrics(preds):
    me = MulticlassClassificationEvaluator(labelCol="attack_type_idx", predictionCol="prediction")
    return {
        "acc": me.setMetricName("accuracy").evaluate(preds),
        "prec": me.setMetricName("weightedPrecision").evaluate(preds),
        "rec": me.setMetricName("weightedRecall").evaluate(preds),
        "f1": me.setMetricName("f1").evaluate(preds),
    }


def print_bin(title, m):
    print(f"\n  {title}")
    print(f"    AUC-ROC   : {m['auc']:.4f}")
    print(f"    Accuracy  : {m['acc']:.4f}")
    print(f"    Precision : {m['prec']:.4f}")
    print(f"    Recall    : {m['rec']:.4f}")
    print(f"    F1        : {m['f1']:.4f}")


def print_multi(title, m):
    print(f"\n  {title}")
    print(f"    Accuracy  : {m['acc']:.4f}")
    print(f"    Precision : {m['prec']:.4f}")
    print(f"    Recall    : {m['rec']:.4f}")
    print(f"    F1        : {m['f1']:.4f}")


# ══════════════════════════════════════════════════════════════════
# PART A — Stratified-by-attack-type split
# ══════════════════════════════════════════════════════════════════
def part_stratified(spark):
    print("=" * 70)
    print("PART A — STRATIFIED-BY-ATTACK-TYPE 80/20 SPLIT")
    print("=" * 70)

    df, feature_cols = load_and_preprocess(spark)
    df = df.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )

    # TRUE stratified split: within each Label, order rows randomly and take
    # the first 20% as test. Guarantees every class appears in both sets.
    w = Window.partitionBy("Label").orderBy(F.rand(seed=42))
    df = df.withColumn("_rn", F.row_number().over(w))
    class_counts = df.groupBy("Label").agg(F.count("*").alias("n"))
    df = df.join(class_counts, "Label")
    df = df.withColumn("_is_test", (F.col("_rn") <= F.ceil(F.col("n") * 0.2)).cast("int"))
    df = df.drop("_rn", "n")
    df.cache()

    train = df.filter("_is_test = 0")
    test = df.filter("_is_test = 1")

    tr_n, te_n = train.count(), test.count()
    print(f"\n  Train: {tr_n:,}  Test: {te_n:,}  (split ratio {tr_n/(tr_n+te_n)*100:.1f}%/{te_n/(tr_n+te_n)*100:.1f}%)")

    # per-class presence check
    print("\n  Per-class presence (train vs test):")
    pc_train = train.groupBy("Label").count().withColumnRenamed("count", "train_n")
    pc_test = test.groupBy("Label").count().withColumnRenamed("count", "test_n")
    pc = pc_train.join(pc_test, "Label", "full_outer").fillna(0).orderBy(F.desc("train_n"))
    pc.show(20, truncate=False)

    train_p, test_p, labels = impute_and_scale(
        train.drop("_is_test", "_src"), test.drop("_is_test", "_src"), feature_cols
    )
    train_p.cache()

    # Binary RF
    print("\n  Training binary RF (50 trees, depth 10) ...")
    rf = RandomForestClassifier(featuresCol="scaled_features", labelCol="is_attack",
                                numTrees=50, maxDepth=10, seed=42)
    m = bin_metrics(rf.fit(train_p).transform(test_p))
    print_bin("Binary RF — stratified 80/20", m)

    # Multi-class RF (only classes present in train)
    print("\n  Training multi-class RF ...")
    rf_m = RandomForestClassifier(featuresCol="scaled_features", labelCol="attack_type_idx",
                                  numTrees=50, maxDepth=10, seed=42)
    preds_m = rf_m.fit(train_p).transform(test_p.filter(F.col("attack_type_idx").isNotNull()))
    m2 = multi_metrics(preds_m)
    print_multi(f"Multi-class RF — stratified 80/20 ({len(labels)} train classes)", m2)

    print("\n  Per-class precision/recall on test:")
    (
        preds_m.withColumn("correct", (F.col("attack_type_idx") == F.col("prediction")).cast("int"))
        .groupBy("attack_type_idx")
        .agg(
            F.count("*").alias("n"),
            F.round(F.avg("correct"), 4).alias("recall"),
        )
        .orderBy(F.desc("n"))
        .show(20, truncate=False)
    )

    spark.catalog.clearCache()


# ══════════════════════════════════════════════════════════════════
# PART B — Feature leakage checks
# ═══════════════════════════════════════════════════ determinism═══
def part_leakage(spark):
    print("=" * 70)
    print("PART B — FEATURE LEAKAGE CHECKS (is 0.9996 AUC inflated?)")
    print("=" * 70)

    df, feature_cols = load_and_preprocess(spark)
    df = df.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    ).cache()

    # B1. Destination_Port distribution per label (quasi-identifier check)
    print("\n  B1. Destination_Port stats per label (is it a giveaway?):")
    (
        df.groupBy("Label")
        .agg(
            F.count("*").alias("n"),
            F.expr("percentile_approx(`Destination_Port`, 0.5, 1000)").alias("dst_port_median"),
            F.expr("count(DISTINCT `Destination_Port`)").alias("distinct_ports"),
            F.round(F.avg(F.when(F.col("Destination_Port") == 80, 1.0).otherwise(0.0)), 3).alias("pct_port80"),
            F.round(F.avg(F.when(F.col("Destination_Port") == 443, 1.0).otherwise(0.0)), 3).alias("pct_port443"),
        )
        .orderBy(F.desc("n"))
        .show(20, truncate=False)
    )

    # Port-only univariate separability: AUC of dst_port alone as score
    print("  B2. Univariate AUC of Destination_Port alone (binary is_attack):")
    from pyspark.ml.classification import LogisticRegression as LR
    va = VectorAssembler(inputCols=["Destination_Port"], outputCol="f")
    dfp = va.transform(df)
    lr = LR(featuresCol="f", labelCol="is_attack", maxIter=10)
    preds = lr.fit(dfp).transform(dfp)
    be = BinaryClassificationEvaluator(labelCol="is_attack", rawPredictionCol="rawPrediction")
    auc_port = be.evaluate(preds)
    print(f"    LR on Destination_Port ONLY  -> AUC = {auc_port:.4f}")

    # B3. Flow_Duration / packet-count style degenerate constants per attack
    print("\n  B3. Per-label variance of key features (near-zero variance = signature-like):")
    for c in ["Flow_Duration", "Flow_Packets/s", "Fwd_Packet_Length_Mean", "Idle_Mean"]:
        stats = (
            df.groupBy("Label")
            .agg(F.round(F.stddev(c), 2).alias("std"), F.round(F.avg(c), 2).alias("mean"))
            .orderBy(F.desc("mean"))
        )
        print(f"\n    {c}:")
        stats.show(20, truncate=False)

    # B4. Duplicate flow rows across days (same feature vector repeated)
    print("  B4. Duplicate feature-vector check (top repeated rows):")
    dup = (
        df.groupBy(feature_cols)
        .agg(F.count("*").alias("n"))
        .filter(F.col("n") > 1)
        .orderBy(F.desc("n"))
    )
    dup_n = dup.agg(F.sum("n")).first()[0] or 0
    total = df.count()
    print(f"    Rows belonging to duplicated feature vectors: {dup_n:,} / {total:,} ({dup_n/total*100:.1f}%)")
    dup.show(5, truncate=False)

    spark.catalog.clearCache()


# ══════════════════════════════════════════════════════════════════
# PART C — Open-set rejection experiment
# ══════════════════════════════════════════════════════════════════
def part_openset(spark):
    print("=" * 70)
    print("PART C — OPEN-SET REJECTION (flag 'unknown' instead of forcing a label)")
    print("=" * 70)
    print("  Setup: train on Mon-Thu (no Friday attacks), test on Friday.")
    print("  Friday attacks (DDoS, PortScan, Bot) are UNSEEN classes.\n")

    # train on Mon-Thu
    train_raw, feature_cols = load_and_preprocess(spark, friday_only="exclude")
    test_raw, _ = load_and_preprocess(spark, friday_only="only")

    # NOTE: imputation/scaling fit on TRAIN only
    train_p, test_p, labels = impute_and_scale(train_raw, test_raw, feature_cols)
    train_p.cache()

    rf = RandomForestClassifier(featuresCol="scaled_features", labelCol="attack_type_idx",
                                numTrees=50, maxDepth=10, seed=42)
    model = rf.fit(train_p)

    # probability column: RF gives probability vector over train classes
    preds = model.transform(test_p)
    preds = preds.withColumn(
        "max_prob",
        F.array_max(vector_to_array(F.col("probability"))),
    )

    n_test = preds.count()
    total_attack = preds.filter("is_attack = 1").count()
    print(f"  Friday test rows : {n_test:,}")
    print(f"  Friday attack rows (DDoS+PortScan+Bot): {total_attack:,}")

    THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
    print(f"\n  {'threshold':>9} | {'rejected→unknown':>16} | {'of which truly-attack':>21} | {'truly-benign':>12} | {'attack coverage':>15}")
    print("  " + "-" * 90)
    for t in THRESHOLDS:
        rej = preds.filter(F.col("max_prob") < t)
        rej_n = rej.count()
        rej_attack = rej.filter("is_attack = 1").count()
        rej_benign = rej.filter("is_attack = 0").count()
        cov = rej_attack / total_attack * 100 if total_attack else 0
        print(f"  {t:>9} | {rej_n:>16,} | {rej_attack:>21,} | {rej_benign:>12,} | {cov:>14.1f}%")

    # At threshold 0.7, per-label breakdown of rejected rows
    t = 0.7
    print(f"\n  Rejected rows at threshold={t}, by true label:")
    (
        preds.filter(F.col("max_prob") < t)
        .groupBy("Label")
        .agg(F.count("*").alias("rejected"))
        .orderBy(F.desc("rejected"))
        .show(20, truncate=False)
    )

    # Baseline: without rejection, how many Friday attacks got mislabeled BENIGN?
    forced = preds.filter((F.col("prediction") == 0.0) & (F.col("is_attack") == 1)).count()
    print(f"  Baseline (no rejection): Friday attack rows forced to 'BENIGN': {forced:,}")
    print(f"  With rejection @0.7, of those {forced:,} → how many now flagged unknown:")
    now_flagged = preds.filter(
        (F.col("max_prob") < t) & (F.col("prediction") == 0.0) & (F.col("is_attack") == 1)
    ).count()
    print(f"    {now_flagged:,} ({now_flagged/forced*100 if forced else 0:.1f}% of forced-BENIGN attacks)")

    spark.catalog.clearCache()


# ══════════════════════════════════════════════════════════════════
# PART D — K-Means structural separability on Friday
# ══════════════════════════════════════════════════════════════════
def part_clusters(spark):
    print("=" * 70)
    print("PART D — K-MEANS ON FRIDAY: DO UNSEEN ATTACKS SEPARATE STRUCTURALLY?")
    print("=" * 70)

    friday, feature_cols = load_and_preprocess(spark, friday_only="only")

    # Friday-only pipeline (fit on Friday itself — unsupervised needs no labels)
    null_cols = [c for c in feature_cols if friday.filter(F.col(c).isNull()).count() > 0]
    if null_cols:
        medians = (
            friday.select(
                [F.percentile_approx(F.col(c), 0.5, 1000).alias(c) for c in null_cols]
            ).first().asDict()
        )
        fill = {c: float(medians[c]) for c in null_cols if medians[c] is not None}
        friday = friday.fillna(fill, subset=null_cols)

    friday = friday.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )

    pipe = Pipeline(
        stages=[
            VectorAssembler(inputCols=feature_cols, outputCol="raw_features", handleInvalid="keep"),
            StandardScaler(inputCol="raw_features", outputCol="scaled_features",
                           withMean=True, withStd=True),
        ]
    ).fit(friday)
    friday_p = pipe.transform(friday).cache()

    for k in (3, 5, 8):
        print(f"\n  ── K-Means k={k} ──")
        km = KMeans(featuresCol="scaled_features", predictionCol="cluster", k=k,
                    maxIter=20, seed=42)
        model = km.fit(friday_p)
        scored = model.transform(friday_p)

        from pyspark.ml.evaluation import ClusteringEvaluator
        sil = ClusteringEvaluator(featuresCol="scaled_features", predictionCol="cluster",
                                  metricName="silhouette").evaluate(scored)
        print(f"    Silhouette: {sil:.4f}")

        comp = (
            scored.groupBy("cluster", "Label").count()
            .orderBy("cluster", F.desc("count"))
        )
        # purity-style summary
        dom = (
            comp.withColumn("rn", F.row_number().over(
                Window.partitionBy("cluster").orderBy(F.desc("count"))))
            .filter("rn = 1")
            .select("cluster", "Label", "count")
        )
        totals = scored.groupBy("cluster").count().withColumnRenamed("count", "total")
        purity_df = dom.join(totals, "cluster").withColumn("purity", F.round(F.col("count") / F.col("total"), 3))
        purity_df.orderBy("cluster").show(truncate=False)

        # attack-vs-benign composition per cluster
        avb = (
            scored.groupBy("cluster")
            .agg(
                F.sum(F.when(F.col("is_attack") == 1, 1).otherwise(0)).alias("attack"),
                F.sum(F.when(F.col("is_attack") == 0, 1).otherwise(0)).alias("benign"),
            )
            .withColumn("attack_pct", F.round(F.col("attack") / (F.col("attack") + F.col("benign")) * 100, 1))
            .orderBy("cluster")
        )
        avb.show(truncate=False)

    spark.catalog.clearCache()


def main():
    part = sys.argv[1] if len(sys.argv) > 1 else "stratified"
    print(f"\n>>> RUNNING PART: {part} <<<\n")
    spark = get_spark(f"Threvia-AdvEval-{part}")
    spark.sparkContext.setLogLevel("WARN")

    if part == "stratified":
        part_stratified(spark)
    elif part == "leakage":
        part_leakage(spark)
    elif part == "openset":
        part_openset(spark)
    elif part == "clusters":
        part_clusters(spark)
    else:
        print(f"Unknown part: {part}. Use stratified|leakage|openset|clusters")
        sys.exit(1)

    spark.stop()


if __name__ == "__main__":
    main()
