"""
Part D supplement — Friday-only K-Means for a single k value.
Run once per k to avoid memory/timeout issues with looping all k in one job.

Usage:
  spark-submit ... friday_cluster_k.py <k>

Example:
  docker exec threvia-spark-master spark-submit --master spark://spark-master:7077 \
      --driver-memory 2g --executor-memory 2g \
      /workspace/backend/ml/friday_cluster_k.py 5
"""

import sys
from pyspark.sql import SparkSession, functions as F, Window
from pyspark.ml import Pipeline
from pyspark.ml.clustering import KMeans
from pyspark.ml.evaluation import ClusteringEvaluator
from pyspark.ml.feature import VectorAssembler, StandardScaler

HDFS_RAW = "hdfs://namenode:8020/threvia/raw"

FRIDAY_FILES = {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
}


def get_spark(k):
    return (
        SparkSession.builder.appName(f"Threvia-FridayClusters-k{k}")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "800s")
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


def main():
    k = int(sys.argv[1]) if len(sys.argv) > 1 else 5

    spark = get_spark(k)
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print(f"  PART D — Friday K-Means  (k={k})")
    print("=" * 70)

    # ── Load Friday-only raw CSVs ─────────────────────────────────
    print(f"\n[1/4] Loading Friday CSVs from {HDFS_RAW} ...")
    df_raw = (
        spark.read.option("header", True).option("inferSchema", True).csv(HDFS_RAW)
        .withColumn("_src", F.regexp_extract(F.input_file_name(), r"([^/]+)$", 1))
    )
    df_raw = clean_columns(df_raw)
    df_raw = df_raw.filter(F.col("_src").isin(list(FRIDAY_FILES)))

    total = df_raw.count()
    print(f"    Friday rows loaded: {total:,}")

    # ── Feature prep ──────────────────────────────────────────────
    feature_cols = [c for c in df_raw.columns if c not in ("Label", "_src")]

    for c in feature_cols:
        df_raw = df_raw.withColumn(c, F.col(c).cast("double"))

    df_raw = df_raw.select([
        F.when(F.isnan(F.col(c)) | F.col(c).isin(float("inf"), float("-inf")), None)
        .otherwise(F.col(c)).alias(c)
        if c in feature_cols else F.col(c)
        for c in df_raw.columns
    ])

    # Impute nulls with Friday-only medians
    null_cols = [c for c in feature_cols if df_raw.filter(F.col(c).isNull()).count() > 0]
    if null_cols:
        medians = (
            df_raw.select(
                [F.percentile_approx(F.col(c), 0.5, 1000).alias(c) for c in null_cols]
            ).first().asDict()
        )
        fill = {c: float(medians[c]) for c in null_cols if medians[c] is not None}
        df_raw = df_raw.fillna(fill, subset=null_cols)

    df_raw = df_raw.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col("Label"))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )

    print(f"\n[2/4] Assembling + scaling features ...")
    pipe = Pipeline(stages=[
        VectorAssembler(inputCols=feature_cols, outputCol="raw_features", handleInvalid="keep"),
        StandardScaler(inputCol="raw_features", outputCol="scaled_features",
                       withMean=True, withStd=True),
    ]).fit(df_raw)
    friday = pipe.transform(df_raw).cache()

    # ── K-Means ───────────────────────────────────────────────────
    print(f"\n[3/4] Training K-Means (k={k}, maxIter=20, seed=42) ...")
    km = KMeans(
        featuresCol="scaled_features", predictionCol="cluster",
        k=k, maxIter=20, seed=42,
    )
    model = km.fit(friday)
    scored = model.transform(friday)

    sil = ClusteringEvaluator(
        featuresCol="scaled_features", predictionCol="cluster", metricName="silhouette"
    ).evaluate(scored)

    print(f"\n    Silhouette score: {sil:.4f}  (range -1 to 1, higher = better)")

    # ── Cluster analysis ──────────────────────────────────────────
    print(f"\n[4/4] Cluster composition ...")

    # Dominant label + purity per cluster
    comp = scored.groupBy("cluster", "Label").count().orderBy("cluster", F.desc("count"))
    dom = (
        comp.withColumn(
            "rn",
            F.row_number().over(Window.partitionBy("cluster").orderBy(F.desc("count")))
        )
        .filter("rn = 1")
        .select("cluster", "Label", "count")
    )
    totals = scored.groupBy("cluster").count().withColumnRenamed("count", "total")
    purity_df = (
        dom.join(totals, "cluster")
        .withColumn("purity", F.round(F.col("count") / F.col("total"), 3))
        .orderBy("cluster")
    )

    print(f"\n    Cluster purity (dominant label):")
    purity_df.show(k, truncate=False)

    # Attack vs benign per cluster
    avb = (
        scored.groupBy("cluster")
        .agg(
            F.sum(F.when(F.col("is_attack") == 1, 1).otherwise(0)).alias("attack"),
            F.sum(F.when(F.col("is_attack") == 0, 1).otherwise(0)).alias("benign"),
        )
        .withColumn(
            "attack_pct",
            F.round(F.col("attack") / (F.col("attack") + F.col("benign")) * 100, 1)
        )
        .orderBy("cluster")
    )

    print(f"    Attack vs Benign per cluster:")
    avb.show(k, truncate=False)

    # Full label breakdown per cluster
    print(f"    Full label breakdown per cluster:")
    comp.show(k * 10, truncate=False)

    print("\n" + "=" * 70)
    print(f"  PART D k={k} COMPLETE  —  Silhouette: {sil:.4f}")
    print("=" * 70)

    spark.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
