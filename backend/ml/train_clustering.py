"""
Phase 3 — K-Means Clustering
Groups similar network flows into clusters to discover patterns
in attack behaviors, including potentially unknown threat types.

Reads from  : hdfs://namenode:8020/threvia/processed  (Parquet)
Writes to   : hdfs://namenode:8020/threvia/models/kmeans
              hdfs://namenode:8020/threvia/output/clusters

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      /workspace/backend/ml/train_clustering.py
"""

import sys
from pyspark.sql import SparkSession, functions as F
from pyspark.ml.clustering import KMeans
from pyspark.ml.evaluation import ClusteringEvaluator

HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"
HDFS_MODELS    = "hdfs://namenode:8020/threvia/models"
HDFS_OUTPUT    = "hdfs://namenode:8020/threvia/output/clusters"
FEATURE_COL    = "scaled_features"
K              = 10   # number of clusters


def get_spark():
    return (
        SparkSession.builder.appName("Threvia-Phase3-KMeans")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "600s")
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print("  THREVIA Phase 3 — K-Means Clustering")
    print("=" * 70)

    # ── Load data ─────────────────────────────────────────────────
    print(f"\n[1/4] Loading Parquet from {HDFS_PROCESSED} ...")
    df = spark.read.parquet(HDFS_PROCESSED)
    print(f"    Rows: {df.count():,}")

    # ── Train K-Means ─────────────────────────────────────────────
    print(f"\n[2/4] Training K-Means (k={K}, maxIter=20, seed=42) ...")
    kmeans = KMeans(
        featuresCol=FEATURE_COL,
        predictionCol="cluster",
        k=K,
        maxIter=20,
        seed=42,
    )
    km_model = kmeans.fit(df)

    # Silhouette score (how well-separated clusters are; -1 to 1, higher=better)
    predictions = km_model.transform(df)
    evaluator = ClusteringEvaluator(
        featuresCol=FEATURE_COL, predictionCol="cluster", metricName="silhouette"
    )
    silhouette = evaluator.evaluate(predictions)
    print(f"    Silhouette score : {silhouette:.4f}  (range: -1 to 1, higher is better)")

    # ── Cluster composition ───────────────────────────────────────
    print("\n[3/4] Cluster composition (cluster → label distribution):")
    composition = (
        predictions.groupBy("cluster", "Label")
        .count()
        .orderBy("cluster", F.desc("count"))
    )

    # Summary: dominant label per cluster
    dominant = (
        composition.groupBy("cluster")
        .agg(
            F.first("Label").alias("dominant_label"),
            F.sum("count").alias("total"),
        )
        .orderBy("cluster")
    )

    print("\n    Cluster  | Total rows | Dominant label")
    print("    " + "-" * 55)
    for row in dominant.collect():
        print(f"    {row['cluster']:<9} | {row['total']:<10,} | {row['dominant_label']}")

    print("\n    Full cluster × label breakdown:")
    composition.show(K * 15, truncate=False)

    # ── Save model + predictions ──────────────────────────────────
    print(f"\n[4/4] Saving model and cluster assignments ...")
    km_model.write().overwrite().save(f"{HDFS_MODELS}/kmeans")

    # Write cluster assignments (cluster id + label + is_attack) for dashboard
    (
        predictions.select("cluster", "Label", "is_attack")
        .write.mode("overwrite")
        .parquet(HDFS_OUTPUT)
    )

    print(f"    KMeans model    → {HDFS_MODELS}/kmeans")
    print(f"    Cluster output  → {HDFS_OUTPUT}")

    print("\n" + "=" * 70)
    print(f"PHASE 3 CLUSTERING COMPLETE  (k={K}, silhouette={silhouette:.4f})")
    print("=" * 70)

    spark.stop()
    sys.exit(0)


if __name__ == "__main__":
    main()
