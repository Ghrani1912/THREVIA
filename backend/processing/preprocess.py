"""
Phase 2 — PySpark Preprocessing & Feature Extraction
Reads all 8 CICIDS2017 CSVs from HDFS (/threvia/raw), cleans and normalizes
them, and writes a consolidated dataset to /threvia/processed as Parquet.

Cleaning performed:
  1. Strip whitespace from column names (CICIDS2017 columns have leading spaces)
  2. Coerce all feature columns to double
  3. Replace infinity values with null, then impute nulls with column median
  4. Drop rows missing a Label
  5. Add binary label is_attack (1 = malicious, 0 = benign)

Usage:
  docker exec threvia-spark-master spark-submit \
      --master spark://spark-master:7077 \
      /workspace/backend/processing/preprocess.py
"""

import math
import sys

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.feature import StandardScaler, VectorAssembler
from pyspark.ml import Pipeline

HDFS_RAW = "hdfs://namenode:8020/threvia/raw"
HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"

# Non-feature columns in CICIDS2017
LABEL_COL = "Label"
NON_FEATURE_COLS = [LABEL_COL]

# CICIDS2017 is heavily class-imbalanced; use median instead of mean for imputation
def get_spark():
    return (
        SparkSession.builder.appName("Threvia-Phase2-Preprocess")
        .config("spark.sql.shuffle.partitions", "8")
        .config("spark.driver.memory", "2g")
        .config("spark.executor.memory", "2g")
        .config("spark.executor.instances", "1")
        .config("spark.executor.cores", "2")
        .config("spark.network.timeout", "600s")
        .config("spark.memory.fraction", "0.6")
        .config("spark.memory.storageFraction", "0.3")
        .config("spark.sql.files.maxPartitionBytes", "67108864")  # 64MB
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .getOrCreate()
    )


def clean_columns(df):
    """Strip whitespace from column names (CICIDS2017 quirk) and dedupe."""
    new_cols = []
    seen = set()
    for c in df.columns:
        c2 = c.strip().replace(" ", "_")
        base = c2
        i = 2
        while c2 in seen:
            c2 = f"{base}_{i}"
            i += 1
        seen.add(c2)
        new_cols.append(c2)
    return df.toDF(*new_cols)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print("THREVIA Phase 2 — Preprocessing")
    print("=" * 70)

    # 1. Read all raw CSVs into a single DataFrame
    print(f"\n[1/6] Reading raw CSVs from {HDFS_RAW} ...")
    df = (
        spark.read.option("header", True)
        .option("inferSchema", True)
        .csv(HDFS_RAW)
    )
    raw_count = df.count()

    # 2. Clean column names FIRST (CICIDS2017 columns have leading/trailing
    #    spaces, e.g. " Label", so must normalize before any column reference)
    print("\n[2/6] Cleaning column names ...")
    df = clean_columns(df)

    raw_label_values = [r[LABEL_COL] for r in df.select(LABEL_COL).distinct().collect()]
    print(f"    Raw rows      : {raw_count:,}")
    print(f"    Raw columns   : {len(df.columns)}")
    print(f"    Raw labels    : {sorted(raw_label_values)}")

    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]

    # 3. Cast features to double, replace inf with null
    print("\n[3/6] Casting features to double, replacing infinities ...")
    for c in feature_cols:
        df = df.withColumn(c, F.col(c).cast("double"))
    df = df.select(
        [
            F.when(F.isnan(F.col(c)) | F.col(c).isin(float("inf"), float("-inf")), None)
            .otherwise(F.col(c))
            .alias(c)
            if c in feature_cols
            else F.col(c)
            for c in df.columns
        ]
    )

    # 4. Impute nulls with column median (robust to skewed distributions)
    print("\n[4/6] Imputing missing values with column medians ...")
    # Only compute median for columns that actually have nulls (much cheaper)
    cols_with_nulls = {}
    for c in feature_cols:
        n = df.filter(F.col(c).isNull()).count()
        if n > 0:
            cols_with_nulls[c] = n
    print(f"    Columns with nulls/inf: {len(cols_with_nulls)}")
    for c, n in sorted(cols_with_nulls.items(), key=lambda x: -x[1]):
        print(f"      {c}: {n:,}")

    if cols_with_nulls:
        medians = (
            df.select(
                [F.percentile_approx(F.col(c), 0.5, 1000).alias(c)
                 for c in cols_with_nulls]
            )
            .first()
            .asDict()
        )
        fill_map = {c: float(medians[c]) for c in cols_with_nulls if medians[c] is not None}
        df = df.fillna(fill_map, subset=list(cols_with_nulls.keys()))
    else:
        print("    No nulls found — skipping imputation.")

    # 5. Drop rows missing Label, add binary is_attack
    print("\n[5/6] Dropping rows without a Label, adding is_attack ...")
    df = df.filter(F.col(LABEL_COL).isNotNull())
    df = df.withColumn(
        "is_attack",
        F.when(F.upper(F.trim(F.col(LABEL_COL))) == "BENIGN", F.lit(0)).otherwise(F.lit(1)),
    )

    # 6. Assemble features vector + scale (StandardScaler) for downstream ML
    print("\n[6/6] Assembling + scaling feature vector ...")
    assembler = VectorAssembler(
        inputCols=feature_cols, outputCol="raw_features", handleInvalid="keep"
    )
    scaler = StandardScaler(
        inputCol="raw_features", outputCol="scaled_features",
        withMean=True, withStd=True,
    )
    pipeline = Pipeline(stages=[assembler, scaler]).fit(df)
    df = pipeline.transform(df)

    # Also keep a plain feature column for classifiers that accept raw doubles
    clean_count = df.count()

    # 7. Write to HDFS as Parquet (snappy), overwrite for idempotent re-runs
    print(f"\nWriting {clean_count:,} rows to {HDFS_PROCESSED} ...")
    (
        df.write.mode("overwrite")
        .parquet(HDFS_PROCESSED)
    )

    # Persist label distribution + row counts for downstream validation
    label_dist = df.groupBy(LABEL_COL).count().orderBy(F.desc("count"))
    print("\nLabel distribution after cleaning:")
    label_dist.show(50, truncate=False)

    summary = label_dist.collect()
    print("=" * 70)
    print(f"PHASE 2 COMPLETE — {clean_count:,} rows written to {HDFS_PROCESSED}")
    print(f"  Features       : {len(feature_cols)}")
    print(f"  Attack rows    : {df.filter('is_attack = 1').count():,}")
    print(f"  Benign rows    : {df.filter('is_attack = 0').count():,}")
    print("=" * 70)

    spark.stop()


if __name__ == "__main__":
    sys.exit(main())
