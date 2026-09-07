"""
Phase 2 — Output Validation
Confirms the outputs of both Phase 2 jobs exist in HDFS and are readable:
  1. /threvia/processed  — consolidated cleaned Parquet (row/column counts)
  2. /threvia/output/attack_frequency — MapReduce aggregation CSV

Usage:
  docker exec threvia-spark-master bash -c \
    "/opt/spark/bin/spark-submit --master spark://spark-master:7077 \
     /workspace/backend/processing/validate_phase2.py"
"""

from functools import reduce
import operator
import sys

from pyspark.sql import SparkSession, functions as F

HDFS_PROCESSED = "hdfs://namenode:8020/threvia/processed"
HDFS_MREDUCE = "hdfs://namenode:8020/threvia/output/attack_frequency"

EXPECTED_TOTAL = 2_830_743
EXPECTED_ATTACK = 557_646
EXPECTED_BENIGN = 2_273_097


def hdfs_ls(spark, path):
    """List an HDFS path via Hadoop FileSystem API through the Spark JVM."""
    jvm = spark._jvm
    conf = spark._jsc.hadoopConfiguration()
    uri = jvm.java.net.URI.create(path)
    fs = jvm.org.apache.hadoop.fs.FileSystem.get(uri, conf)
    p = jvm.org.apache.hadoop.fs.Path(path)
    if not fs.exists(p):
        return "(missing)"
    statuses = fs.listStatus(p)
    lines = []
    for s in statuses:
        name = s.getPath().getName()
        if s.isDirectory():
            lines.append(f"  {name}/")
        else:
            size_mb = s.getLen() / (1024 * 1024)
            lines.append(f"  {name}  ({size_mb:.2f} MB)")
    return "\n".join(lines)


def main():
    spark = SparkSession.builder.appName("Threvia-Phase2-Validate").getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print("THREVIA Phase 2 — Output Validation")
    print("=" * 70)

    passed = True

    # ── 1. Parquet output ────────────────────────────────────────
    print("\n[1] Validating /threvia/processed (Parquet) ...")
    try:
        df = spark.read.parquet(HDFS_PROCESSED)
        count = df.count()
        attack = df.filter("is_attack = 1").count()
        benign = df.filter("is_attack = 0").count()
        check_cols = [c for c in df.columns if c not in ("Label", "raw_features", "scaled_features")]
        null_cond = reduce(operator.or_, [F.col(c).isNull() for c in check_cols])
        nulls = df.filter(null_cond).count()

        print(f"    Rows          : {count:,}  (expected {EXPECTED_TOTAL:,})")
        print(f"    Columns       : {len(df.columns)}")
        print(f"    Attack rows   : {attack:,}  (expected {EXPECTED_ATTACK:,})")
        print(f"    Benign rows   : {benign:,}  (expected {EXPECTED_BENIGN:,})")
        print(f"    Rows w/ nulls : {nulls:,}  (expected 0)")

        ok = (
            count == EXPECTED_TOTAL
            and attack == EXPECTED_ATTACK
            and benign == EXPECTED_BENIGN
            and nulls == 0
        )
        print(f"    [{'PASS' if ok else 'FAIL'}] Parquet dataset")
        passed &= ok
    except Exception as e:
        print(f"    [FAIL] Could not read Parquet: {e}")
        passed = False

    # ── 2. MapReduce output ──────────────────────────────────────
    print("\n[2] Validating /threvia/output/attack_frequency (CSV) ...")
    try:
        agg = (
            spark.read.option("header", True)
            .option("sep", "\t")
            .csv(HDFS_MREDUCE)
        )
        agg = agg.withColumn("total", F.col("total").cast("long"))
        combos = agg.count()
        agg_total = agg.agg(F.sum("total")).first()[0]

        print(f"    (file, label) combos : {combos}  (expected 22)")
        print(f"    Summed total         : {agg_total:,}  (expected {EXPECTED_TOTAL:,})")

        ok = combos == 22 and agg_total == EXPECTED_TOTAL
        print(f"    [{'PASS' if ok else 'FAIL'}] MapReduce output")
        passed &= ok
    except Exception as e:
        print(f"    [FAIL] Could not read MapReduce output: {e}")
        passed = False

    # ── 3. HDFS listing of both output trees ─────────────────────
    print("\n[3] HDFS directory listing:")
    for path in ("hdfs://namenode:8020/threvia/processed", "hdfs://namenode:8020/threvia/output"):
        print(f"\n  {path}:")
        listing = hdfs_ls(spark, path).strip()
        print("    " + (listing.replace("\n", "\n    ") if listing else "(empty)"))

    print("\n" + "=" * 70)
    print("PHASE 2 VALIDATION: " + ("PASSED ✅" if passed else "FAILED ❌"))
    print("=" * 70)

    spark.stop()
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
