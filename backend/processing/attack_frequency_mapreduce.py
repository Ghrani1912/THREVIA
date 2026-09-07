"""
Phase 2 — MapReduce-Style Attack Frequency Aggregation
Counts Label frequency per day-file (simulating a Hadoop MapReduce
word-count-style aggregation over the raw CSVs in /threvia/raw).

Reads raw CSVs directly (map phase = parse + emit (file, label, 1)),
then reduces by summing counts. Results go to /threvia/output as
tab-separated text, plus a readable console report.

Usage:
  docker exec threvia-spark-master spark-submit \
      --master spark://spark-master:7077 \
      /workspace/backend/processing/attack_frequency_mapreduce.py
"""

import sys

from pyspark.sql import SparkSession, functions as F

HDFS_RAW = "hdfs://namenode:8020/threvia/raw"
HDFS_OUTPUT = "hdfs://namenode:8020/threvia/output/attack_frequency"


def get_spark():
    return (
        SparkSession.builder.appName("Threvia-Phase2-MapReduce-AttackFreq")
        .config("spark.sql.shuffle.partitions", "8")
        .getOrCreate()
    )


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel("WARN")

    print("=" * 70)
    print("THREVIA Phase 2 — MapReduce Attack Frequency Aggregation")
    print("=" * 70)

    # ── MAP PHASE ────────────────────────────────────────────────
    # input_file_name() gives the source CSV path per record, which
    # stands in for the classic MapReduce (file, key) pairing.
    print(f"\n[MAP] Reading raw CSVs from {HDFS_RAW} ...")
    df = (
        spark.read.option("header", True)
        .option("inferSchema", True)
        .csv(HDFS_RAW)
    )
    print(f"    Parsed {df.count():,} rows across all files")

    mapped = (
        df.select(
            F.regexp_extract(F.input_file_name(), r"([^/]+)$", 1).alias("source_file"),
            F.trim(F.col(" Label")).alias("label"),
        )
        .withColumn("count", F.lit(1))
    )

    # ── REDUCE PHASE ─────────────────────────────────────────────
    print("\n[REDUCE] Aggregating (source_file, label) -> total count ...")
    reduced = (
        mapped.groupBy("source_file", "label")
        .sum("count")
        .withColumnRenamed("sum(count)", "total")
        .orderBy("source_file", F.desc("total"))
    )

    # ── WRITE OUTPUT ─────────────────────────────────────────────
    print(f"\n[OUTPUT] Writing results to {HDFS_OUTPUT} ...")
    (
        reduced.coalesce(1)
        .write.mode("overwrite")
        .option("header", True)
        .option("sep", "\t")
        .csv(HDFS_OUTPUT)
    )

    # ── CONSOLE REPORT ───────────────────────────────────────────
    rows = reduced.collect()
    grand_total = sum(r["total"] for r in rows)

    print("\nAttack frequency by file:")
    print(f"  {'source_file':<55} {'label':<25} {'count':>10}")
    print("  " + "-" * 93)
    for r in rows:
        print(f"  {r['source_file']:<55} {r['label']:<25} {r['total']:>10,}")
    print("  " + "-" * 93)
    print(f"  {'GRAND TOTAL':<81} {grand_total:>10,}")

    print("\n" + "=" * 70)
    print(f"PHASE 2 MAPREDUCE COMPLETE — {len(rows)} (file, label) combos")
    print(f"Written to {HDFS_OUTPUT}")
    print("=" * 70)

    spark.stop()


if __name__ == "__main__":
    sys.exit(main())
