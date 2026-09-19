"""
build_infiltration_split.py — Step 5: a real held-out test for Infiltration
===========================================================================
Every previous Infiltration number in this project was measured on statistically
meaningless support: 20/29 rows (IDS2025) or 28/36 rows (CIC-2017 Thursday).
This script carves the FIRST defensible held-out split out of the 161,934
CICIDS2018 Infiltration rows already in the training corpus.

Why temporal, not random
------------------------
The raw CSVs carry no source-IP column (80 columns; only Dst Port + Timestamp
identify a flow's origin), so session/host grouping is impossible.  What the
Timestamps DO give is a stricter guarantee than a row split: the split boundary
is a point in time, so every test row is guaranteed to have been captured after
every training row.  Note the discipline this enforces on the existing splits
too: ``split_friday_sessions.py`` documented that its port-bucket attempt was
degenerate and fell back to a row-level ``randomSplit`` — the same weakness this
split avoids.

Leak guard
----------
CICIDS2018 Infiltration capture windows are highly repetitive; identical or
near-identical flow rows can appear on both sides of any split.  Before
evaluating, both sides are deduplicated on a hash of all canonical feature
values, and any hash present in the training side is removed from the test
side.  The script reports exactly how many rows this removed, so the leak rate
is visible rather than assumed away.

Outputs (HDFS)
--------------
  /threvia/corpus/infiltration_train   (temporal early side, deduped)
  /threvia/corpus/infiltration_test    (temporal late side, deduped,
                                        de-leaked vs train hashes)

Both sides keep the canonical feature columns + Label + is_attack, i.e. the
same shape ``train_clean_corpus.py`` consumes.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/build_infiltration_split.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

HDFS_ROOT      = 'hdfs://namenode:8020/threvia'
HDFS_CIC18     = f'{HDFS_ROOT}/cic18_raw'
HDFS_TRAIN_OUT = f'{HDFS_ROOT}/corpus/infiltration_train'
HDFS_TEST_OUT  = f'{HDFS_ROOT}/corpus/infiltration_test'

from backend.processing.schema_maps import CIC18_RENAME, CIC18_EXTRA_DROP, CANONICAL_FEATURE_COLS

FEAT_COLS = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
LABEL_COL = 'Label'


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-BuildInfiltrationSplit')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('ERROR')

    from backend.processing.merge_corpus import clean_features, select_canonical
    from backend.processing.schema_maps import LABEL_NORMALISE
    from pyspark.sql.types import StringType

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )

    sep('1. Loading CICIDS2018 raw (Thursday + Wednesday)')
    df = spark.read.option('header', True).option('inferSchema', False).csv(HDFS_CIC18)
    print(f'  Raw rows (all labels): {df.count():,}')

    # Capture Timestamp BEFORE CIC18_EXTRA_DROP removes it -- it is the split key.
    if 'Timestamp' in df.columns:
        df = df.withColumnRenamed('Timestamp', '_ts_raw')
    elif '_ts_raw' not in df.columns:
        print('  ERROR: Timestamp column not found in raw CSV; cannot build a temporal split.')
        return 2

    for c in CIC18_EXTRA_DROP:
        if c in df.columns:
            df = df.drop(c)
    for src, tgt in CIC18_RENAME.items():
        if src in df.columns:
            df = df.withColumnRenamed(src, tgt)

    df = df.withColumn(LABEL_COL, label_udf(F.col(LABEL_COL)))
    df = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'INFILTRATION')
    print(f'  Infiltration rows: {df.count():,}')

    # Parse the timestamp.  CICIDS2018 format: dd/mm/yyyy HH:MM:SS.
    # Known artifact: the raw CSVs contain header-contamination rows (the
    # literal text 'Timestamp' repeated as data, see merge_corpus.py), so use
    # try_to_timestamp and drop unparseable rows.
    ts = F.try_to_timestamp(F.col('_ts_raw'), F.lit('dd/M/yyyy H:mm:ss').cast('string'))
    df = df.withColumn('_ts', ts)
    n_bad_ts = df.filter(F.col('_ts').isNull()).count()
    print(f'  Rows with unparseable Timestamp (header contamination): {n_bad_ts:,}')
    df = df.filter(F.col('_ts').isNotNull())

    tmin, tmax = df.select(F.min('_ts'), F.max('_ts')).first()
    print(f'  Time range: {tmin}  ->  {tmax}')

    sep('2. Temporal split at the median timestamp')
    # approxQuantile refuses TimestampType, so take the quantile over epoch
    # seconds and convert back.  percent_rank over a global window would work
    # but pulls the entire frame through a single partition.
    from pyspark.sql.functions import unix_timestamp, to_timestamp
    df = df.withColumn('_epoch', unix_timestamp('_ts'))
    median_epoch = df.approxQuantile('_epoch', [0.5], 0.001)[0]
    boundary = F.to_timestamp(F.lit(median_epoch).cast('int'))
    print(f'  Boundary: {boundary} (median of {df.count():,} timestamps)')

    train_side = df.filter(F.col('_ts') <= boundary)
    test_side  = df.filter(F.col('_ts') > boundary)
    print(f'  Train side (early): {train_side.count():,}')
    print(f'  Test side  (late) : {test_side.count():,}')

    # Day-of-source annotation: Wednesday rows are one capture day, Thursday
    # another.  If the boundary lands inside one day, the split is within-day
    # temporal; if the days separate cleanly, report that too.
    day_stats = df.groupBy(F.to_date('_ts').alias('_day')).count().orderBy('_day')
    print('  Rows per capture day:')
    day_stats.show(10, False)

    sep('3. Clean to canonical shape')
    # _ts/_epoch are split bookkeeping only -- strip them before the canonical
    # selection so they can never become features.
    train_c = select_canonical(clean_features(
        train_side.drop('_ts', '_epoch'), FEAT_COLS, label_udf), FEAT_COLS)
    test_c = select_canonical(clean_features(
        test_side.drop('_ts', '_epoch'), FEAT_COLS, label_udf), FEAT_COLS)

    sep('4. Dedup + de-leak on the canonical feature hash')
    def with_hash(d):
        return d.withColumn('_fhash', F.hash(*[F.col(c) for c in FEAT_COLS]))

    train_h = with_hash(train_c).cache()
    test_h  = with_hash(test_c).cache()

    n_train_raw = train_h.count()
    n_test_raw  = test_h.count()
    train_u = train_h.dropDuplicates(['_fhash'])
    n_train_dedup = train_u.count()

    train_hashes = train_u.select('_fhash')
    test_dedup = test_h.dropDuplicates(['_fhash'])
    n_test_dedup = test_dedup.count()
    test_leaked = test_dedup.join(train_hashes, on='_fhash', how='left_semi').count()
    test_clean  = test_dedup.join(train_hashes, on='_fhash', how='left_anti')
    n_test_clean = test_clean.count()

    print(f'  Train rows raw / deduped : {n_train_raw:,} / {n_train_dedup:,}')
    print(f'  Test rows raw / deduped  : {n_test_raw:,} / {n_test_dedup:,}')
    print(f'  Test rows sharing a hash with train (leak removed): {test_leaked:,}')
    print(f'  FINAL test rows          : {n_test_clean:,}  '
          f'({n_test_clean / n_test_raw * 100:.1f}% of raw survived)')

    sep('5. Writing split parquets')
    train_out = train_u.drop('_ts', '_pr', '_fhash').withColumn('is_attack', F.lit(1))
    test_out  = test_clean.drop('_ts', '_pr', '_fhash').withColumn('is_attack', F.lit(1))
    train_out.write.mode('overwrite').option('compression', 'snappy').parquet(HDFS_TRAIN_OUT)
    test_out.write.mode('overwrite').option('compression', 'snappy').parquet(HDFS_TEST_OUT)
    print(f'  {HDFS_TRAIN_OUT}: {train_out.count():,}')
    print(f'  {HDFS_TEST_OUT}: {test_out.count():,}')

    sep('DONE')
    print(f"""
  Final held-out test set: {n_test_clean:,} Infiltration rows.
  Compare with the 29- and 36-row sets every previous claim rested on.

  Next: score these rows with evaluate_infiltration_split.py.
""")
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
