"""
audit_corpus_sources.py — Step 0 audit: is the training data itself the problem?
==============================================================================
The v1-vs-v2 comparison (compare_model_versions.py) established that correcting
the class weights did not improve discrimination at matched FPR.  That rules
imbalance OUT as the lever.  This script tests the remaining step-1 hypothesis:
the merged corpus is dominated by ONE capture source, so the decision boundary
is tuned to that environment and does not transfer.

It measures, with no retraining:

  1. DUPLICATES      — how much of the corpus is repeated flows.  Duplicated
                       training rows inflate in-sample scores and pull tree
                       splits toward whatever the duplicated flow looks like.
                       PortScan and CICIDS2018 were deduped at source; LycoS
                       (87% of the corpus) was never checked.

  2. SOURCE MIX      — LycoS is the only source missing 5 canonical columns
                       (LYCOS_MISSING_FROM_LYCOS), so after median imputation
                       those 5 features sit at an exact constant for every
                       LycoS row.  Counting rows per-label that equal that
                       constant gives a lower bound on LycoS's share of each
                       class — i.e. it shows which classes are single-source.

  3. CROSS-SOURCE    — scores the deployed v1 binary model on IDS2025 and
                       breaks recall down BY IDS2025 LABEL, so we can see
                       whether the misses are a model defect or simply attack
                       families the corpus never contained.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 4g \
    /workspace/backend/ml/audit_corpus_sources.py"
"""

import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

HDFS_ROOT   = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN  = f'{HDFS_ROOT}/corpus/train'
MODELS      = f'{HDFS_ROOT}/models_clean'
IDS25       = f'{HDFS_ROOT}/validation/ids2025_validation.csv'

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
BINARY_COL = 'is_attack'

# The 5 canonical columns LycoS does not have (schema_maps.LYCOS_MISSING_FROM_LYCOS).
# LycoS rows arrive as NULL and get median-imputed, so their value is a single
# constant per column.  Any row sitting exactly on that constant is *probably*
# LycoS; rows with a different value are definitely NOT LycoS.  So
# (rows off the constant) / (rows) is an upper bound for the non-LycoS share.
LYCOS_PROXY_COLS = [
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'act_data_pkt_fwd',
    'min_seg_size_forward',
]

# The deployed cut used by detection_policy.py.
DEPLOYED_T = 0.65


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-AuditCorpusSources')
        .config('spark.sql.shuffle.partitions', '32')
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

    from backend.processing.schema_maps import CANONICAL_FEATURE_COLS, LABEL_NORMALISE
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.ml import PipelineModel
    from pyspark.ml.classification import RandomForestClassificationModel
    from pyspark.sql.types import StringType

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    train = spark.read.parquet(HDFS_TRAIN)

    # ── 1. duplicates ────────────────────────────────────────────────────────
    sep('1. DUPLICATE ROWS (hash of the 78 canonical feature values)')
    hashed = train.withColumn('_h', F.hash(*[F.col(c) for c in feat_cols]))
    grp = hashed.groupBy('_h').count().cache()
    n_distinct = grp.count()
    agg = grp.agg(
        F.sum('count').alias('rows'),
        F.max('count').alias('max_mult'),
        F.sum(F.when(F.col('count') > 1, F.col('count')).otherwise(0)).alias('rows_in_dups'),
    ).first()
    n_rows = int(agg['rows'])
    dup_rows = int(agg['rows_in_dups'] or 0)
    print(f'  total rows          : {n_rows:,}')
    print(f'  distinct feature vec: {n_distinct:,}')
    print(f'  rows in dup groups  : {dup_rows:,}  ({dup_rows / n_rows * 100:.1f}%)')
    print(f'  largest multiplicity: {int(agg["max_mult"]):,}')
    print(f'  exact-dup excess    : {n_rows - n_distinct:,}  '
          f'({(n_rows - n_distinct) / n_rows * 100:.1f}% removable)')

    # ── 2. source mix via the LycoS-only null-fill constant ──────────────────
    sep('2. SOURCE MIX (LycoS proxy: rows sitting on the imputed median)')
    med_row = spark.read.parquet(f'{MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}
    proxy = None
    for c in LYCOS_PROXY_COLS:
        if c not in medians:
            continue
        cond = F.col(c).isNull() | (F.abs(F.col(c) - F.lit(float(medians[c]))) < 1e-9)
        proxy = cond if proxy is None else (proxy & cond)
    if proxy is None:
        print('  no imputer medians available — skipping')
    else:
        shaped = train.withColumn('_lycos_proxy', F.when(proxy, F.lit(1)).otherwise(F.lit(0)))
        tbl = (
            shaped.groupBy(LABEL_COL)
            .agg(F.count('*').alias('rows'),
                 F.sum(F.when(F.col('_lycos_proxy') == 0, 1).otherwise(0)).alias('not_lycos'))
            .withColumn('sources_other', F.col('not_lycos'))
            .orderBy(F.desc('rows'))
        )
        print(f'  {"label":<28}{"rows":>12}{"NOT-LycoS":>12}{"LycoS share":>13}')
        for r in tbl.collect():
            rows = int(r['rows'])
            other = int(r['not_lycos'] or 0)
            share = (rows - other) / rows * 100 if rows else 0.0
            print(f'  {r[LABEL_COL]:<28}{rows:>12,}{other:>12,}{share:>12.1f}%')

    # ── 3. cross-source recall by label ──────────────────────────────────────
    sep('3. CROSS-SOURCE: deployed v1 binary model on IDS2025, by label')
    pipe = PipelineModel.load(f'{MODELS}/scaler_pipeline')
    rf = RandomForestClassificationModel.load(f'{MODELS}/rf_binary')
    from pyspark.ml.functions import vector_to_array

    ids_raw = (spark.read.option('header', True).option('inferSchema', False).csv(IDS25))
    ids = clean_and_scale_external(spark, ids_raw, feat_cols, pipe, label_udf, fill_map=medians)
    ids = rf.transform(ids).withColumn('p_attack', vector_to_array(F.col('probability'))[1])
    ids.cache()
    n_ids = ids.count()
    print(f'  IDS2025 rows: {n_ids:,}')
    print('\n  Raw IDS2025 label distribution (post-normalisation):')
    ids.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(30, truncate=False)

    print(f'  Detection rate at deployed T={DEPLOYED_T} (is_attack=1) BY LABEL:')
    by_label = (
        ids.groupBy(LABEL_COL)
        .agg(F.count('*').alias('n'),
             F.sum(F.when(F.col('p_attack') >= DEPLOYED_T, 1).otherwise(0)).alias('flagged'),
             F.avg('p_attack').alias('mean_p'))
        .orderBy(F.desc('n'))
    )
    print(f'  {"IDS2025 label":<28}{"n":>10}{"flagged":>10}{"rate":>9}{"mean P":>9}')
    for r in by_label.collect():
        n = int(r['n'])
        fl = int(r['flagged'] or 0)
        print(f'  {r[LABEL_COL]:<28}{n:>10,}{fl:>10,}{fl / n * 100:>8.1f}%{float(r["mean_p"]):>9.3f}')

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
