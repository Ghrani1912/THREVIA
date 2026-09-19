"""
audit_corpus_leakage.py — Step 0b: is the "cross-source" holdout actually clean?
==============================================================================
audit_corpus_sources.py showed the corpus is ~87% one source (LycoS) and that
the deployed model transfers to IDS2025 for PortScan (100%) — the one attack
class trained on CIC-2017 — but collapses on the classes trained only on LycoS
(DoS/DDoS 32.6%, Brute Force 36.0%).

That pattern fits the LycoS-dominance hypothesis, but it also fits a much less
interesting explanation: IDS2025 might BE CIC-2017 data, in which case PortScan's
100% is train/test leakage rather than transfer, and the "cross-source" claim is
void.

This script settles it:

  1. The largest duplicate groups in corpus/train — up to 132,723 rows share one
     identical feature vector.  What are they, and which labels conflict?

  2. Whether IDS2025 rows appear in corpus/train.  Both sides go through the same
     clean-up + log1p path and are then fingerprinted on a subset of columns
     whose CICFlowMeter definitions agree across CIC-2017 / CICIDS2018 / LycoS
     (schema_maps.py), so a fingerprint match means the same physical flow.
     A subset can only over-report a match, so a low overlap is conservative.

Memory note: this container is capped at 7.6 GiB, so the corpus must never be
shuffled or cached.  The overlap check therefore broadcasts the small IDS2025
side and streams the corpus against it (broadcast hash join, no corpus shuffle).

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/audit_corpus_leakage.py"
  SKIP_DUP=1 ...   # skip stage 1 on re-runs
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

HDFS_ROOT  = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN = f'{HDFS_ROOT}/corpus/train'
MODELS     = f'{HDFS_ROOT}/models_clean'
IDS25      = f'{HDFS_ROOT}/validation/ids2025_validation.csv'

LABEL_COL = 'Label'
FEAT_COL  = 'scaled_features'

FP_COLS = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Header Length',
    'Bwd Header Length',
    'SYN Flag Count',
    'ACK Flag Count',
    'Min Packet Length',
    'Max Packet Length',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
]


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-AuditLeakage')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def fp_expr(cols):
    return F.md5(F.concat_ws('|', *[
        F.coalesce(F.round(F.col(c).cast('double'), 4).cast('string'), F.lit('~'))
        for c in cols
    ]))


def stage_duplicates(train):
    sep('1. LARGEST DUPLICATE GROUPS in corpus/train (78-feature hash)')
    h78 = F.hash(*[F.col(c) for c in train.columns if c not in
                   ('Label', 'is_attack', 'raw_features', 'scaled_features')])

    per_label = train.withColumn('_h', h78).groupBy('_h', LABEL_COL).count()
    top = (
        per_label.groupBy('_h').agg(F.sum('count').alias('tot'))
        .orderBy(F.desc('tot')).limit(10).collect()
    )
    top_hashes = [r['_h'] for r in top]
    detail = (
        per_label.filter(F.col('_h').isin(top_hashes))
        .groupBy('_h').agg(F.collect_list(F.struct(LABEL_COL, 'count')).alias('mix'))
        .collect()
    )
    mix_by_hash = {r['_h']: r['mix'] for r in detail}
    for r in top:
        mix = mix_by_hash.get(r['_h'], [])
        label_mix = ', '.join(f'{m[LABEL_COL]}={m["count"]:,}'
                              for m in sorted(mix, key=lambda x: -x['count']))
        print(f'\n  multiplicity {int(r["tot"]):,}   [{label_mix}]')

    sample = (
        train.withColumn('_h', h78).filter(F.col('_h').isin(top_hashes[:3]))
        .groupBy('_h').agg(
            F.first('Destination Port').alias('dport'),
            F.first('Flow Duration').alias('dur'),
            F.first('Flow Packets/s').alias('pps'),
            F.first('Total Fwd Packets').alias('fwd'),
            F.first('SYN Flag Count').alias('syn'),
            F.first(LABEL_COL).alias('lbl'),
        ).collect()
    )
    print('\n  Sample of the biggest groups:')
    for s in sample:
        print(f'    DstPort={s["dport"]}, FlowDur={s["dur"]:.4f}, '
              f'Pkts/s={s["pps"]:.4f}, FwdPkts={s["fwd"]:.0f}, '
              f'SYN={s["syn"]:.0f}, label={s["lbl"]}')


# The CIC-2017-derived splits that the corpus is built from.  Together they are
# ~600K rows, small enough to broadcast; the full 15.7M-row corpus is not, and a
# broadcast hash join against it would materialise up to 11.6M BENIGN matches.
CIC17_DERIVED = [
    (f'{HDFS_ROOT}/portscan_clean_raw/portscan_train', 'csv', 'PortScan train (in corpus)'),
    (f'{HDFS_ROOT}/portscan_clean_raw/portscan_test', 'csv', 'PortScan test (held out)'),
    (f'{HDFS_ROOT}/corpus/friday_ddos_train', 'parquet', 'Friday DDoS train (in corpus)'),
    (f'{HDFS_ROOT}/corpus/friday_bot_train', 'parquet', 'Friday Bot train (in corpus)'),
    # The CIC-2017 Monday-Thursday attack rows added by build_corpus_v3.py.  If
    # IDS2025 overlaps THESE, then the v3 gain on IDS2025's DoS/DDoS and Brute
    # Force labels is leakage from the newly merged data, not generalisation.
    (f'{HDFS_ROOT}/corpus/cic17_extra', 'parquet', 'cic17_extra (v3 additions)'),
]


def stage_overlap(spark, train):
    sep('2. IDS2025 vs the CIC-2017 splits the corpus was built from')
    print('  Decisive question: IDS2025 detects PortScan at 100% with mean')
    print('  P(attack)=0.996, and PortScan is the ONE attack class in the corpus')
    print('  whose training rows come from CIC-2017 (not LycoS).  If IDS2025 shares')
    print('  fingerprints with those rows, IDS2025 is CIC-2017-derived and its')
    print('  numbers are leakage, not cross-source generalisation.')

    from backend.processing.schema_maps import CANONICAL_FEATURE_COLS, LABEL_NORMALISE
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.ml import PipelineModel
    from pyspark.sql.types import StringType

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    pipe = PipelineModel.load(f'{MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}

    ids_raw = spark.read.option('header', True).option('inferSchema', False).csv(IDS25)
    ids = clean_and_scale_external(spark, ids_raw, feat_cols, pipe, label_udf,
                                   fill_map=medians)
    ids_fp = (ids.select(*FP_COLS, LABEL_COL)
                 .withColumn('_fp', fp_expr(FP_COLS))
                 .select('_fp', LABEL_COL))
    n_ids = ids_fp.count()
    print(f'\n  IDS2025 rows: {n_ids:,}')

    union = None
    for path, kind, _name in CIC17_DERIVED:
        if kind == 'csv':
            d = spark.read.option('header', True).option('inferSchema', False).csv(path)
        else:
            d = spark.read.parquet(path)
        # Some splits are stored already cleaned + scaled.  Re-running the
        # pipeline on them would apply log1p a second time, so pass them through.
        if FEAT_COL not in d.columns:
            d = clean_and_scale_external(spark, d, feat_cols, pipe, label_udf,
                                         fill_map=medians)
        d = d.select(*FP_COLS, LABEL_COL).withColumn('_fp', fp_expr(FP_COLS)) \
             .select('_fp', LABEL_COL)
        union = d if union is None else union.unionByName(d)

    n_union = union.count()
    print(f'  union of CIC-2017-derived splits: {n_union:,} rows')

    matched = ids_fp.join(F.broadcast(union), on='_fp', how='left_semi')
    hits = matched.distinct().cache()
    n_hit = hits.count()
    print(f'  IDS2025 rows whose fingerprint occurs in those splits: {n_hit:,}')

    print('\n  Matched IDS2025 rows by label (vs full IDS2025 distribution):')
    hit_counts = {r[LABEL_COL]: r['count'] for r in
                  hits.groupBy(LABEL_COL).count().collect()}
    for r in ids_fp.groupBy(LABEL_COL).count().orderBy(F.desc('count')).collect():
        n = int(r['count'])
        h = int(hit_counts.get(r[LABEL_COL], 0))
        print(f'    {r[LABEL_COL]:<28}{n:>10,} rows{h:>10,} matched'
              f'{h / n * 100:>8.1f}%')
    hits.unpersist()


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('ERROR')

    train = spark.read.parquet(HDFS_TRAIN)

    if os.getenv('SKIP_DUP') != '1':
        stage_duplicates(train)
    stage_overlap(spark, train)

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
