"""
build_corpus_v3.py — Step 1 fix: repair the DATA SELECTION, then re-measure
==========================================================================
The audits (audit_corpus_sources.py, audit_corpus_leakage.py) found that the
merged corpus, not the model, is what caps cross-source recall:

  1. SOURCE MONOPOLY.  87% of the corpus is LycoS, and seven of the fourteen
     classes (DoS Hulk, FTP-Patator, SSH-Patator, DoS slowloris, DoS GoldenEye,
     DoS Slowhttptest, all three Web Attacks) come from LycoS and ONLY LycoS.
     On the IDS2025 probe the deployed model scores 32.6% on DoS/DDoS and 36.0%
     on Brute Force — precisely those single-source classes — while PortScan,
     the one attack class trained on CIC-2017, scores 100%.

  2. THE OBVIOUS TRAINING DATA WAS NEVER MERGED.  CIC-2017's Tuesday (FTP/SSH
     Patator), Wednesday (all four DoS variants) and Thursday (Web Attacks,
     Infiltration) captures are sitting in backend/data/CIC-IDS- 2017 and were
     never added — yet those are exactly the attack families the corpus knows
     only from LycoS.  Adding them gives a SECOND source to seven classes.
     The Friday files are deliberately excluded: the C1 holdout
     (friday_ddos_test / friday_bot_test) and the port-grouped PortScan holdout
     are split out of them, so adding them would leak the holdouts.

  3. UNUSED-INCOMPATIBLE DATA.  backend/data also holds CTU-13 (``botnet``:
     Argus binetflow, 11 columns) and UNSW-NB15 (Bro/Argus, 49 features incl.
     categoricals).  Neither shares the 78-feature CICFlowMeter schema, so they
     cannot be merged into this model at all — they would need a second feature
     pipeline and a second model.  That is a real answer to "should I have used
     other datasets": for two of the three, no, not with this feature space.

  4. CIC-DDoS2019 (``new_dos``) DOES match the schema almost one-to-one, so it
     is usable — but its parquet exports have no Destination Port, so every row
     would take the same imputed median port.  Training on that would teach a
     spurious "median port" source signature, which is the same class of defect
     this script exists to remove.  It is therefore used only as a clean
     cross-environment HOLDOUT.

Outputs
-------
  /threvia/corpus/cic17_extra        the unused CIC-2017 attack rows, cleaned and
                                     scaled on the training scaler (~270K rows)
  /threvia/corpus/ddos2019_test      CIC-DDoS2019's own testing split, cleaned and
                                     scaled (~306K rows) — a genuinely clean
                                     cross-environment probe (different year,
                                     different tooling, never in training)

  With REBUILD_CORPUS=1 it additionally writes /threvia/corpus/train_v3, a
  de-noised copy of the corpus with conflicting-label duplicates dropped and
  DoS Hulk down-sampled.  That path reshuffles all 15.7M wide rows and needs more
  heap than this 7.6 GiB container gives a Spark driver (it gets OOM-killed), so
  it is opt-in.  The measured size of that defect is reported either way.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/build_corpus_v3.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

HDFS_ROOT        = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN       = f'{HDFS_ROOT}/corpus/train'
HDFS_EXTRA_OUT   = f'{HDFS_ROOT}/corpus/cic17_extra'
HDFS_DDOS19_TEST = f'{HDFS_ROOT}/corpus/ddos2019_test'
HDFS_V3_OUT      = os.getenv('CORPUS_OUT', f'{HDFS_ROOT}/corpus/train_v3')
MODELS           = f'{HDFS_ROOT}/models_clean'

# Local mount of the project root inside the Spark container.
DATA_DIR  = '/workspace/backend/data'
CIC17_DIR = f'{DATA_DIR}/CIC-IDS- 2017'
DDOS19_DIR = f'{DATA_DIR}/new_dos'

# Monday-Thursday only.  The Friday files feed the C1 and PortScan holdouts.
CIC17_ATTACK_FILES = [
    'Tuesday-WorkingHours.pcap_ISCX.csv',                          # FTP/SSH-Patator
    'Wednesday-workingHours.pcap_ISCX.csv',                        # 4 DoS variants
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',      # Web Attacks
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',  # Infiltration
]

# Attack labels only.  BENIGN from these files is already covered by
# benign_clean_raw/benign_train, and re-adding it would shift the BENIGN mean.
CIC17_KEEP = {
    'FTP-Patator', 'SSH-Patator',
    'DoS Hulk', 'DoS GoldenEye', 'DoS slowloris', 'DoS Slowhttptest',
    'Web Attack - Brute Force', 'Web Attack - XSS', 'Web Attack - Sql Injection',
    'Infiltration',
}

LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'
FEAT_COL   = 'scaled_features'


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-BuildCorpusV3')
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
    import glob as _glob

    from backend.processing.schema_maps import (
        CANONICAL_FEATURE_COLS, LABEL_NORMALISE, DDOS19_RENAME, DDOS19_EXTRA_DROP,
    )
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.ml import PipelineModel
    from pyspark.sql.types import StringType

    from backend.processing.schema_maps import label_lookup_key

    norm_map = {label_lookup_key(k): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: (bc.value.get(label_lookup_key(raw), raw.strip())
                     if raw else None),
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
    # NOTE: 'raw_features' is intentionally NOT carried here.  The training and
    # evaluation paths read only scaled_features, and persisting both dense
    # 78-wide vectors doubles the peak heap of the write — which is what was
    # getting this job OOM-killed.  train_clean_corpus.py prunes to
    # (scaled_features, Label, is_attack, attack_type_idx) anyway.
    OUT_COLS = feat_cols + [LABEL_COL, BINARY_COL, FEAT_COL]

    pipe = PipelineModel.load(f'{MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}

    def shape(df):
        return df.select(*OUT_COLS)

    # ── 1. the unused CIC-2017 attack days ───────────────────────────────────
    sep('1. Adding the unused CIC-2017 Monday-Thursday attack captures')
    extra_total = 0
    for i, fname in enumerate(CIC17_ATTACK_FILES):
        # LABEL ENCODING: these Web-Attack labels contain U+FFFD where an en-dash
        # used to be (an earlier spreadsheet round-trip destroyed it).  The label
        # UDF goes through schema_maps.label_lookup_key, which collapses the bad
        # character so the rows land on the ASCII 'Web Attack - ...' keys.  Without
        # that, all 2,180 CIC-2017 Web Attack rows were silently dropped.
        raw = (spark.read.option('header', True).option('inferSchema', False)
               .csv(os.path.join(CIC17_DIR, fname)))
        # Raw CIC-2017 headers carry leading spaces, and Spark's CSV reader has
        # already disambiguated the two duplicate 'Fwd Header Length' columns as
        # ...34 / ...55.  clean_and_scale_external() knows both names.
        for c in raw.columns:
            s = c.strip()
            if s != c:
                raw = raw.withColumnRenamed(c, s)
        scaled = clean_and_scale_external(spark, raw, feat_cols, pipe, label_udf,
                                          fill_map=medians)
        kept = shape(scaled.filter(F.col(LABEL_COL).isin(sorted(CIC17_KEEP))))
        n = kept.count()
        print(f'  {fname:<52} attack rows: {n:,}')
        if not n:
            continue
        # Write one file at a time (first overwrites, rest append) so only a
        # single capture is materialised at once instead of four CSVs' worth of
        # dense 78-wide vectors.
        mode = 'overwrite' if extra_total == 0 else 'append'
        kept.write.mode(mode).option('compression', 'snappy').parquet(HDFS_EXTRA_OUT)
        extra_total += n

    extra_n = spark.read.parquet(HDFS_EXTRA_OUT).count()
    print(f'\n  Written: {extra_n:,} rows -> {HDFS_EXTRA_OUT}')
    print('  Per-class rows added:')
    (spark.read.parquet(HDFS_EXTRA_OUT).groupBy(LABEL_COL).count()
     .orderBy(F.desc('count')).show(20, truncate=False))

    # ── 2. clean CIC-DDoS2019 cross-environment holdout ──────────────────────
    sep(f'2. Building {HDFS_DDOS19_TEST} (clean cross-environment holdout)')
    test_total = 0
    for path in sorted(_glob.glob(os.path.join(DDOS19_DIR, '*-testing.parquet'))):
        raw = spark.read.parquet(path)
        for c in DDOS19_EXTRA_DROP:
            if c in raw.columns:
                raw = raw.drop(c)
        for src, tgt in DDOS19_RENAME.items():
            if src in raw.columns:
                raw = raw.withColumnRenamed(src, tgt)
        scaled = shape(clean_and_scale_external(spark, raw, feat_cols, pipe,
                                                label_udf, fill_map=medians))
        labs = scaled.groupBy(LABEL_COL).count().collect()
        n = sum(r['count'] for r in labs)
        print(f'  {os.path.basename(path):<34}{n:>9,} rows  '
              + ', '.join(f'{r[LABEL_COL]}={r["count"]:,}' for r in labs))
        if not n:
            continue
        mode = 'overwrite' if test_total == 0 else 'append'
        scaled.write.mode(mode).option('compression', 'snappy').parquet(HDFS_DDOS19_TEST)
        test_total += n

    n_test = spark.read.parquet(HDFS_DDOS19_TEST).count()
    print(f'  Written: {n_test:,} rows -> {HDFS_DDOS19_TEST}')

    # ── 3. leak check: does the new holdout appear in the training corpus? ───
    if os.getenv('SKIP_LEAK') != '1':
        sep('3. Leak check: CIC-DDoS2019 holdout vs the training data')
        fp_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
                   'Flow Packets/s', 'Flow Bytes/s']

        def fp(df):
            return df.select(*fp_cols).withColumn(
                '_fp',
                F.md5(F.concat_ws('|', *[
                    F.coalesce(F.round(F.col(c).cast('double'), 4).cast('string'),
                               F.lit('~'))
                    for c in fp_cols]))).select('_fp')

        # IDs2025 is the contaminated probe (86.9% of its PortScan rows are
        # training flows), so it is included here as a POSITIVE CONTROL: an
        # overlap detector that cannot see that contamination is broken.
        ctrl = fp(clean_and_scale_external(
            spark,
            spark.read.option('header', True).option('inferSchema', False)
            .csv(f'{HDFS_ROOT}/validation/ids2025_validation.csv'),
            feat_cols, pipe, label_udf, fill_map=medians))
        # Broadcast the SMALL holdout side and stream the corpus against it.
        # Broadcasting the corpus itself fails outright: "Not enough memory to
        # build and broadcast the table".
        tst = fp(spark.read.parquet(HDFS_DDOS19_TEST)).distinct().cache()
        trn = fp(spark.read.parquet(HDFS_TRAIN)).cache()
        print(f'  distinct holdout fingerprints : {tst.count():,}')
        print(f'  also present in corpus/train  : '
              f'{trn.join(F.broadcast(tst), on="_fp", how="left_semi").count():,}'
              f'   (expected ~0)')
        print(f'  IDS2025 fingerprints in train : '
              f'{trn.join(F.broadcast(ctrl.distinct()), on="_fp", how="left_semi").count():,}'
              f'   (positive control, expected > 0)')
        tst.unpersist(); trn.unpersist()

    # ── 4. optional: full de-noised corpus rewrite ───────────────────────────
    if os.getenv('REBUILD_CORPUS') == '1':
        sep('4. REBUILD_CORPUS=1 — de-noised corpus/train_v3')
        print('  Dropping every row in a feature-hash group with conflicting labels')
        print('  and down-sampling DoS Hulk.  This reshuffles the full 15.7M-row')
        print('  corpus; if the driver is killed, raise the container memory cap.')
        train = spark.read.parquet(HDFS_TRAIN)
        h = F.hash(*[F.col(c) for c in feat_cols])
        n_train = train.count()
        conflicts = (
            train.select(h.alias('_h'), F.col(LABEL_COL))
            .groupBy('_h').agg(F.min(LABEL_COL).alias('_lo'),
                               F.max(LABEL_COL).alias('_hi'))
            .filter(F.col('_lo') != F.col('_hi')).select('_h').cache())
        print(f'  conflicting groups: {conflicts.count():,}')
        cap = int(os.getenv('DOS_HULK_CAP', '250000'))
        base = train.withColumn('_h', h).join(
            F.broadcast(conflicts), on='_h', how='left_anti')
        if cap:
            n_hulk = base.filter(F.col(LABEL_COL) == 'DoS Hulk').count()
            if n_hulk > cap:
                print(f'  DoS Hulk {n_hulk:,} -> ~{cap:,}')
                base = base.filter((F.col(LABEL_COL) != 'DoS Hulk')
                                   | (F.rand(42) < F.lit(cap / n_hulk)))
        merged = base.unionByName(spark.read.parquet(HDFS_EXTRA_OUT),
                                 allowMissingColumns=True).select(*OUT_COLS)
        (merged.write.mode('overwrite').option('compression', 'snappy')
         .parquet(HDFS_V3_OUT))
        print(f'  Written {spark.read.parquet(HDFS_V3_OUT).count():,} rows '
              f'(was {n_train:,}) -> {HDFS_V3_OUT}')
    else:
        sep('4. Corpus rewrite skipped (set REBUILD_CORPUS=1 to enable)')

    sep('DONE')
    print(f"""
  cic17_extra   : {extra_n:,} rows -> {HDFS_EXTRA_OUT}
  ddos2019_test : {n_test:,} rows  -> {HDFS_DDOS19_TEST}

  Next — retrain on corpus/train UNION cic17_extra and compare at matched FPR:

    docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \\
      CORPUS_TRAIN=hdfs://namenode:8020/threvia/corpus/train \\
      EXTRA_CORPUS=hdfs://namenode:8020/threvia/corpus/cic17_extra \\
      MODELS_OUT=hdfs://namenode:8020/threvia/models_clean_v3 \\
      METRICS_OUT=/workspace/backend/ml/model_metrics_v3.json \\
      /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \\
      /workspace/backend/ml/train_clean_corpus.py"

    docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \\
      /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \\
      /workspace/backend/ml/compare_at_matched_fpr.py"
""")
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
