"""
Phase 3 — Retrain on Clean Corpus
===================================
Trains RF (binary + multi-class) on the unified clean corpus at
/threvia/corpus/train and evaluates on three held-out test sets:

  TEST-A  IDS2025 validation  (/threvia/validation/ids2025_validation.csv)
          — cross-source generalisation check
  TEST-B  PortScan held-out   (/threvia/corpus/portscan_test)
          — port-grouped, zero-leakage PortScan test
  TEST-C  CIC-2017 Friday     (/threvia/raw — Friday files only)
          — temporal generalisation (unseen DDoS/PortScan/Bot from original data)

The corpus already has scaled_features from merge_corpus.py.
For IDS2025 and Friday we apply the SAME pipeline saved during merge.

Prints a side-by-side comparison vs the old CIC-2017 random-split baseline.

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      --driver-memory 3g --executor-memory 3g \\
      /workspace/backend/ml/train_clean_corpus.py
"""

import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import StringIndexer, VectorAssembler, StandardScaler
from pyspark.ml import Pipeline

from backend.processing.schema_maps import (
    CANONICAL_FEATURE_COLS,
    IDS25_RENAME, IDS25_EXTRA_DROP,
    normalise_label,
)

# ── HDFS paths ────────────────────────────────────────────────────────────────
HDFS_TRAIN      = 'hdfs://namenode:8020/threvia/corpus/train'
HDFS_PS_TEST    = 'hdfs://namenode:8020/threvia/corpus/portscan_test'
HDFS_VALIDATION = 'hdfs://namenode:8020/threvia/validation/ids2025_validation.csv'
HDFS_RAW        = 'hdfs://namenode:8020/threvia/raw'
HDFS_MODELS_NEW = 'hdfs://namenode:8020/threvia/models_clean'

FEAT_COL    = 'scaled_features'
LABEL_COL   = 'Label'
BINARY_COL  = 'is_attack'
MULTI_COL   = 'attack_type_idx'

FRIDAY_FILES = {
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
}

# ── Baseline numbers from old CIC-2017 random-split evaluation ────────────────
BASELINE = {
    'RF_binary':     dict(acc=0.9958, f1=0.9958, auc=0.9996),
    'RF_multiclass': dict(acc=0.9962, f1=0.9955, auc=None),
}


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-CleanCorpusTrain')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.driver.memory', '3g')
        .config('spark.executor.memory', '3g')
        .config('spark.executor.instances', '1')
        .config('spark.executor.cores', '2')
        .config('spark.network.timeout', '800s')
        .config('spark.serializer', 'org.apache.spark.serializer.KryoSerializer')
        .config('spark.memory.fraction', '0.6')
        .getOrCreate()
    )


def sep(title=''):
    print('\n' + '=' * 72)
    if title:
        print(f'  {title}')
        print('=' * 72)


def bin_metrics(preds):
    be = BinaryClassificationEvaluator(
        labelCol=BINARY_COL, rawPredictionCol='rawPrediction')
    me = MulticlassClassificationEvaluator(
        labelCol=BINARY_COL, predictionCol='prediction')
    return dict(
        auc  = be.setMetricName('areaUnderROC').evaluate(preds),
        acc  = me.setMetricName('accuracy').evaluate(preds),
        prec = me.setMetricName('weightedPrecision').evaluate(preds),
        rec  = me.setMetricName('weightedRecall').evaluate(preds),
        f1   = me.setMetricName('f1').evaluate(preds),
    )


def multi_metrics(preds):
    me = MulticlassClassificationEvaluator(
        labelCol=MULTI_COL, predictionCol='prediction')
    return dict(
        acc  = me.setMetricName('accuracy').evaluate(preds),
        prec = me.setMetricName('weightedPrecision').evaluate(preds),
        rec  = me.setMetricName('weightedRecall').evaluate(preds),
        f1   = me.setMetricName('f1').evaluate(preds),
    )


def per_class_recall(preds, label_col, label_map):
    """Print per-class support + recall table."""
    total_pc = preds.groupBy(label_col).count().withColumnRenamed('count', 'support')
    correct  = (
        preds.filter(F.col(label_col) == F.col('prediction'))
        .groupBy(label_col).count().withColumnRenamed('count', 'correct')
    )
    ldf = spark_broadcast_label_map(preds.sparkSession, label_map, label_col)
    (
        total_pc.join(correct, label_col, 'left')
        .fillna(0, subset=['correct'])
        .withColumn('recall', F.round(F.col('correct') / F.col('support'), 4))
        .join(ldf, label_col, 'left')
        .orderBy(F.desc('support'))
        .select(label_col, 'label_name', 'support', 'correct', 'recall')
        .show(20, truncate=False)
    )


def spark_broadcast_label_map(spark, label_map, label_col):
    return spark.createDataFrame(
        [(float(i), v) for i, v in label_map.items()], [label_col, 'label_name']
    )


def clean_and_scale_external(spark, df, feat_cols, pipe_model, label_udf):
    """Apply feature cleaning + the TRAIN-fitted scaler to an external test set."""
    inf_val, ninf_val = float('inf'), float('-inf')
    for c in feat_cols:
        if c in df.columns:
            df = df.withColumn(c, F.col(c).cast('double'))
        else:
            df = df.withColumn(c, F.lit(None).cast('double'))

    df = df.select([
        F.when(
            F.isnan(F.col(c)) | F.col(c).isin(inf_val, ninf_val), None
        ).otherwise(F.col(c)).alias(c)
        if c in feat_cols else F.col(c)
        for c in df.columns
    ])

    # Impute nulls with zero (external sets — median would require a scan)
    null_cols = [c for c in feat_cols if df.filter(F.col(c).isNull()).count() > 0]
    if null_cols:
        df = df.fillna(0.0, subset=null_cols)

    df = df.withColumn(LABEL_COL, label_udf(F.col(LABEL_COL)))
    df = df.filter(
        F.col(LABEL_COL).isNotNull() & (F.trim(F.col(LABEL_COL)) != '')
    )
    df = df.withColumn(
        BINARY_COL,
        F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0))
         .otherwise(F.lit(1))
    )
    return pipe_model.transform(df)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    # Label normalisation UDF
    from backend.processing.schema_maps import LABEL_NORMALISE
    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc_map = spark.sparkContext.broadcast(norm_map)
    from pyspark.sql.types import StringType
    label_udf = F.udf(
        lambda raw: bc_map.value.get(raw.strip().upper(), raw.strip())
        if raw else None,
        StringType()
    )

    sep('THREVIA — Train on Clean Corpus')

    # ── 1. Load training corpus ────────────────────────────────────────────────
    sep('1. Loading training corpus')
    train = spark.read.parquet(HDFS_TRAIN)
    train_n = train.count()
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
    print(f'  Training rows : {train_n:,}')
    print(f'  Features      : {FEAT_COL} (scaled, from merge_corpus)')
    print(f'  Schema cols   : {len(train.columns)}')

    # Encode multi-class label
    indexer = StringIndexer(inputCol=LABEL_COL, outputCol=MULTI_COL,
                            handleInvalid='keep')
    idx_model = indexer.fit(train)
    train = idx_model.transform(train)
    label_map = {i: v for i, v in enumerate(idx_model.labels)}
    print(f'  Classes ({len(label_map)}) : {label_map}')

    # Label distribution
    print('\n  Training label distribution:')
    (
        train.groupBy(LABEL_COL).count()
        .orderBy(F.desc('count'))
        .show(20, truncate=False)
    )
    train.cache()

    # ── Rebuild the scaler pipeline (to transform external test sets) ──────────
    # The merge corpus used VectorAssembler + StandardScaler; we need to refit
    # it here using the training data so we can apply it to IDS2025 + Friday.
    sep('Fitting VectorAssembler + StandardScaler on training corpus')
    assembler = VectorAssembler(
        inputCols=feat_cols, outputCol='_raw_f', handleInvalid='keep')
    scaler = StandardScaler(
        inputCol='_raw_f', outputCol='_scaled_f',
        withMean=True, withStd=True)
    ext_pipe = Pipeline(stages=[assembler, scaler])

    # The train corpus already has scaled_features from merge, but we need
    # a pipeline fitted on train to apply to external CSVs.
    # We fit on a 10% sample to keep it fast (scaler parameters from full
    # data don't change meaningfully with a large sample).
    sample = train.sample(0.10, seed=42)
    ext_pipe_model = ext_pipe.fit(sample)
    print('  Pipeline fitted on 10% training sample (for external test sets)')

    # ══════════════════════════════════════════════════════════════════════════
    # A) BINARY RANDOM FOREST
    # ══════════════════════════════════════════════════════════════════════════
    sep('A. Train — Binary RF (is_attack 0/1)')
    rf_bin = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=BINARY_COL,
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF binary (50 trees, depth 10) ...')
    rf_bin_model = rf_bin.fit(train)
    rf_bin_model.write().overwrite().save(f'{HDFS_MODELS_NEW}/rf_binary')
    print(f'  Saved -> {HDFS_MODELS_NEW}/rf_binary')

    # ══════════════════════════════════════════════════════════════════════════
    # B) MULTI-CLASS RANDOM FOREST
    # ══════════════════════════════════════════════════════════════════════════
    sep('B. Train — Multi-class RF (all attack types)')
    rf_multi = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=MULTI_COL,
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF multi-class (50 trees, depth 10) ...')
    rf_multi_model = rf_multi.fit(train)
    rf_multi_model.write().overwrite().save(f'{HDFS_MODELS_NEW}/rf_multiclass')
    print(f'  Saved -> {HDFS_MODELS_NEW}/rf_multiclass')

    # ══════════════════════════════════════════════════════════════════════════
    # EVALUATION ON TEST SETS
    # ══════════════════════════════════════════════════════════════════════════

    results = {}  # test_name -> {binary: {...}, multi: {...}}

    # ── TEST-A: IDS2025 held-out validation ───────────────────────────────────
    sep('TEST-A: IDS2025 Validation (cross-source, balanced)')
    ids25_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_VALIDATION)
    )
    ids25 = clean_and_scale_external(
        spark, ids25_raw, feat_cols, ext_pipe_model, label_udf)
    ids25 = idx_model.transform(ids25)
    ids25.cache()
    print(f'  IDS2025 test rows: {ids25.count():,}')
    print('  IDS2025 label distribution:')
    ids25.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(20, truncate=False)

    preds_a_bin   = rf_bin_model.transform(ids25)
    preds_a_multi = rf_multi_model.transform(ids25)
    m_a_bin   = bin_metrics(preds_a_bin)
    m_a_multi = multi_metrics(preds_a_multi)
    results['IDS2025'] = dict(binary=m_a_bin, multi=m_a_multi)

    print('\n  Binary:')
    for k, v in m_a_bin.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in m_a_multi.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Per-class recall (multi):')
    per_class_recall(preds_a_multi, MULTI_COL, label_map)

    # ── TEST-B: PortScan held-out ──────────────────────────────────────────────
    sep('TEST-B: PortScan Held-Out (port-grouped, zero-leakage)')
    ps_test = spark.read.parquet(HDFS_PS_TEST)
    ps_test = idx_model.transform(ps_test)
    ps_test.cache()
    print(f'  PortScan test rows: {ps_test.count():,}')

    preds_b_bin   = rf_bin_model.transform(ps_test)
    preds_b_multi = rf_multi_model.transform(ps_test)
    m_b_bin   = bin_metrics(preds_b_bin)
    m_b_multi = multi_metrics(preds_b_multi)
    results['PortScan_test'] = dict(binary=m_b_bin, multi=m_b_multi)

    print('\n  Binary:')
    for k, v in m_b_bin.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in m_b_multi.items(): print(f'    {k:<8}: {v:.4f}')

    # ── TEST-C: CIC-2017 Friday (temporal generalisation) ─────────────────────
    sep('TEST-C: CIC-2017 Friday (temporal — unseen DDoS/PortScan/Bot)')
    friday_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_RAW)
        .withColumn('_src', F.regexp_extract(F.input_file_name(), r'([^/]+)$', 1))
        .filter(F.col('_src').isin(list(FRIDAY_FILES)))
    )
    # strip col name spaces
    for c in friday_raw.columns:
        sc = c.strip()
        if sc != c:
            friday_raw = friday_raw.withColumnRenamed(c, sc)

    friday_raw = friday_raw.withColumn(
        LABEL_COL, label_udf(F.col(LABEL_COL)))
    friday = clean_and_scale_external(
        spark, friday_raw, feat_cols, ext_pipe_model, label_udf)
    friday = idx_model.transform(friday)
    friday.cache()
    print(f'  Friday test rows: {friday.count():,}')
    print('  Friday label distribution:')
    friday.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(20, truncate=False)

    preds_c_bin   = rf_bin_model.transform(friday)
    preds_c_multi = rf_multi_model.transform(friday)
    m_c_bin   = bin_metrics(preds_c_bin)
    m_c_multi = multi_metrics(preds_c_multi)
    results['CIC17_Friday'] = dict(binary=m_c_bin, multi=m_c_multi)

    print('\n  Binary:')
    for k, v in m_c_bin.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in m_c_multi.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Per-class recall (multi — Friday):')
    per_class_recall(preds_c_multi, MULTI_COL, label_map)

    # ══════════════════════════════════════════════════════════════════════════
    # COMPARISON TABLE
    # ══════════════════════════════════════════════════════════════════════════
    sep('COMPARISON — Clean Corpus vs Old CIC-2017 Baseline')
    print(f"""
  BINARY CLASSIFICATION (is_attack 0/1)
  ┌──────────────────────────┬──────────┬──────────┬──────────┬──────────┐
  │ Evaluation Set           │ Accuracy │    F1    │  AUC-ROC │   Note   │
  ├──────────────────────────┼──────────┼──────────┼──────────┼──────────┤
  │ OLD: CIC-2017 rand 80/20 │  0.9958  │  0.9958  │  0.9996  │ inflated │
  │ NEW: IDS2025 validation  │  {m_a_bin['acc']:.4f}  │  {m_a_bin['f1']:.4f}  │  {m_a_bin['auc']:.4f}  │ cross-src│
  │ NEW: PortScan held-out   │  {m_b_bin['acc']:.4f}  │  {m_b_bin['f1']:.4f}  │  {m_b_bin['auc']:.4f}  │ grp-split│
  │ NEW: CIC-17 Friday       │  {m_c_bin['acc']:.4f}  │  {m_c_bin['f1']:.4f}  │  {m_c_bin['auc']:.4f}  │ temporal │
  └──────────────────────────┴──────────┴──────────┴──────────┴──────────┘

  MULTI-CLASS (all attack types)
  ┌──────────────────────────┬──────────┬──────────┬──────────┐
  │ Evaluation Set           │ Accuracy │    F1    │  Recall  │
  ├──────────────────────────┼──────────┼──────────┼──────────┤
  │ OLD: CIC-2017 rand 80/20 │  0.9962  │  0.9955  │  0.9962  │
  │ NEW: IDS2025 validation  │  {m_a_multi['acc']:.4f}  │  {m_a_multi['f1']:.4f}  │  {m_a_multi['rec']:.4f}  │
  │ NEW: PortScan held-out   │  {m_b_multi['acc']:.4f}  │  {m_b_multi['f1']:.4f}  │  {m_b_multi['rec']:.4f}  │
  │ NEW: CIC-17 Friday       │  {m_c_multi['acc']:.4f}  │  {m_c_multi['f1']:.4f}  │  {m_c_multi['rec']:.4f}  │
  └──────────────────────────┴──────────┴──────────┴──────────┘
    """)

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
