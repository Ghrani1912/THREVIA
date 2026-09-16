"""
Phase 3 â€” Retrain on Clean Corpus
===================================
Trains RF (binary + multi-class) on the unified clean corpus at
/threvia/corpus/train and evaluates on three held-out test sets:

  TEST-A  IDS2025 validation  (/threvia/validation/ids2025_validation.csv)
          â€” cross-source generalisation check
  TEST-B  PortScan held-out   (/threvia/corpus/portscan_test)
          â€” port-grouped, zero-leakage PortScan test
  TEST-C  CIC-2017 Friday     (/threvia/raw â€” Friday files only)
          â€” temporal generalisation (unseen DDoS/PortScan/Bot from original data)

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

# â”€â”€ HDFS paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
HDFS_TRAIN      = 'hdfs://namenode:8020/threvia/corpus/train'
HDFS_PS_TEST    = 'hdfs://namenode:8020/threvia/corpus/portscan_test'
HDFS_VALIDATION = 'hdfs://namenode:8020/threvia/validation/ids2025_validation.csv'
HDFS_RAW        = 'hdfs://namenode:8020/threvia/raw'
HDFS_DDOS_TEST  = 'hdfs://namenode:8020/threvia/corpus/friday_ddos_test'   # TEST-C1: held-out DDoS sessions
HDFS_BOT_TEST   = 'hdfs://namenode:8020/threvia/corpus/friday_bot_test'    # TEST-C1: held-out Bot sessions
HDFS_BENIGN_C2  = 'hdfs://namenode:8020/threvia/corpus/friday_benign_c2'   # TEST-C2: Friday BENIGN temporal holdout
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

# â”€â”€ Baseline numbers from old CIC-2017 random-split evaluation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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


def clean_and_scale_external(spark, df, feat_cols, pipe_model, label_udf, fill_map=None):
    """Apply feature cleaning + log1p + the TRAIN-fitted scaler to an external test set.
    Must mirror the clean_features() + log1p logic in merge_corpus.py exactly.
    """
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

    # Bug-2 fix: impute with training medians loaded from HDFS, NOT zero.
    # _train_medians is injected into this function via the `fill_map` param.
    if fill_map:
        null_cols = [c for c in feat_cols if c in fill_map
                     and df.filter(F.col(c).isNull()).count() > 0]
        if null_cols:
            df = df.fillna({c: fill_map[c] for c in null_cols}, subset=null_cols)
    else:
        # fallback: only if no medians saved (should not happen after merge_corpus fix)
        null_cols = [c for c in feat_cols if df.filter(F.col(c).isNull()).count() > 0]
        if null_cols:
            df = df.fillna(0.0, subset=null_cols)

    # â”€â”€ log1p transform (must match merge_corpus.py) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    DURATION_FLOOR = 1.0
    if 'Flow Duration' in feat_cols:
        df = df.withColumn(
            'Flow Duration',
            F.log1p(F.greatest(F.col('Flow Duration'), F.lit(DURATION_FLOOR)))
        )
    for c in ['Flow Bytes/s', 'Flow Packets/s']:
        if c in feat_cols:
            df = df.withColumn(c, F.log1p(F.greatest(F.col(c), F.lit(0.0))))

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


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MAIN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

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

    sep('THREVIA â€” Train on Clean Corpus')

    # â”€â”€ 1. Load training corpus â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # Fix-1: Inverse-frequency class weights (no corpus rebuild needed).
    # weight_i = N / (K * count_i)  where N=total rows, K=num classes.
    # This corrects Bot/Infiltration/Slowhttptest recall without SMOTE.
    sep('Computing inverse-frequency class weights')
    freq_df = train.groupBy(LABEL_COL).count().withColumnRenamed('count', '_cnt')
    num_classes = freq_df.count()
    weight_df = freq_df.withColumn(
        'weight',
        F.lit(float(train_n)) / (F.lit(float(num_classes)) * F.col('_cnt'))
    ).select(LABEL_COL, 'weight')
    print('  Per-class weights:')
    weight_df.orderBy(F.desc('weight')).show(20, truncate=False)
    train = train.join(weight_df, on=LABEL_COL, how='left')
    train = train.fillna(1.0, subset=['weight'])
    train.cache()


    # Bug-1 fix: load the scaler pipeline saved by merge_corpus.py.
    # This guarantees external test sets are z-scored with the SAME mu/sigma
    # as the training corpus (not a noisy 10%-sample refit).
    HDFS_SCALER  = f'{HDFS_MODELS_NEW}/scaler_pipeline'
    HDFS_MEDIANS = f'{HDFS_MODELS_NEW}/imputer_medians'
    sep(f'Loading saved scaler pipeline from {HDFS_SCALER}')
    from pyspark.ml import PipelineModel
    ext_pipe_model = PipelineModel.load(HDFS_SCALER)
    print('  Scaler pipeline loaded from HDFS.')

    # Load training-set imputer medians (Bug-2 fix).
    # Falls back to empty dict gracefully if medians were not saved.
    try:
        _med_row = spark.read.parquet(HDFS_MEDIANS).first()
        _train_medians = dict(_med_row.asDict()) if _med_row else {}
        print(f'  Imputer medians loaded: {len(_train_medians)} columns.')
    except Exception as _e:
        print(f'  WARNING: could not load imputer medians ({_e}) - falling back to 0.0')
        _train_medians = {}

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # A) BINARY RANDOM FOREST
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    sep('A. Train â€” Binary RF (is_attack 0/1)')
    rf_bin = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=BINARY_COL, weightCol='weight',
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF binary (50 trees, depth 10) ...')
    rf_bin_model = rf_bin.fit(train)
    rf_bin_model.write().overwrite().save(f'{HDFS_MODELS_NEW}/rf_binary')
    print(f'  Saved -> {HDFS_MODELS_NEW}/rf_binary')

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # B) MULTI-CLASS RANDOM FOREST
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    sep('B. Train â€” Multi-class RF (all attack types)')
    rf_multi = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=MULTI_COL,  weightCol='weight',
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF multi-class (50 trees, depth 10) ...')
    rf_multi_model = rf_multi.fit(train)
    rf_multi_model.write().overwrite().save(f'{HDFS_MODELS_NEW}/rf_multiclass')
    print(f'  Saved -> {HDFS_MODELS_NEW}/rf_multiclass')

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # EVALUATION ON TEST SETS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    results = {}  # test_name -> {binary: {...}, multi: {...}}

    # â”€â”€ TEST-A: IDS2025 held-out validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sep('TEST-A: IDS2025 Validation (cross-source, balanced)')
    ids25_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_VALIDATION)
    )
    ids25 = clean_and_scale_external(
        spark, ids25_raw, feat_cols, ext_pipe_model, label_udf, fill_map=_train_medians)
    ids25 = idx_model.transform(ids25)
    ids25.cache()
    # Diagnostic: label distribution + unseen-class count
    print('  IDS2025 Label distribution (post-normalisation):')
    ids25.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(30, truncate=False)
    known_labels = set(idx_model.labels)
    ids25_unseen = ids25.filter(~F.col(LABEL_COL).isin(list(known_labels))).count()
    print(f'  IDS2025 unseen-label rows (not in training 14 classes): {ids25_unseen:,}')
    print(f'  IDS2025 test rows: {ids25.count():,}')


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

    # â”€â”€ TEST-B: PortScan held-out â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # ── TEST-C1: Session-split DDoS + Bot (held-out 30%, zero overlap with training) ──────
    sep('TEST-C1: Session-split DDoS + Bot (held-out, zero training overlap)')
    print('  DDoS test  : friday_ddos_test  (38,348 rows — held-out 30%, never in training)')
    print('  Bot test   : friday_bot_test   (570 rows  — held-out 30%, never in training)')

    # Load raw parquets (split_friday_sessions saved raw rows - no scaling yet)
    ddos_raw = spark.read.parquet(HDFS_DDOS_TEST)
    bot_raw  = spark.read.parquet(HDFS_BOT_TEST)

    # Apply same external clean+scale pipeline used for TEST-A (IDS2025)
    ddos_test = clean_and_scale_external(
        spark, ddos_raw, feat_cols, ext_pipe_model, label_udf, fill_map=_train_medians)
    bot_test  = clean_and_scale_external(
        spark, bot_raw,  feat_cols, ext_pipe_model, label_udf, fill_map=_train_medians)

    # Assign integer label index
    ddos_test = idx_model.transform(ddos_test)
    bot_test  = idx_model.transform(bot_test)

    # Union for combined C1 evaluation
    c1_test = ddos_test.unionByName(bot_test, allowMissingColumns=True)
    c1_test.cache()
    print(f'  Total C1 test rows: {c1_test.count():,}')
    c1_test.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(10, truncate=False)

    preds_c1_bin   = rf_bin_model.transform(c1_test)
    preds_c1_multi = rf_multi_model.transform(c1_test)
    m_c1_bin   = bin_metrics(preds_c1_bin)
    m_c1_multi = multi_metrics(preds_c1_multi)
    results['C1_session_split'] = dict(binary=m_c1_bin, multi=m_c1_multi)

    print('\\n  Binary (C1):')
    for k, v in m_c1_bin.items(): print(f'    {k:<8}: {v:.4f}')
    print('\\n  Multi-class (C1):')
    for k, v in m_c1_multi.items(): print(f'    {k:<8}: {v:.4f}')
    print('\\n  Per-class recall (C1 — DDoS + Bot held-out):')
    per_class_recall(preds_c1_multi, MULTI_COL, label_map)

    # ── TEST-C2: Friday BENIGN temporal holdout ──────────────────────────────────────────
    sep('TEST-C2: Friday BENIGN temporal holdout (genuine OOD generalisation)')
    print('  Source: friday_benign_c2 (286,785 BENIGN rows — never in training)')
    print('  Goal  : measure BENIGN precision under temporal shift (false alarm rate)')

    benign_raw = spark.read.parquet(HDFS_BENIGN_C2)
    benign_c2 = clean_and_scale_external(
        spark, benign_raw, feat_cols, ext_pipe_model, label_udf, fill_map=_train_medians)
    benign_c2 = idx_model.transform(benign_c2)
    benign_c2.cache()
    n_c2 = benign_c2.count()
    print(f'  C2 rows: {n_c2:,}')

    preds_c2_bin   = rf_bin_model.transform(benign_c2)
    preds_c2_multi = rf_multi_model.transform(benign_c2)
    m_c2_bin   = bin_metrics(preds_c2_bin)
    m_c2_multi = multi_metrics(preds_c2_multi)
    results['C2_temporal_benign'] = dict(binary=m_c2_bin, multi=m_c2_multi)

    # For C2: key metric is False Positive Rate (BENIGN flagged as attack)
    fp_c2 = preds_c2_bin.filter(F.col('prediction') != F.col(BINARY_COL)).count()
    fp_rate_c2 = fp_c2 / n_c2 if n_c2 > 0 else 0.0
    print(f'  False Positives (BENIGN flagged as attack): {fp_c2:,} / {n_c2:,} = {fp_rate_c2:.4f} ({fp_rate_c2*100:.2f}%)')
    print('\\n  Binary (C2):')
    for k, v in m_c2_bin.items(): print(f'    {k:<8}: {v:.4f}')

    # Use m_c_bin / m_c_multi as aliases for comparison table (C1 is primary)
    m_c_bin   = m_c1_bin
    m_c_multi = m_c1_multi

    # COMPARISON TABLE
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    sep('COMPARISON â€” Clean Corpus vs Old CIC-2017 Baseline')
    print(f"""
  BINARY CLASSIFICATION (is_attack 0/1)
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Evaluation Set           â”‚ Accuracy â”‚    F1    â”‚  AUC-ROC â”‚   Note   â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚ OLD: CIC-2017 rand 80/20 â”‚  0.9958  â”‚  0.9958  â”‚  0.9996  â”‚ inflated â”‚
  â”‚ NEW: IDS2025 validation  â”‚  {m_a_bin['acc']:.4f}  â”‚  {m_a_bin['f1']:.4f}  â”‚  {m_a_bin['auc']:.4f}  â”‚ cross-srcâ”‚
  â”‚ NEW: PortScan held-out   â”‚  {m_b_bin['acc']:.4f}  â”‚  {m_b_bin['f1']:.4f}  â”‚  {m_b_bin['auc']:.4f}  â”‚ grp-splitâ”‚
  | NEW: C1 session-split    |  {m_c_bin['acc']:.4f}  |  {m_c_bin['f1']:.4f}  |  {m_c_bin['auc']:.4f}  | within-src|
  | NEW: C2 temporal BENIGN  |  {m_c2_bin['acc']:.4f}  |  {m_c2_bin['f1']:.4f}  |  {m_c2_bin['auc']:.4f}  | temporal  |
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

  MULTI-CLASS (all attack types)
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚ Evaluation Set           â”‚ Accuracy â”‚    F1    â”‚  Recall  â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚ OLD: CIC-2017 rand 80/20 â”‚  0.9962  â”‚  0.9955  â”‚  0.9962  â”‚
  â”‚ NEW: IDS2025 validation  â”‚  {m_a_multi['acc']:.4f}  â”‚  {m_a_multi['f1']:.4f}  â”‚  {m_a_multi['rec']:.4f}  â”‚
  â”‚ NEW: PortScan held-out   â”‚  {m_b_multi['acc']:.4f}  â”‚  {m_b_multi['f1']:.4f}  â”‚  {m_b_multi['rec']:.4f}  â”‚
  â”‚ NEW: CIC-17 Friday       â”‚  {m_c_multi['acc']:.4f}  â”‚  {m_c_multi['f1']:.4f}  â”‚  {m_c_multi['rec']:.4f}  â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
    """)

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()



