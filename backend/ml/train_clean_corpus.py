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

import os
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

# ── Class-weight configuration ────────────────────────────────────────────────
# WEIGHT_CAP caps inverse-frequency class weights.  Pre-fix they were unbounded
# and reached 22,420x for "Web Attack - Sql Injection" (50 rows in a 15.69M-row
# corpus) and 9,663x for XSS.  See backend/ml/audit_class_weights.py for the
# full table.  The cap preserves genuine uplift for rare classes while removing
# the anomalous amplification that pulled slow/sparse BENIGN flows across the
# binary decision boundary.
WEIGHT_CAP = float(os.getenv('WEIGHT_CAP', '100.0'))

# MODELS_OUT lets a candidate retrain be written somewhere other than the live
# model directory, so it can be evaluated on the held-out sets before promotion.
# Scaler + imputer medians are always *loaded* from HDFS_MODELS_NEW.
MODELS_OUT = os.getenv('MODELS_OUT', HDFS_MODELS_NEW)

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
    table = (
        total_pc.join(correct, label_col, 'left')
        .fillna(0, subset=['correct'])
        .withColumn('recall', F.round(F.col('correct') / F.col('support'), 4))
        .join(ldf, label_col, 'left')
        .orderBy(F.desc('support'))
        .select(label_col, 'label_name', 'support', 'correct', 'recall')
    )
    table.show(20, truncate=False)
    # Also return the table so the caller can persist it as a metric artifact.
    return {
        (r['label_name'] or f'idx_{r[label_col]}'): {
            'support': int(r['support']),
            'correct': int(r['correct']),
            'recall': float(r['recall']),
        }
        for r in table.collect()
    }


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
    # NOTE: `train` is deliberately NOT cached here.  The corpus is 81 columns
    # wide and carries TWO dense vectors per row (raw_features and
    # scaled_features), so materialising it before the weight joins and again
    # afterwards exhausts the driver heap (observed: java.lang.OutOfMemoryError
    # during the binary RF fit).  The weight tables are computed first, then
    # joined once, then the frame is pruned to the columns training actually
    # reads and cached exactly once.

    # Fix-1b: SEPARATE weight columns, one per target, each capped (WEIGHT_CAP).
    #
    # The pre-fix code computed ONE weight column from the MULTICLASS label
    # distribution and handed it to BOTH models.  Measured consequences on this
    # corpus (see audit_class_weights.py):
    #
    #   binary model received  BENIGN 0.1x vs Sql Injection 22,420x
    #   correct binary weights BENIGN 0.672x vs ATTACK 1.954x
    #
    # i.e. BENIGN was under-weighted ~6.7x while rare attack rows were
    # over-weighted by four to five figures, when deciding attack-or-not.  That
    # is the documented cause of the slow/sparse-BENIGN false positives: the
    # binary model was pushed to call anything resembling a rare slow attack an
    # attack, and slow/sparse BENIGN traffic has the same shape.
    #
    #   weight_bin   = N / (2 * count_is_attack)          -> benign-vs-attack RF
    #   weight_multi = N / (K * count_label), capped      -> multiclass RF
    sep('Computing per-target inverse-frequency class weights')
    print(f'  WEIGHT_CAP = {WEIGHT_CAP:g}')
    print('  (weight tables are computed before anything is cached -- they are\n'
          '   small aggregations and need no materialised corpus)')

    # -- Multiclass weights (used by the multiclass RF only) --
    freq_df = train.groupBy(LABEL_COL).count().withColumnRenamed('count', '_cnt')
    num_classes = freq_df.count()
    multi_weight_df = (
        freq_df.withColumn(
            '_raw',
            F.lit(float(train_n)) / (F.lit(float(num_classes)) * F.col('_cnt')),
        )
        .withColumn('weight_multi', F.least(F.col('_raw'), F.lit(WEIGHT_CAP)))
        .select(LABEL_COL, 'weight_multi', '_raw')
    )
    print('\n  Multiclass weights (multiclass RF):')
    multi_weight_df.orderBy(F.desc('_raw')).show(20, truncate=False)
    _moved = multi_weight_df.filter(F.col('_raw') > F.lit(WEIGHT_CAP)).count()
    print(f'  Labels moved by the {WEIGHT_CAP:g}x cap: {_moved}')
    label_weight_df = multi_weight_df.select(LABEL_COL, 'weight_multi')

    # -- Binary weights (used by the binary RF only) --
    bin_freq = (
        train.withColumn(
            '_binary_tmp',
            F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0)).otherwise(F.lit(1)),
        )
        .groupBy('_binary_tmp').count().withColumnRenamed('count', '_bcnt')
    )
    bin_weight_df = bin_freq.withColumn(
        'weight_bin',
        F.least(
            F.lit(float(train_n)) / (F.lit(2.0) * F.col('_bcnt')),
            F.lit(WEIGHT_CAP),
        ),
    ).withColumnRenamed('_binary_tmp', BINARY_COL).select(BINARY_COL, 'weight_bin')
    print('\n  Binary weights (binary RF):  0 = BENIGN, 1 = attack')
    bin_weight_df.orderBy(BINARY_COL).show(10, truncate=False)

    # Prune to the columns training reads, then join the two tiny weight tables.
    # Dropping raw_features and the 75 unscaled feature columns roughly halves
    # the cached footprint.
    train = (
        train.select(FEAT_COL, LABEL_COL, BINARY_COL, MULTI_COL)
        .join(F.broadcast(label_weight_df), on=LABEL_COL, how='left')
        .join(F.broadcast(bin_weight_df), on=BINARY_COL, how='left')
        .fillna(1.0, subset=['weight_bin', 'weight_multi'])
        .select(FEAT_COL, LABEL_COL, BINARY_COL, MULTI_COL, 'weight_bin', 'weight_multi')
    )
    # Default MEMORY_AND_DISK is enough now that the frame is pruned: the
    # original script cached 81 columns and completed, and this holds 6, so the
    # cached footprint drops roughly 3x.  (Spark 4.2 no longer exposes the
    # MEMORY_AND_DISK_SER constant, so the plain cache is also the portable
    # choice.)
    train.cache()
    print(f'\n  Cached training frame : {train.count():,} rows x {len(train.columns)} cols'
          f' (feature vector: {len(feat_cols)} dims)')
    print(f'  Columns kept          : {train.columns}')


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
        featuresCol=FEAT_COL, labelCol=BINARY_COL, weightCol='weight_bin',
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF binary (50 trees, depth 10) ...')
    rf_bin_model = rf_bin.fit(train)
    rf_bin_model.write().overwrite().save(f'{MODELS_OUT}/rf_binary')
    print(f'  Saved -> {MODELS_OUT}/rf_binary')

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # B) MULTI-CLASS RANDOM FOREST
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    sep('B. Train â€” Multi-class RF (all attack types)')
    rf_multi = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=MULTI_COL,  weightCol='weight_multi',
        numTrees=50, maxDepth=10, seed=42,
    )
    print('  Training RF multi-class (50 trees, depth 10) ...')
    rf_multi_model = rf_multi.fit(train)
    rf_multi_model.write().overwrite().save(f'{MODELS_OUT}/rf_multiclass')
    print(f'  Saved -> {MODELS_OUT}/rf_multiclass')

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
    c1_per_class = per_class_recall(preds_c1_multi, MULTI_COL, label_map)

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

    # ── Emit the measured metrics artifact ───────────────────────────────────────────────────
    # The dashboard reads this instead of hardcoded constants, so the numbers it
    # shows are always the ones this run actually produced.
    sep('Emitting measured metrics artifact')
    try:
        import json as _json, datetime as _dt
        _metrics = {
            'generated_at': _dt.datetime.utcnow().isoformat() + 'Z',
            'generated_by': 'backend/ml/train_clean_corpus.py',
            'models_dir': MODELS_OUT,
            'training_rows': int(train_n),
            'weighting': {
                'scheme': 'per-target inverse-frequency, capped',
                'weight_cap': WEIGHT_CAP,
                'binary_weights': {str(r[BINARY_COL]): round(float(r['weight_bin']), 4)
                                   for r in bin_weight_df.collect()},
                'multiclass_weights': {r[LABEL_COL]: round(float(r['weight_multi']), 4)
                                       for r in label_weight_df.collect()},
            },
            'label_map': {str(k): v for k, v in label_map.items()},
            'tests': results,
            'temporal_benign_holdout': {
                'rows': int(n_c2),
                'false_positives': int(fp_c2),
                'fpr': round(float(fp_rate_c2), 6),
                'fpr_percent': round(float(fp_rate_c2) * 100, 2),
            },
            'per_class_recall': {'C1_session_split': c1_per_class},
        }
        _out = os.path.join('/workspace', 'backend', 'ml', 'model_metrics.json')
        with open(_out, 'w', encoding='utf-8') as _fh:
            _json.dump(_metrics, _fh, indent=2, default=str)
        print(f'  Wrote {_out}')
        print(f'  C2 temporal BENIGN FPR: {fp_rate_c2 * 100:.2f}%  ({fp_c2:,}/{n_c2:,})')
    except Exception as _e:
        print(f'  WARNING: could not write metrics artifact ({_e})')

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



