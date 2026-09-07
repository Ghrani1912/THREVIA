"""
Evaluate saved clean-corpus models on all three test sets.
Models at /threvia/models_clean/ (already trained — no refit).

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      --driver-memory 3g --executor-memory 3g \\
      /workspace/backend/ml/eval_clean_corpus.py
"""
import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import (
    RandomForestClassificationModel,
)
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)
from pyspark.ml.feature import StringIndexer, VectorAssembler, StandardScaler
from pyspark.ml import Pipeline
from pyspark.sql.types import StringType

from backend.processing.schema_maps import (
    CANONICAL_FEATURE_COLS, LABEL_NORMALISE,
)

HDFS_TRAIN      = 'hdfs://namenode:8020/threvia/corpus/train'
HDFS_PS_TEST    = 'hdfs://namenode:8020/threvia/corpus/portscan_test'
HDFS_VALIDATION = 'hdfs://namenode:8020/threvia/validation/ids2025_validation.csv'
HDFS_RAW        = 'hdfs://namenode:8020/threvia/raw'
HDFS_MODELS_NEW = 'hdfs://namenode:8020/threvia/models_clean'

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
BIN_COL   = 'is_attack'
MULTI_COL = 'attack_type_idx'

FRIDAY_FILES = {
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
}
FEAT_COLS = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-EvalClean')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.driver.memory', '3g')
        .config('spark.executor.memory', '3g')
        .config('spark.executor.instances', '1')
        .config('spark.executor.cores', '2')
        .config('spark.network.timeout', '800s')
        .config('spark.serializer', 'org.apache.spark.serializer.KryoSerializer')
        .getOrCreate()
    )


def sep(t=''):
    print('\n' + '=' * 72)
    if t:
        print(f'  {t}')
        print('=' * 72)


def bin_m(preds):
    be = BinaryClassificationEvaluator(labelCol=BIN_COL, rawPredictionCol='rawPrediction')
    me = MulticlassClassificationEvaluator(labelCol=BIN_COL, predictionCol='prediction')
    return dict(
        auc  = be.setMetricName('areaUnderROC').evaluate(preds),
        acc  = me.setMetricName('accuracy').evaluate(preds),
        prec = me.setMetricName('weightedPrecision').evaluate(preds),
        rec  = me.setMetricName('weightedRecall').evaluate(preds),
        f1   = me.setMetricName('f1').evaluate(preds),
    )


def multi_m(preds):
    me = MulticlassClassificationEvaluator(labelCol=MULTI_COL, predictionCol='prediction')
    return dict(
        acc  = me.setMetricName('accuracy').evaluate(preds),
        prec = me.setMetricName('weightedPrecision').evaluate(preds),
        rec  = me.setMetricName('weightedRecall').evaluate(preds),
        f1   = me.setMetricName('f1').evaluate(preds),
    )


def per_class(preds, label_col, label_map, spark):
    ldf = spark.createDataFrame(
        [(float(i), v) for i, v in label_map.items()], [label_col, 'lname'])
    sup = preds.groupBy(label_col).count().withColumnRenamed('count', 'support')
    cor = (preds.filter(F.col(label_col) == F.col('prediction'))
           .groupBy(label_col).count().withColumnRenamed('count', 'correct'))
    (sup.join(cor, label_col, 'left')
       .fillna(0, subset=['correct'])
       .withColumn('recall', F.round(F.col('correct') / F.col('support'), 4))
       .join(ldf, label_col, 'left')
       .orderBy(F.desc('support'))
       .select(label_col, 'lname', 'support', 'correct', 'recall')
       .show(20, truncate=False))


def prep_external(spark, df, feat_cols, pipe_model, label_udf, idx_model):
    """Rename + clean + scale + encode an external CSV dataframe."""
    # strip col name whitespace
    for c in df.columns:
        sc = c.strip()
        if sc != c:
            df = df.withColumnRenamed(c, sc)

    inf_val, ninf_val = float('inf'), float('-inf')
    for c in feat_cols:
        if c in df.columns:
            df = df.withColumn(c, F.col(c).cast('double'))
        else:
            df = df.withColumn(c, F.lit(None).cast('double'))

    df = df.select([
        F.when(F.isnan(F.col(c)) | F.col(c).isin(inf_val, ninf_val), None)
         .otherwise(F.col(c)).alias(c)
        if c in feat_cols else F.col(c)
        for c in df.columns
    ])
    null_cols = [c for c in feat_cols if df.filter(F.col(c).isNull()).count() > 0]
    if null_cols:
        df = df.fillna(0.0, subset=null_cols)

    df = df.withColumn(LABEL_COL, label_udf(F.col(LABEL_COL)))
    df = df.filter(F.col(LABEL_COL).isNotNull() & (F.trim(F.col(LABEL_COL)) != ''))
    df = df.withColumn(
        BIN_COL,
        F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0))
         .otherwise(F.lit(1))
    )
    df = pipe_model.transform(df)
    df = idx_model.transform(df)
    return df


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc_map = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc_map.value.get(raw.strip().upper(), raw.strip())
        if raw else None, StringType()
    )

    sep('THREVIA — Evaluate Clean-Corpus Models')

    # ── Load training corpus (for StringIndexer fit + scaler sample) ──────────
    sep('Loading training corpus for StringIndexer + scaler fit')
    train = spark.read.parquet(HDFS_TRAIN)
    train_n = train.count()
    print(f'  Training rows : {train_n:,}')

    idx_model = StringIndexer(
        inputCol=LABEL_COL, outputCol=MULTI_COL, handleInvalid='keep'
    ).fit(train)
    label_map = {i: v for i, v in enumerate(idx_model.labels)}
    print(f'  Classes ({len(label_map)}): {label_map}')

    # Fit external scaler on 10% sample (same as training)
    sample = train.sample(0.10, seed=42)
    ext_pipe = Pipeline(stages=[
        VectorAssembler(inputCols=FEAT_COLS, outputCol='_raw_f', handleInvalid='keep'),
        StandardScaler(inputCol='_raw_f', outputCol=FEAT_COL,
                       withMean=True, withStd=True),
    ])
    ext_pipe_model = ext_pipe.fit(sample)
    print('  Scaler pipeline fitted on 10% train sample')

    # ── Load saved models ─────────────────────────────────────────────────────
    sep('Loading saved models')
    rf_bin   = RandomForestClassificationModel.load(f'{HDFS_MODELS_NEW}/rf_binary')
    rf_multi = RandomForestClassificationModel.load(f'{HDFS_MODELS_NEW}/rf_multiclass')
    print(f'  rf_binary    loaded  (numTrees={rf_bin.getNumTrees})')
    print(f'  rf_multiclass loaded (numTrees={rf_multi.getNumTrees})')

    results = {}

    # ══════════════════════════════════════════════════════════════════════════
    # TEST-A: IDS2025 Validation
    # ══════════════════════════════════════════════════════════════════════════
    sep('TEST-A: IDS2025 Validation (cross-source, balanced)')
    ids25_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_VALIDATION)
    )
    ids25 = prep_external(spark, ids25_raw, FEAT_COLS, ext_pipe_model, label_udf, idx_model)
    ids25.cache()
    ids25_n = ids25.count()
    print(f'  Rows: {ids25_n:,}')
    print('  Label dist:')
    ids25.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(20, truncate=False)

    p_a_bin   = rf_bin.transform(ids25)
    p_a_multi = rf_multi.transform(ids25)
    ma_b = bin_m(p_a_bin)
    ma_m = multi_m(p_a_multi)
    results['IDS2025'] = (ma_b, ma_m)

    print('\n  Binary:')
    for k, v in ma_b.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in ma_m.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Per-class recall (multi):')
    per_class(p_a_multi, MULTI_COL, label_map, spark)

    # ══════════════════════════════════════════════════════════════════════════
    # TEST-B: PortScan held-out
    # ══════════════════════════════════════════════════════════════════════════
    sep('TEST-B: PortScan Held-Out (port-grouped, zero-leakage)')
    ps_test = spark.read.parquet(HDFS_PS_TEST)
    ps_test = idx_model.transform(ps_test)
    ps_test.cache()
    ps_n = ps_test.count()
    print(f'  Rows: {ps_n:,}')

    p_b_bin   = rf_bin.transform(ps_test)
    p_b_multi = rf_multi.transform(ps_test)
    mb_b = bin_m(p_b_bin)
    mb_m = multi_m(p_b_multi)
    results['PortScan'] = (mb_b, mb_m)

    print('\n  Binary:')
    for k, v in mb_b.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in mb_m.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Confusion (PortScan multi):')
    p_b_multi.groupBy(MULTI_COL, 'prediction').count().orderBy(MULTI_COL).show(20)

    # ══════════════════════════════════════════════════════════════════════════
    # TEST-C: CIC-2017 Friday (temporal)
    # ══════════════════════════════════════════════════════════════════════════
    sep('TEST-C: CIC-2017 Friday (temporal — unseen DDoS/PortScan/Bot)')
    friday_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_RAW)
        .withColumn('_src', F.regexp_extract(F.input_file_name(), r'([^/]+)$', 1))
        .filter(F.col('_src').isin(list(FRIDAY_FILES)))
    )
    friday = prep_external(
        spark, friday_raw, FEAT_COLS, ext_pipe_model, label_udf, idx_model)
    friday.cache()
    fri_n = friday.count()
    print(f'  Rows: {fri_n:,}')
    print('  Label dist:')
    friday.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(20, truncate=False)

    p_c_bin   = rf_bin.transform(friday)
    p_c_multi = rf_multi.transform(friday)
    mc_b = bin_m(p_c_bin)
    mc_m = multi_m(p_c_multi)
    results['CIC17_Friday'] = (mc_b, mc_m)

    print('\n  Binary:')
    for k, v in mc_b.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Multi-class:')
    for k, v in mc_m.items(): print(f'    {k:<8}: {v:.4f}')
    print('\n  Per-class recall (multi — Friday):')
    per_class(p_c_multi, MULTI_COL, label_map, spark)
    print('\n  Confusion (Friday binary):')
    p_c_bin.groupBy(BIN_COL, 'prediction').count().orderBy(BIN_COL).show()

    # ══════════════════════════════════════════════════════════════════════════
    # COMPARISON TABLE
    # ══════════════════════════════════════════════════════════════════════════
    sep('COMPARISON: Clean Corpus vs Old CIC-2017 Baseline')
    print(f"""
  BINARY (is_attack 0/1)
  ┌──────────────────────────┬──────────┬──────────┬──────────┬─────────────────┐
  │ Evaluation Set           │ Accuracy │    F1    │  AUC-ROC │ Note            │
  ├──────────────────────────┼──────────┼──────────┼──────────┼─────────────────┤
  │ OLD: CIC-2017 rand 80/20 │  0.9958  │  0.9958  │  0.9996  │ inflated/leaked │
  │ NEW: IDS2025 validation  │  {ma_b['acc']:.4f}  │  {ma_b['f1']:.4f}  │  {ma_b['auc']:.4f}  │ cross-source    │
  │ NEW: PortScan held-out   │  {mb_b['acc']:.4f}  │  {mb_b['f1']:.4f}  │  {mb_b['auc']:.4f}  │ grp-split clean │
  │ NEW: CIC-17 Friday       │  {mc_b['acc']:.4f}  │  {mc_b['f1']:.4f}  │  {mc_b['auc']:.4f}  │ temporal        │
  └──────────────────────────┴──────────┴──────────┴──────────┴─────────────────┘

  MULTI-CLASS (all attack types)
  ┌──────────────────────────┬──────────┬──────────┬──────────┐
  │ Evaluation Set           │ Accuracy │    F1    │  Recall  │
  ├──────────────────────────┼──────────┼──────────┼──────────┤
  │ OLD: CIC-2017 rand 80/20 │  0.9962  │  0.9955  │  0.9962  │
  │ NEW: IDS2025 validation  │  {ma_m['acc']:.4f}  │  {ma_m['f1']:.4f}  │  {ma_m['rec']:.4f}  │
  │ NEW: PortScan held-out   │  {mb_m['acc']:.4f}  │  {mb_m['f1']:.4f}  │  {mb_m['rec']:.4f}  │
  │ NEW: CIC-17 Friday       │  {mc_m['acc']:.4f}  │  {mc_m['f1']:.4f}  │  {mc_m['rec']:.4f}  │
  └──────────────────────────┴──────────┴──────────┴──────────┘
    """)

    sep('EVALUATION COMPLETE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
