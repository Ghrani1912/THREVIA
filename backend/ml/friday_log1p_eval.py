"""
Step 4 — Isolation Experiment: log1p transform on Friday, OLD saved model
==========================================================================
Applies the new log1p preprocessing (Flow Duration, Bytes/s, Packets/s)
to CIC-2017 Friday test data ONLY, then scores with the EXISTING saved model
at /threvia/models_clean/ (no retraining).

Compares AUC-ROC, accuracy, BENIGN recall vs the v1 eval (no log1p):
  v1 result: binary acc=0.3334, F1=0.2491, AUC=0.2394, BENIGN recall=8.0%

If AUC moves from 0.24 back toward ≥ 0.5, the scale gap was the driver.
If AUC barely moves, the domain shift is structural and log1p alone won't fix it.

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      --driver-memory 3g --executor-memory 3g \\
      /workspace/backend/ml/friday_log1p_eval.py
"""

import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassificationModel
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

HDFS_TRAIN      = 'hdfs://namenode:8020/threvia/corpus/train'   # v1 corpus for scaler fit
HDFS_RAW        = 'hdfs://namenode:8020/threvia/raw'
HDFS_MODELS     = 'hdfs://namenode:8020/threvia/models_clean'   # models trained on v1

FEAT_COLS = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
LABEL_COL = 'Label'
BIN_COL   = 'is_attack'
MULTI_COL = 'attack_type_idx'
DURATION_FLOOR = 1.0

FRIDAY_FILES = {
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
}

# v1 baseline numbers (no log1p, from eval_clean_corpus.py run)
V1 = dict(bin_acc=0.3334, bin_f1=0.2491, bin_auc=0.2394,
          multi_acc=0.1618, multi_f1=0.2263,
          benign_recall=0.0801)


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-FridayLog1pIsolation')
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


def apply_log1p(df, feat_cols):
    """Apply log1p to the three rate/duration features."""
    if 'Flow Duration' in feat_cols:
        df = df.withColumn(
            'Flow Duration',
            F.log1p(F.greatest(F.col('Flow Duration'), F.lit(DURATION_FLOOR)))
        )
    for c in ['Flow Bytes/s', 'Flow Packets/s']:
        if c in feat_cols:
            df = df.withColumn(c, F.log1p(F.greatest(F.col(c), F.lit(0.0))))
    return df


def prep_friday(spark, feat_cols, label_udf, pipe_model, idx_model,
                apply_transform=True):
    """Load CIC-2017 Friday, clean, optionally apply log1p, scale, encode."""
    df = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_RAW)
        .withColumn('_src', F.regexp_extract(F.input_file_name(), r'([^/]+)$', 1))
        .filter(F.col('_src').isin(list(FRIDAY_FILES)))
    )
    # strip col whitespace
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

    if apply_transform:
        df = apply_log1p(df, feat_cols)

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


def evaluate(preds_bin, preds_multi, label_map, spark):
    be = BinaryClassificationEvaluator(labelCol=BIN_COL, rawPredictionCol='rawPrediction')
    me = MulticlassClassificationEvaluator(labelCol=BIN_COL, predictionCol='prediction')
    mm = MulticlassClassificationEvaluator(labelCol=MULTI_COL, predictionCol='prediction')

    bin_res = dict(
        auc  = be.setMetricName('areaUnderROC').evaluate(preds_bin),
        acc  = me.setMetricName('accuracy').evaluate(preds_bin),
        prec = me.setMetricName('weightedPrecision').evaluate(preds_bin),
        rec  = me.setMetricName('weightedRecall').evaluate(preds_bin),
        f1   = me.setMetricName('f1').evaluate(preds_bin),
    )
    multi_res = dict(
        acc  = mm.setMetricName('accuracy').evaluate(preds_multi),
        prec = mm.setMetricName('weightedPrecision').evaluate(preds_multi),
        rec  = mm.setMetricName('weightedRecall').evaluate(preds_multi),
        f1   = mm.setMetricName('f1').evaluate(preds_multi),
    )

    # per-class recall
    ldf = spark.createDataFrame(
        [(float(i), v) for i, v in label_map.items()], [MULTI_COL, 'lname'])
    sup = preds_multi.groupBy(MULTI_COL).count().withColumnRenamed('count', 'support')
    cor = (preds_multi.filter(F.col(MULTI_COL) == F.col('prediction'))
           .groupBy(MULTI_COL).count().withColumnRenamed('count', 'correct'))
    pc = (sup.join(cor, MULTI_COL, 'left')
            .fillna(0, subset=['correct'])
            .withColumn('recall', F.round(F.col('correct') / F.col('support'), 4))
            .join(ldf, MULTI_COL, 'left')
            .orderBy(F.desc('support'))
            .select(MULTI_COL, 'lname', 'support', 'correct', 'recall'))

    # BENIGN recall specifically
    benign_row = pc.filter(F.col('lname') == 'BENIGN').first()
    benign_recall = benign_row['recall'] if benign_row else 0.0

    return bin_res, multi_res, pc, benign_recall


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc_map = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc_map.value.get(raw.strip().upper(), raw.strip())
        if raw else None, StringType()
    )

    sep('THREVIA — Step 4: log1p Isolation Experiment (Friday, old model)')

    # ── Load v1 training corpus for scaler + index fit ────────────────────────
    sep('Loading v1 corpus for StringIndexer + scaler sample')
    train_v1 = spark.read.parquet(HDFS_TRAIN)
    print(f'  v1 corpus rows : {train_v1.count():,}')

    idx_model = StringIndexer(
        inputCol=LABEL_COL, outputCol=MULTI_COL, handleInvalid='keep'
    ).fit(train_v1)
    label_map = {i: v for i, v in enumerate(idx_model.labels)}
    print(f'  Classes : {label_map}')

    # Fit scaler on v1 training sample WITH log1p applied
    # (the scaler in models_clean was fit WITHOUT log1p — this is a new scaler
    #  fit on log1p-transformed data, matched to how the new corpus will look)
    print('\n  Fitting log1p-aware scaler on 10% v1 train sample ...')
    sample = train_v1.sample(0.10, seed=42).drop('raw_features', 'scaled_features')
    sample = apply_log1p(sample, FEAT_COLS)
    ext_pipe = Pipeline(stages=[
        VectorAssembler(inputCols=FEAT_COLS, outputCol='_raw_f', handleInvalid='keep'),
        StandardScaler(inputCol='_raw_f', outputCol='scaled_features',
                       withMean=True, withStd=True),
    ])
    pipe_model = ext_pipe.fit(sample)
    print('  Done.')

    # ── Load models ───────────────────────────────────────────────────────────
    sep('Loading saved models (trained on v1 corpus, no log1p)')
    rf_bin   = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_binary')
    rf_multi = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_multiclass')
    print(f'  rf_binary    (numTrees={rf_bin.getNumTrees})')
    print(f'  rf_multiclass(numTrees={rf_multi.getNumTrees})')

    # ── Run A: v1 path — NO log1p (should reproduce prior eval numbers) ───────
    sep('A. Friday WITHOUT log1p  (should match v1 eval: AUC=0.2394)')
    fri_v1 = prep_friday(spark, FEAT_COLS, label_udf, pipe_model, idx_model,
                         apply_transform=False)
    fri_v1.cache()
    print(f'  Friday rows: {fri_v1.count():,}')
    p_bin_v1   = rf_bin.transform(fri_v1)
    p_multi_v1 = rf_multi.transform(fri_v1)
    b1, m1, pc1, benign_r1 = evaluate(p_bin_v1, p_multi_v1, label_map, spark)
    print(f'\n  Binary : acc={b1["acc"]:.4f}  f1={b1["f1"]:.4f}  auc={b1["auc"]:.4f}')
    print(f'  Multi  : acc={m1["acc"]:.4f}  f1={m1["f1"]:.4f}')
    print(f'  BENIGN recall : {benign_r1:.4f}')
    print('\n  Per-class:')
    pc1.show(10, truncate=False)

    # ── Run B: WITH log1p ─────────────────────────────────────────────────────
    sep('B. Friday WITH log1p  (isolation: same model, log1p transform only)')
    fri_v2 = prep_friday(spark, FEAT_COLS, label_udf, pipe_model, idx_model,
                         apply_transform=True)
    fri_v2.cache()
    print(f'  Friday rows: {fri_v2.count():,}')
    p_bin_v2   = rf_bin.transform(fri_v2)
    p_multi_v2 = rf_multi.transform(fri_v2)
    b2, m2, pc2, benign_r2 = evaluate(p_bin_v2, p_multi_v2, label_map, spark)
    print(f'\n  Binary : acc={b2["acc"]:.4f}  f1={b2["f1"]:.4f}  auc={b2["auc"]:.4f}')
    print(f'  Multi  : acc={m2["acc"]:.4f}  f1={m2["f1"]:.4f}')
    print(f'  BENIGN recall : {benign_r2:.4f}')
    print('\n  Per-class:')
    pc2.show(10, truncate=False)

    # ── Comparison ────────────────────────────────────────────────────────────
    sep('COMPARISON — log1p isolation result')

    def delta(new, old):
        d = new - old
        arrow = '▲' if d > 0.001 else ('▼' if d < -0.001 else '~')
        return f'{new:.4f}  ({arrow}{abs(d):.4f})'

    print(f"""
  ┌─────────────────────┬──────────────────────────┬──────────────────────────┐
  │ Metric              │ v1  (no log1p)           │ log1p only (same model)  │
  ├─────────────────────┼──────────────────────────┼──────────────────────────┤
  │ Binary AUC-ROC      │ {V1['bin_auc']:.4f}                    │ {delta(b2['auc'],  V1['bin_auc']):<24} │
  │ Binary Accuracy     │ {V1['bin_acc']:.4f}                    │ {delta(b2['acc'],  V1['bin_acc']):<24} │
  │ Binary F1           │ {V1['bin_f1']:.4f}                    │ {delta(b2['f1'],   V1['bin_f1']):<24} │
  │ Multi-class Acc     │ {V1['multi_acc']:.4f}                    │ {delta(m2['acc'],  V1['multi_acc']):<24} │
  │ Multi-class F1      │ {V1['multi_f1']:.4f}                    │ {delta(m2['f1'],   V1['multi_f1']):<24} │
  │ BENIGN recall       │ {V1['benign_recall']:.4f}                    │ {delta(benign_r2, V1['benign_recall']):<24} │
  └─────────────────────┴──────────────────────────┴──────────────────────────┘

  INTERPRETATION:
    AUC-ROC delta = {b2['auc'] - V1['bin_auc']:+.4f}
    {'AUC moved significantly toward 0.5+ => log1p compresses the scale gap; '
     'retraining on log1p corpus should improve generalization further.'
     if b2['auc'] - V1['bin_auc'] > 0.10
     else
     'AUC barely moved => domain shift is structural (log1p alone insufficient); '
     'retraining on combined LycoS+CIC-2017 BENIGN data is the right next step.'}
    """)

    sep('STEP 4 COMPLETE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
