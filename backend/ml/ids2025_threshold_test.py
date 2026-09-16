"""
ids2025_threshold_test.py -- Sanity check T=0.50 vs T=0.65 on IDS2025
"""
import sys
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.pipeline import PipelineModel
from pyspark.ml.functions import vector_to_array
import pyspark.sql.functions as F
from pyspark.sql.types import StringType

HDFS           = 'hdfs://namenode:8020/threvia'
HDFS_VALIDATION = f'{HDFS}/validation/ids2025_validation.csv'
HDFS_RF_BIN    = f'{HDFS}/models_clean/rf_binary'
HDFS_SCALER    = f'{HDFS}/models_clean/scaler_pipeline'
HDFS_MEDIANS   = f'{HDFS}/models_clean/imputer_medians'
LABEL_COL      = 'Label'
BINARY_COL     = 'is_attack'

def sep(msg):
    print(f'\n{"="*72}\n  {msg}\n{"="*72}')

def prep(spark, raw_df, ext_pipe, label_udf, fill_map):
    if 'Fwd Header Length34' in raw_df.columns:
        raw_df = raw_df.withColumnRenamed('Fwd Header Length34', 'Fwd Header Length')
    if 'Fwd Header Length55' in raw_df.columns:
        raw_df = raw_df.drop('Fwd Header Length55')
    skip = {LABEL_COL, BINARY_COL, 'attack_type_idx', 'weight',
            'Timestamp', 'Flow ID', 'Source IP', 'Destination IP', 'Protocol'}
    feat_cols = [c for c in raw_df.columns if c not in skip]
    sys.path.insert(0, '/workspace/backend/ml')
    sys.path.insert(0, '/workspace')
    from train_clean_corpus import clean_and_scale_external
    return clean_and_scale_external(spark, raw_df, feat_cols, ext_pipe, label_udf, fill_map=fill_map)

def main():
    spark = (SparkSession.builder
             .appName('Threvia-IDS2025-ThresholdTest')
             .config('spark.sql.shuffle.partitions', '8')
             .getOrCreate())
    spark.sparkContext.setLogLevel('WARN')

    sys.path.insert(0, '/workspace')
    from backend.processing.schema_maps import LABEL_NORMALISE
    _norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    _bc       = spark.sparkContext.broadcast(_norm_map)
    label_udf = F.udf(
        lambda r: _bc.value.get(r.strip().upper(), r.strip()) if r else None,
        StringType()
    )

    sep('Loading models')
    ext_pipe = PipelineModel.load(HDFS_SCALER)
    rf_bin   = RandomForestClassificationModel.load(HDFS_RF_BIN)
    med_row  = spark.read.parquet(HDFS_MEDIANS).first()
    fill_map = dict(med_row.asDict()) if med_row else {}

    sep('Preparing IDS2025 Validation Data')
    raw_ids25 = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(HDFS_VALIDATION)
    )

    ids25_scaled = prep(spark, raw_ids25, ext_pipe, label_udf, fill_map)

    def add_p_att(df):
        return (rf_bin.transform(df)
                .withColumn('prob_arr', vector_to_array('probability'))
                .withColumn('p_att', F.col('prob_arr')[1])
                .select(BINARY_COL, 'p_att')
                .cache())

    preds = add_p_att(ids25_scaled)

    # Split into true benign and true attack for metrics
    n_total  = preds.count()
    n_benign = preds.filter(F.col(BINARY_COL) == 0).count()
    n_attack = preds.filter(F.col(BINARY_COL) == 1).count()
    
    print(f'  IDS2025 BENIGN flows: {n_benign:,}')
    print(f'  IDS2025 ATTACK flows: {n_attack:,}')
    print(f'  IDS2025 TOTAL flows : {n_total:,}')

    sep('Threshold sweep -- attack-side P(attack) > T')
    
    for t in [0.50, 0.65]:
        print(f'  Evaluating T={t:.2f}...')
        fp = preds.filter((F.col(BINARY_COL) == 0) & (F.col('p_att') > t)).count()
        fpr = (fp / n_benign) * 100 if n_benign > 0 else 0
        
        tp = preds.filter((F.col(BINARY_COL) == 1) & (F.col('p_att') > t)).count()
        recall = (tp / n_attack) * 100 if n_attack > 0 else 0
        
        print(f'    T={t:.2f} -> FPR: {fpr:.2f}% (FP: {fp:,}) | Recall: {recall:.2f}% (TP: {tp:,})')

    sep('DONE')
    spark.stop()

if __name__ == '__main__':
    main()
