"""
Infiltration Proper Test — CIC-2017 Thursday Afternoon
=======================================================

Training: CICIDS2018 Thursday + Wednesday (161,934 rows)
Test: CIC-2017 Thursday Afternoon Infiltration

This provides a real temporal + cross-dataset test for Infiltration,
which has been "effectively untested" throughout the investigation.

Expected challenges:
- Different years (2018 train → 2017 test)
- Different network environments
- Possibly different Infiltration attack tools/methods

Usage:
    spark-submit eval_infiltration.py
"""

import sys
sys.path.insert(0, '/workspace/backend')

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.feature import StringIndexerModel

# Paths
HDFS_ROOT = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN = f'{HDFS_ROOT}/corpus/train'
HDFS_MODELS = f'{HDFS_ROOT}/models_clean'
LOCAL_CIC17_INFILTRATION = 'file:///workspace/backend/data/CIC-IDS- 2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'

LABEL_COL = 'Label'
FEAT_COL = 'scaled_features'
MULTI_COL = 'attack_type_idx'

def get_spark():
    return (SparkSession.builder
            .appName('threvia-eval-infiltration')
            .config('spark.sql.shuffle.partitions', '50')
            .getOrCreate())

def sep(msg):
    print('\n' + '=' * 72)
    print(f'  {msg}')
    print('=' * 72)

def bin_metrics(preds_df):
    from pyspark.ml.evaluation import BinaryClassificationEvaluator, MulticlassClassificationEvaluator
    auc_eval = BinaryClassificationEvaluator(labelCol='is_attack', metricName='areaUnderROC')
    mc_eval = MulticlassClassificationEvaluator(labelCol='is_attack', predictionCol='prediction')
    return {
        'auc': auc_eval.evaluate(preds_df),
        'acc': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'accuracy'}),
        'prec': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'precisionByLabel'}),
        'rec': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'recallByLabel'}),
        'f1': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'fMeasureByLabel'}),
    }

def multi_metrics(preds_df):
    from pyspark.ml.evaluation import MulticlassClassificationEvaluator
    mc_eval = MulticlassClassificationEvaluator(labelCol=MULTI_COL, predictionCol='prediction')
    return {
        'acc': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'accuracy'}),
        'prec': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'weightedPrecision'}),
        'rec': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'weightedRecall'}),
        'f1': mc_eval.evaluate(preds_df, {mc_eval.metricName: 'weightedFMeasure'}),
    }

def per_class_recall(preds_df, label_col, label_map):
    from pyspark.sql.window import Window
    preds_with_name = preds_df.withColumn(
        'label_name',
        F.when(F.col(label_col).isin(list(label_map.keys())),
               F.lit(None).cast('string'))
         .otherwise(F.lit('NULL'))
    )
    for k, v in label_map.items():
        preds_with_name = preds_with_name.withColumn(
            'label_name',
            F.when(F.col(label_col) == k, F.lit(v)).otherwise(F.col('label_name'))
        )
    
    recall_df = (
        preds_with_name
        .groupBy(label_col, 'label_name')
        .agg(
            F.count('*').alias('support'),
            F.sum(F.when(F.col(label_col) == F.col('prediction'), 1).otherwise(0)).alias('correct')
        )
        .withColumn('recall', F.col('correct') / F.col('support'))
        .orderBy(F.desc('support'))
    )
    recall_df.show(20, truncate=False)

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')
    
    sep('INFILTRATION PROPER TEST — CIC-2017 Thursday (Temporal + Cross-Dataset)')
    
    # Load training corpus to get StringIndexer labels
    print('\n  Loading training corpus to extract label mapping...')
    train = spark.read.parquet(HDFS_TRAIN)
    train_labels = train.select(LABEL_COL).distinct().collect()
    label_set = {row[LABEL_COL] for row in train_labels}
    print(f'  Training classes (14): {sorted(label_set)}')
    print(f'  "Infiltration" in training: {"Infiltration" in label_set}')
    
    # Load models
    print('\n  Loading models...')
    rf_bin_model = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_binary')
    rf_multi_model = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_multiclass')
    
    # Load StringIndexer (trained label map)
    from pyspark.ml import PipelineModel
    scaler_pipe = PipelineModel.load(f'{HDFS_MODELS}/scaler_pipeline')
    # Extract StringIndexer from the pipeline (it's the first stage in train_clean_corpus.py)
    # Actually, we need to rebuild it from training labels
    from pyspark.ml.feature import StringIndexer
    indexer = StringIndexer(inputCol=LABEL_COL, outputCol=MULTI_COL, handleInvalid='keep')
    idx_model = indexer.fit(train)
    label_map = {i: label for i, label in enumerate(idx_model.labels)}
    print(f'  Label map: {label_map}')
    
    # ── Load CIC-2017 Thursday Infiltration ───────────────────────────────────
    sep('Loading CIC-2017 Thursday Afternoon Infiltration')
    
    infil_raw = (
        spark.read.option('header', True).option('inferSchema', False)
        .csv(LOCAL_CIC17_INFILTRATION)
    )
    
    # Strip column name spaces and handle duplicates
    raw_cols = infil_raw.columns
    for c in raw_cols:
        sc = c.strip()
        if sc != c:
            infil_raw = infil_raw.withColumnRenamed(c, sc)
    
    # CRITICAL: CIC-2017 has duplicate 'Fwd Header Length' (cols 35 and 55)
    # The first one often gets dropped or the second one gets a suffix
    # Check if 'Fwd Header Length' exists; if not, add it with zeros
    if 'Fwd Header Length' not in infil_raw.columns:
        print('  WARNING: "Fwd Header Length" missing! Adding zeros...')
        infil_raw = infil_raw.withColumn('Fwd Header Length', F.lit(0.0))
    
    total_rows = infil_raw.count()
    print(f'  Total rows in file: {total_rows:,}')
    
    # Label distribution
    print('\n  Raw label distribution:')
    infil_raw.groupBy('Label').count().orderBy(F.desc('count')).show(10, truncate=False)
    
    # Keep both Infiltration and BENIGN for evaluation
    infil_df = infil_raw.filter(
        F.upper(F.trim(F.col('Label'))).isin(['INFILTRATION', 'INFILTERATION', 'BENIGN'])
    )
    infil_count = infil_raw.filter(
        F.upper(F.trim(F.col('Label'))).isin(['INFILTRATION', 'INFILTERATION'])
    ).count()
    benign_count = infil_raw.filter(F.upper(F.trim(F.col('Label'))) == 'BENIGN').count()
    
    print(f'\n  Test set composition (Infiltration + BENIGN):')
    print(f'    Infiltration: {infil_count:,}')
    print(f'    BENIGN: {benign_count:,}')
    print(f'    Total test rows: {infil_count + benign_count:,}')
    
    if infil_count == 0:
        print('\n  ❌ NO INFILTRATION ROWS FOUND')
        print('  Checking for typo variants...')
        infil_raw.groupBy('Label').count().orderBy(F.desc('count')).show(20, truncate=False)
        spark.stop()
        return
    
    # Normalize label
    infil_df = infil_df.withColumn(
        LABEL_COL,
        F.when(F.upper(F.col(LABEL_COL)).contains('INFIL'), F.lit('Infiltration'))
         .otherwise(F.col(LABEL_COL))
    )
    
    # The corpus pipeline already has scaler fitted
    # We need to apply same preprocessing: cast to double, log1p, scale
    FEAT_COLS = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets',
        'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max',
        'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max',
        'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
        'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
        'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
        'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
        'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
        'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
        'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
        'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
        'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
        'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd',
        'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
        'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ]
    DURATION_FLOOR = 1.0
    
    # Cast and clean
    for c in FEAT_COLS:
        if c in infil_df.columns:
            infil_df = infil_df.withColumn(c, F.col(c).cast('double'))
    
    # Apply log1p to rate features (same as merge_corpus)
    log1p_cols = ['Flow Duration', 'Flow Bytes/s', 'Flow Packets/s']
    for c in log1p_cols:
        if c in infil_df.columns:
            if c == 'Flow Duration':
                infil_df = infil_df.withColumn(
                    c, F.log1p(F.greatest(F.col(c), F.lit(DURATION_FLOOR)))
                )
            else:
                infil_df = infil_df.withColumn(c, F.log1p(F.col(c)))
    
    # Replace inf/nan with null
    inf_val, ninf_val = float('inf'), float('-inf')
    for c in FEAT_COLS:
        if c in infil_df.columns:
            infil_df = infil_df.withColumn(
                c,
                F.when(F.isnan(F.col(c)) | F.col(c).isin(inf_val, ninf_val), None)
                 .otherwise(F.col(c))
            )
    
    # Select only canonical features
    select_cols = [c for c in FEAT_COLS if c in infil_df.columns] + [LABEL_COL]
    infil_df = infil_df.select(*select_cols)
    
    # Apply scaler pipeline
    infil_scaled = scaler_pipe.transform(infil_df)
    
    # Add is_attack column
    infil_scaled = infil_scaled.withColumn(
        'is_attack',
        F.when(F.col(LABEL_COL) == 'BENIGN', 0.0).otherwise(1.0)
    )
    
    # Apply StringIndexer
    infil_scaled = idx_model.transform(infil_scaled)
    infil_scaled.cache()
    
    print(f'\n  Preprocessed test rows: {infil_scaled.count():,}')
    print('  Label distribution after preprocessing:')
    infil_scaled.groupBy(LABEL_COL).count().show(10, truncate=False)
    
    # ── Evaluate ──────────────────────────────────────────────────────────────
    sep('Evaluation on CIC-2017 Infiltration')
    
    # Binary
    preds_bin = rf_bin_model.transform(infil_scaled)
    m_bin = bin_metrics(preds_bin)
    
    print('\n  Binary (Infiltration vs BENIGN):')
    for k, v in m_bin.items():
        print(f'    {k:<8}: {v:.4f}')
    
    # Multi-class
    preds_multi = rf_multi_model.transform(infil_scaled)
    m_multi = multi_metrics(preds_multi)
    
    print('\n  Multi-class:')
    for k, v in m_multi.items():
        print(f'    {k:<8}: {v:.4f}')
    
    print('\n  Per-class recall:')
    per_class_recall(preds_multi, MULTI_COL, label_map)
    
    # Confusion matrix for Infiltration specifically
    print('\n  Infiltration confusion (what did Infiltration get predicted as?):')
    infil_only = preds_multi.filter(F.col(LABEL_COL) == 'Infiltration')
    infil_confusion = (
        infil_only
        .withColumn('pred_label', 
            F.when(F.col('prediction').isin(list(label_map.keys())),
                   F.lit('NULL'))
             .otherwise(F.lit('NULL'))
        )
    )
    for k, v in label_map.items():
        infil_confusion = infil_confusion.withColumn(
            'pred_label',
            F.when(F.col('prediction') == k, F.lit(v)).otherwise(F.col('pred_label'))
        )
    
    infil_confusion.groupBy('pred_label').count().orderBy(F.desc('count')).show(15, truncate=False)
    
    # ── Verdict ───────────────────────────────────────────────────────────────
    sep('VERDICT — Infiltration Temporal Test')
    
    infiltration_recall = preds_multi.filter(
        (F.col(LABEL_COL) == 'Infiltration') & 
        (F.col('prediction') == F.col(MULTI_COL))
    ).count() / infil_count if infil_count > 0 else 0.0
    
    print(f"""
  Test: CIC-2017 Thursday Afternoon Infiltration ({infil_count:,} rows)
  Train: CICIDS2018 Thursday + Wednesday (161,934 rows)
  
  Results:
    Binary AUC    : {m_bin['auc']:.4f}
    Binary Acc    : {m_bin['acc']:.4f}
    Multi-class F1: {m_multi['f1']:.4f}
    
    Infiltration Recall: {infiltration_recall:.2%} ({int(infiltration_recall * infil_count)}/{infil_count})
  
  Interpretation:
    {"✅ GOOD — Model generalizes across datasets/years" if infiltration_recall > 0.80
     else "⚠️  MODERATE — Some generalization but not strong" if infiltration_recall > 0.50
     else "❌ POOR — Cross-dataset/temporal generalization failed"}
    
    This is the first proper Infiltration test in the entire investigation.
    Previous tests had only 9-29 test rows — statistically meaningless.
    """)
    
    spark.stop()

if __name__ == '__main__':
    main()
