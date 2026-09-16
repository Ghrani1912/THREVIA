"""
Bot Evaluation After Label Case Fix
====================================

Test Bot recall after fixing label case mismatch ('BOT' -> 'Bot').

This isolates the label-fix effect before re-training or applying class weights.

Usage:
    spark-submit eval_bot_label_fixed.py
"""

import sys
sys.path.insert(0, '/workspace/backend')

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml import PipelineModel

HDFS_ROOT = 'hdfs://namenode:8020/threvia'
HDFS_BOT_TEST = f'{HDFS_ROOT}/corpus/friday_bot_test'
HDFS_MODELS = f'{HDFS_ROOT}/models_clean'
LABEL_COL = 'Label'
MULTI_COL = 'attack_type_idx'

def get_spark():
    return (SparkSession.builder
            .appName('threvia-eval-bot-fixed')
            .config('spark.sql.shuffle.partitions', '20')
            .getOrCreate())

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')
    
    print('\n' + '=' * 72)
    print('  BOT EVALUATION — Label Case Fix Only (No Retraining)')
    print('=' * 72)
    
    # Load test data
    print('\n  Loading Bot test split...')
    bot_test = spark.read.parquet(HDFS_BOT_TEST)
    print(f'  Bot test rows: {bot_test.count():,}')
    print('\n  Label check:')
    bot_test.select(LABEL_COL).distinct().show()
    
    # Load models
    print('\n  Loading models (trained on OLD corpus with "Bot")...')
    rf_multi_model = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_multiclass')
    scaler_pipe = PipelineModel.load(f'{HDFS_MODELS}/scaler_pipeline')
    
    # Build label map
    from pyspark.ml.feature import StringIndexer
    # We need to check what labels the model was trained on
    train = spark.read.parquet(f'{HDFS_ROOT}/corpus/train')
    indexer = StringIndexer(inputCol=LABEL_COL, outputCol=MULTI_COL, handleInvalid='keep')
    idx_model = indexer.fit(train)
    label_map = {i: label for i, label in enumerate(idx_model.labels)}
    print(f'  Training label map: {label_map}')
    print(f'  "Bot" in training labels: {"Bot" in label_map.values()}')
    
    # Apply preprocessing
    print('\n  Applying scaler pipeline...')
    bot_test_scaled = scaler_pipe.transform(bot_test)
    bot_test_scaled = idx_model.transform(bot_test_scaled)
    bot_test_scaled.cache()
    
    # Predict
    print('\n  Running predictions...')
    preds = rf_multi_model.transform(bot_test_scaled)
    
    # Compute recall
    bot_idx = [k for k, v in label_map.items() if v == 'Bot']
    if not bot_idx:
        print('\n  ❌ ERROR: "Bot" not found in training labels!')
        spark.stop()
        return
    bot_idx = bot_idx[0]
    
    total = preds.count()
    correct = preds.filter(F.col('prediction') == bot_idx).count()
    recall = correct / total if total > 0 else 0
    
    print('\n' + '=' * 72)
    print('  RESULTS')
    print('=' * 72)
    print(f'\n  Bot test samples: {total}')
    print(f'  Correctly predicted as Bot: {correct}')
    print(f'  Bot Recall: {recall:.2%} ({correct}/{total})')
    
    # Confusion matrix
    print('\n  Confusion (Bot predicted as):')
    confusion = preds.withColumn(
        'pred_name',
        F.when(F.col('prediction').isin(list(label_map.keys())), F.lit('NULL'))
         .otherwise(F.lit('NULL'))
    )
    for k, v in label_map.items():
        confusion = confusion.withColumn(
            'pred_name',
            F.when(F.col('prediction') == k, F.lit(v)).otherwise(F.col('pred_name'))
        )
    confusion.groupBy('pred_name').count().orderBy(F.desc('count')).show(10, truncate=False)
    
    print('\n' + '=' * 72)
    print('  VERDICT')
    print('=' * 72)
    print(f"""
  Label Fix Impact:
    Previous recall (with 'BOT' label mismatch): 0.31% (6/1,966)
    Current recall (with 'Bot' label fixed): {recall:.2%} ({correct}/{total})
    
  {"✅ FIXED — Label case mismatch was the root cause" if recall > 50
   else "⚠️  PARTIAL FIX — Recall improved but still low, imbalance/signature issues remain" if recall > 5
   else "❌ NO FIX — Label case wasn't the issue, or training corpus also needs rebuild"}
    """)
    
    spark.stop()

if __name__ == '__main__':
    main()
