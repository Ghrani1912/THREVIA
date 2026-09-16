"""
Causal Leakage Test for LycoS Classes
======================================

The CORRECT test from the original PortScan investigation:

1. DEDUP + RETRAIN TEST (causal):
   - Remove duplicate/near-duplicate vectors from DoS Hulk, SSH-Patator, GoldenEye
   - Create new train/test splits WITHOUT duplicates
   - Retrain model on deduplicated data
   - Compare recall before/after
   - If recall drops significantly → duplicates were inflating performance

2. TIME-BUCKET GROUPED SPLIT (structural):
   - Apply same time-bucket grouped split used for Friday DDoS
   - Split by timestamp quantiles (e.g., 70% earliest → train, 30% latest → test)
   - Retrain and evaluate
   - If recall drops vs. random split → session correlation was inflating performance

3. COMPARISON:
   - Original random split recall (baseline)
   - Deduplicated random split recall (removes exact duplication)
   - Time-grouped split recall (removes session correlation)
   - If all three match → NO LEAKAGE
   - If grouped < random → LEAKAGE CONFIRMED

Classes to test:
  - DoS Hulk (100% recall on random split)
  - SSH-Patator (99.94% recall on random split)
  - DoS GoldenEye (99.77% recall on random split)

Usage:
    spark-submit test_lycos_leakage_causal.py
"""

import sys
sys.path.insert(0, '/workspace/backend')

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql.window import Window
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.feature import StringIndexer, VectorAssembler, StandardScaler
from pyspark.ml import Pipeline
from pyspark.ml.evaluation import MulticlassClassificationEvaluator

HDFS_ROOT = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN = f'{HDFS_ROOT}/corpus/train'

TARGET_CLASSES = ['DoS Hulk', 'SSH-Patator', 'DoS GoldenEye']

def get_spark():
    return (SparkSession.builder
            .appName('threvia-lycos-causal-test')
            .config('spark.sql.shuffle.partitions', '50')
            .getOrCreate())

def sep(msg):
    print('\n' + '=' * 80)
    print(f'  {msg}')
    print('=' * 80)

def dedup_dataset(df, class_name):
    """Remove duplicate feature vectors"""
    print(f'\n  Deduplicating {class_name}...')
    
    # Key features for deduplication (same as diagnostic)
    key_features = [
        'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
        'Total Fwd Packets', 'Total Backward Packets',
        'Destination Port'
    ]
    
    before_count = df.count()
    
    # Drop duplicates based on key features
    deduped = df.dropDuplicates(key_features)
    
    after_count = deduped.count()
    removed = before_count - after_count
    removed_pct = (removed / before_count * 100) if before_count > 0 else 0
    
    print(f'    Before: {before_count:,} rows')
    print(f'    After:  {after_count:,} rows')
    print(f'    Removed: {removed:,} rows ({removed_pct:.2f}%)')
    
    return deduped, removed_pct

def train_and_evaluate(train_df, test_df, class_name, split_type):
    """Train RF model and evaluate on test set"""
    print(f'\n  Training on {split_type} split for {class_name}...')
    
    # Binary classification: target class vs. rest
    train_binary = train_df.withColumn('binary_label', 
                                       F.when(F.col('Label') == class_name, 1.0).otherwise(0.0))
    test_binary = test_df.withColumn('binary_label',
                                     F.when(F.col('Label') == class_name, 1.0).otherwise(0.0))
    
    train_count = train_binary.count()
    test_count = test_binary.count()
    test_positive = test_binary.filter(F.col('binary_label') == 1.0).count()
    
    print(f'    Train size: {train_count:,}')
    print(f'    Test size:  {test_count:,} ({test_positive:,} positive)')
    
    # Use existing scaled_features
    rf = RandomForestClassifier(
        featuresCol='scaled_features',
        labelCol='binary_label',
        numTrees=100,
        maxDepth=10,
        seed=42
    )
    
    model = rf.fit(train_binary)
    preds = model.transform(test_binary)
    
    # Compute metrics
    evaluator = MulticlassClassificationEvaluator(
        labelCol='binary_label',
        predictionCol='prediction'
    )
    
    recall_eval = MulticlassClassificationEvaluator(
        labelCol='binary_label',
        predictionCol='prediction',
        metricName='recallByLabel',
        metricLabel=1.0
    )
    
    precision_eval = MulticlassClassificationEvaluator(
        labelCol='binary_label',
        predictionCol='prediction',
        metricName='precisionByLabel',
        metricLabel=1.0
    )
    
    accuracy = evaluator.evaluate(preds, {evaluator.metricName: 'accuracy'})
    recall = recall_eval.evaluate(preds)
    precision = precision_eval.evaluate(preds)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    # Confusion matrix for positive class
    tp = preds.filter((F.col('binary_label') == 1.0) & (F.col('prediction') == 1.0)).count()
    fn = preds.filter((F.col('binary_label') == 1.0) & (F.col('prediction') == 0.0)).count()
    
    print(f'    Recall:    {recall:.4f} ({tp}/{test_positive})')
    print(f'    Precision: {precision:.4f}')
    print(f'    F1:        {f1:.4f}')
    print(f'    Accuracy:  {accuracy:.4f}')
    
    return {
        'split_type': split_type,
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'accuracy': accuracy,
        'tp': tp,
        'fn': fn,
        'test_positive': test_positive
    }

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')
    
    sep('CAUSAL LEAKAGE TEST FOR LYCOS CLASSES')
    
    print(f'\n  Target classes: {", ".join(TARGET_CLASSES)}')
    print(f'  Tests:')
    print(f'    1. BASELINE: Random split (current evaluation)')
    print(f'    2. DEDUP: Deduplicated random split')
    print(f'    3. TIME-GROUPED: Not possible (no timestamp in merged corpus)')
    print(f'\n  If DEDUP recall < BASELINE recall → duplicate inflation detected')
    
    # Load full corpus
    print(f'\n  Loading training corpus...')
    full_corpus = spark.read.parquet(HDFS_TRAIN)
    print(f'  Total rows: {full_corpus.count():,}')
    
    results = {}
    
    for class_name in TARGET_CLASSES:
        sep(f'TESTING: {class_name}')
        
        # Filter to just this class + some BENIGN for contrast
        class_df = full_corpus.filter(F.col('Label') == class_name)
        benign_sample = full_corpus.filter(F.col('Label') == 'BENIGN').sample(0.01, seed=42)
        
        class_count = class_df.count()
        benign_count = benign_sample.count()
        
        print(f'\n  Class size: {class_count:,} rows')
        print(f'  BENIGN sample: {benign_count:,} rows')
        
        # Combine
        combined = class_df.union(benign_sample)
        
        # ═══════════════════════════════════════════════════════════════════════
        # TEST 1: BASELINE - Random Split (current method)
        # ═══════════════════════════════════════════════════════════════════════
        print(f'\n  ─── TEST 1: BASELINE (Random Split 70/30) ───')
        
        train_baseline, test_baseline = combined.randomSplit([0.70, 0.30], seed=42)
        metrics_baseline = train_and_evaluate(train_baseline, test_baseline, class_name, 'BASELINE')
        
        # ═══════════════════════════════════════════════════════════════════════
        # TEST 2: DEDUP - Remove duplicates then split
        # ═══════════════════════════════════════════════════════════════════════
        print(f'\n  ─── TEST 2: DEDUPLICATED (Remove dups, then random split 70/30) ───')
        
        class_deduped, dup_pct = dedup_dataset(class_df, class_name)
        combined_deduped = class_deduped.union(benign_sample)
        
        train_deduped, test_deduped = combined_deduped.randomSplit([0.70, 0.30], seed=42)
        metrics_deduped = train_and_evaluate(train_deduped, test_deduped, class_name, 'DEDUPLICATED')
        
        # ═══════════════════════════════════════════════════════════════════════
        # COMPARISON
        # ═══════════════════════════════════════════════════════════════════════
        print(f'\n  ─── COMPARISON ───')
        print(f'    Duplicate %:        {dup_pct:.2f}%')
        print(f'    BASELINE recall:    {metrics_baseline["recall"]:.4f}')
        print(f'    DEDUPLICATED recall: {metrics_deduped["recall"]:.4f}')
        
        recall_drop = metrics_baseline['recall'] - metrics_deduped['recall']
        recall_drop_pct = (recall_drop / metrics_baseline['recall'] * 100) if metrics_baseline['recall'] > 0 else 0
        
        print(f'    Recall drop:        {recall_drop:.4f} ({recall_drop_pct:.1f}%)')
        
        if abs(recall_drop) < 0.01:
            print(f'    ✅ MINIMAL DROP — Duplicates NOT inflating performance')
        elif recall_drop > 0.05:
            print(f'    🔴 SIGNIFICANT DROP — Duplicates WERE inflating performance')
        else:
            print(f'    🟡 MODERATE DROP — Some duplicate influence')
        
        results[class_name] = {
            'dup_pct': dup_pct,
            'baseline': metrics_baseline,
            'deduped': metrics_deduped,
            'recall_drop': recall_drop,
            'recall_drop_pct': recall_drop_pct
        }
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FINAL VERDICT
    # ═══════════════════════════════════════════════════════════════════════════
    sep('FINAL CAUSAL TEST VERDICT')
    
    print(f'\n  Summary Table:')
    print('  ' + '-' * 78)
    print(f'  {"Class":<20} {"Dup %":<10} {"Baseline":<12} {"Deduped":<12} {"Drop":<12} {"Verdict"}')
    print('  ' + '-' * 78)
    
    for class_name, res in results.items():
        baseline_recall = res['baseline']['recall']
        deduped_recall = res['deduped']['recall']
        drop = res['recall_drop']
        dup_pct = res['dup_pct']
        
        if abs(drop) < 0.01:
            verdict = '✅ NO INFLATION'
        elif drop > 0.05:
            verdict = '🔴 INFLATED'
        else:
            verdict = '🟡 MINOR INFLATION'
        
        print(f'  {class_name:<20} {dup_pct:<10.2f} {baseline_recall:<12.4f} {deduped_recall:<12.4f} {drop:<12.4f} {verdict}')
    
    print('\n  Interpretation:')
    print('  ' + '-' * 78)
    
    any_inflated = any(res['recall_drop'] > 0.05 for res in results.values())
    
    if any_inflated:
        print(f"""
  🔴 LEAKAGE CONFIRMED (Duplicate Inflation)
  
  One or more classes show >5% recall drop after deduplication.
  This means the original random split recall was inflated by duplicate vectors.
  
  Action required:
    1. Use deduplicated splits for TEST-A evaluation
    2. Re-report recall numbers with DEDUPLICATED split
    3. Original numbers should be marked as "INFLATED (pre-dedup)"
        """)
    else:
        print(f"""
  ✅ NO DUPLICATE INFLATION DETECTED
  
  All classes show <1% recall drop after deduplication.
  This matches the original finding: accuracy dropped only 0.0003 after global dedup.
  
  However:
    ⚠️  This only tests EXACT duplicates, not session correlation
    ⚠️  Time-grouped split test NOT possible (no timestamp in merged corpus)
    ⚠️  Cannot rule out correlated-flow inflation without temporal split
  
  Recommendation:
    - Mark TEST-A as "dedup-verified, session-correlation untestable"
    - If original LycoS extraction preserved timestamps, re-run with time-grouped split
    - Otherwise, acknowledge limitation in final report
        """)
    
    spark.stop()

if __name__ == '__main__':
    main()
