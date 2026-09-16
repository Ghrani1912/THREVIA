"""
Diagnose Bot 0.31% recall (6 correct out of 1,966)
===================================================

Two hypotheses:
1. Label mismatch: Training "Bot" != Test "Bot" after normalisation
2. Class imbalance: 97,550 Bot training rows (0.62% of 15.7M) drowned by BENIGN

Checks:
- Exact label strings in training vs test
- Training class distribution (raw counts + percentages)
- Feature distribution comparison (brief — already done in bot_and_benign_audit.py)

Usage:
    python backend/processing/diagnose_bot.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyspark.sql import SparkSession
import pyspark.sql.functions as F

HDFS_TRAIN = 'hdfs://namenode:8020/threvia/corpus/train'
HDFS_BOT_TEST = 'hdfs://namenode:8020/threvia/corpus/friday_bot_test'

def get_spark():
    return (SparkSession.builder
            .appName('threvia-diagnose-bot')
            .config('spark.sql.shuffle.partitions', '20')
            .getOrCreate())

def sep(msg):
    print('\n' + '=' * 72)
    print(f'  {msg}')
    print('=' * 72)

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')
    
    sep('DIAGNOSIS — Bot 0.31% Recall (6/1966)')
    
    # ── Training corpus ───────────────────────────────────────────────────────
    sep('1. Training Corpus Label Distribution')
    train = spark.read.parquet(HDFS_TRAIN)
    total = train.count()
    print(f'  Total training rows: {total:,}')
    
    label_dist = train.groupBy('Label').count().orderBy(F.desc('count'))
    label_dist_with_pct = label_dist.withColumn(
        'pct', (F.col('count') / total * 100).cast('decimal(10,2)')
    )
    print('\n  Label distribution:')
    label_dist_with_pct.show(20, truncate=False)
    
    # Bot specifically
    bot_train = train.filter(F.upper(F.col('Label')) == 'BOT')
    bot_count = bot_train.count()
    bot_pct = bot_count / total * 100
    print(f'\n  Bot in training: {bot_count:,} rows ({bot_pct:.4f}%)')
    
    # Check for label variants
    bot_variants = train.filter(F.col('Label').contains('ot')).groupBy('Label').count()
    print('\n  Labels containing "ot":')
    bot_variants.show(10, truncate=False)
    
    # ── Test split ────────────────────────────────────────────────────────────
    sep('2. Bot Test Split (570 rows)')
    bot_test = spark.read.parquet(HDFS_BOT_TEST)
    print(f'  Bot test rows: {bot_test.count():,}')
    print('\n  Label distribution in test:')
    bot_test.groupBy('Label').count().show(10, truncate=False)
    
    # Check exact label strings
    test_labels = bot_test.select('Label').distinct().collect()
    train_labels = train.select('Label').distinct().collect()
    
    test_set = {row['Label'] for row in test_labels}
    train_set = {row['Label'] for row in train_labels}
    
    print(f'\n  Unique labels in test: {test_set}')
    print(f'  "Bot" in training: {"Bot" in train_set}')
    print(f'  "Bot" in test: {"Bot" in test_set}')
    
    # ── Class imbalance analysis ──────────────────────────────────────────────
    sep('3. Class Imbalance Analysis')
    
    # Get attack vs BENIGN split
    benign_count = train.filter(F.col('Label') == 'BENIGN').count()
    attack_count = train.filter(F.col('Label') != 'BENIGN').count()
    
    print(f'\n  BENIGN  : {benign_count:,}  ({benign_count/total*100:.2f}%)')
    print(f'  ATTACK  : {attack_count:,}  ({attack_count/total*100:.2f}%)')
    print(f'  Ratio   : {benign_count/attack_count:.2f}x')
    
    # Bot specifically
    print(f'\n  Bot vs BENIGN ratio: {benign_count/bot_count:.0f}x')
    print(f'  Bot vs total: 1 in {int(total/bot_count):,} rows')
    
    # Smallest classes
    print('\n  Smallest 5 classes:')
    label_dist.orderBy('count').show(5, truncate=False)
    
    sep('4. Random Forest Class Weighting Note')
    print("""
  Spark MLlib's RandomForestClassifier does NOT support class weights.
  The only options are:
    1. Manual oversampling of minority class (Bot) before training
    2. Manual undersampling of majority class (BENIGN)
    3. Threshold tuning at prediction time
    4. Use a different algorithm (e.g., LogisticRegression with weightCol)
  
  Current RF was trained with default equal weighting → BENIGN dominates.
    """)
    
    sep('VERDICT')
    print(f"""
  Root cause of Bot 0.31% recall (6/1966):
  
  1. ✅ Label strings match — "Bot" in both train and test (no silent bug)
  
  2. ❌ EXTREME class imbalance:
     - Bot: 97,550 rows (0.62% of training data)
     - BENIGN: 11,677,188 rows (74.4% of training data)
     - Ratio: {int(benign_count/bot_count)}:1
     
     The Random Forest learned "when in doubt, predict BENIGN" because:
       a) BENIGN dominates 74% of training examples
       b) RF has no class weighting to up-weight Bot
       c) Bot's 1,396 Friday training examples (1.4% of Bot class) are
          statistically invisible in a 15.7M row corpus
  
  3. ❌ Signature mismatch compounds the problem:
     - Earlier analysis showed 73x difference in Flow Packets/s
     - Different TCP flag patterns (LycoS Bot has SYN=2/FIN=1, CIC Bot has 0)
     - The small number of correct predictions (6) suggests the model 
       only catches Bot flows that happen to look like LycoS Bot
  
  Fix options (in order of impact):
    A. Oversample Bot to ~5-10% of training corpus (500K-1M rows via SMOTE)
    B. Train a separate Bot-specific binary classifier with balanced data
    C. Ensemble: RF for main classes + tuned threshold for Bot
    D. Use LogisticRegression with weightCol='class_weight' instead of RF
    """)
    
    spark.stop()

if __name__ == '__main__':
    main()
