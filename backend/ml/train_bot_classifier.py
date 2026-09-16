"""
train_bot_classifier.py  (Tier-2 Bot Specialist)
================================================
Trains a dedicated binary Random Forest for Bot vs not-Bot.

Why a separate classifier?
  The main RF sees 15.69M rows; Bot is ~1,400 of them (~0.009%).
  Even with class weights the signal is tiny relative to corpus noise.
  A focused 50/50 balanced classifier avoids this entirely.

Method
  1. Load Bot train rows from HDFS corpus (Label == 'Bot')
  2. Sample an equal number of BENIGN rows (balanced 50/50)
  3. Train RF with 100 trees, depth 12 (deeper = better minority recall)
  4. Save model to /threvia/models_clean/rf_bot_binary
  5. Evaluate on Bot test split (TEST-C1 Bot rows)

Output model is used as Tier-2: when main RF gives confidence < 0.80
on a flow, route to this classifier for a Bot-specific verdict.

Usage:
  docker exec threvia-spark-master spark-submit \
      --master spark://spark-master:7077 \
      --driver-memory 2g --executor-memory 2g \
      /workspace/backend/ml/train_bot_classifier.py
"""

import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import (
    BinaryClassificationEvaluator,
    MulticlassClassificationEvaluator,
)

# ── HDFS paths ──────────────────────────────────────────────────────────────
HDFS_CORPUS     = 'hdfs://namenode:8020/threvia/corpus/train'
HDFS_BOT_TEST   = 'hdfs://namenode:8020/threvia/corpus/friday_bot_test'
HDFS_MODEL_OUT  = 'hdfs://namenode:8020/threvia/models_clean/rf_bot_binary'

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
BOT_COL   = 'is_bot'      # 1 = Bot, 0 = not-Bot
SEED      = 42

# ── Spark ────────────────────────────────────────────────────────────────────
def get_spark():
    return (
        SparkSession.builder.appName('Threvia-BotClassifier')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.driver.memory', '2g')
        .config('spark.executor.memory', '2g')
        .config('spark.network.timeout', '600s')
        .getOrCreate()
    )

def sep(msg=''):
    print('\n' + '=' * 72 + (f'\n  {msg}\n' + '=' * 72 if msg else ''))

def bin_metrics(preds, label_col):
    be = BinaryClassificationEvaluator(labelCol=label_col, rawPredictionCol='rawPrediction')
    me = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol='prediction')
    return dict(
        auc  = be.setMetricName('areaUnderROC').evaluate(preds),
        acc  = me.setMetricName('accuracy').evaluate(preds),
        prec = me.setMetricName('weightedPrecision').evaluate(preds),
        rec  = me.setMetricName('weightedRecall').evaluate(preds),
        f1   = me.setMetricName('f1').evaluate(preds),
    )

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    # ── 1. Load corpus, separate Bot from not-Bot ───────────────────────────
    sep('1. Loading corpus and separating Bot rows')
    corpus = spark.read.parquet(HDFS_CORPUS)
    total  = corpus.count()
    print(f'  Total corpus rows : {total:,}')

    bot_rows    = corpus.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BOT')
    notbot_rows = corpus.filter(F.upper(F.trim(F.col(LABEL_COL))) != 'BOT')
    n_bot = bot_rows.count()
    print(f'  Bot rows          : {n_bot:,}')
    print(f'  Not-Bot rows      : {notbot_rows.count():,}')

    # ── 2. Build balanced 50/50 dataset ─────────────────────────────────────
    sep('2. Building balanced training set (Bot vs not-Bot 50/50)')
    # Sample equal number of not-Bot rows (BENIGN preferred — closest to Bot)
    # Fraction = n_bot / not-bot count, capped at 1.0
    notbot_count = notbot_rows.count()
    frac = min(1.0, float(n_bot) / float(notbot_count))
    notbot_sample = notbot_rows.sample(withReplacement=False, fraction=frac, seed=SEED)
    print(f'  Not-Bot sampled   : {notbot_sample.count():,}  (target {n_bot:,})')

    # Add binary target column
    bot_rows    = bot_rows.withColumn(BOT_COL,    F.lit(1))
    notbot_sample = notbot_sample.withColumn(BOT_COL, F.lit(0))

    balanced = bot_rows.unionByName(notbot_sample, allowMissingColumns=True)
    balanced = balanced.fillna(0, subset=[BOT_COL])
    n_balanced = balanced.count()
    print(f'  Balanced set size : {n_balanced:,}')
    balanced.groupBy(BOT_COL).count().show()

    # ── 3. Train Bot specialist RF ───────────────────────────────────────────
    sep('3. Training Bot binary RF (100 trees, depth 12)')
    rf = RandomForestClassifier(
        featuresCol=FEAT_COL,
        labelCol=BOT_COL,
        numTrees=100,
        maxDepth=12,
        seed=SEED,
        # No weightCol needed — dataset is already 50/50 balanced
        featureSubsetStrategy='sqrt',   # standard for classification
    )
    model = rf.fit(balanced)
    model.write().overwrite().save(HDFS_MODEL_OUT)
    print(f'  Bot classifier saved -> {HDFS_MODEL_OUT}')

    # ── 4. Evaluate on TEST-C1 Bot test split ────────────────────────────────
    sep('4. Evaluate on TEST-C1 Bot test split')
    bot_test = spark.read.parquet(HDFS_BOT_TEST)
    bot_test = bot_test.withColumn(
        BOT_COL,
        F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BOT', F.lit(1)).otherwise(F.lit(0))
    )
    n_test = bot_test.count()
    n_bot_test = bot_test.filter(F.col(BOT_COL) == 1).count()
    print(f'  Test rows: {n_test:,}  (Bot={n_bot_test:,}, not-Bot={n_test-n_bot_test:,})')

    preds = model.transform(bot_test)
    m = bin_metrics(preds, BOT_COL)

    sep('Bot Classifier Results')
    print(f"""
  Bot binary classifier (100 trees, depth 12, balanced 50/50)
  +----------+---------+
  | Metric   | Value   |
  +----------+---------+
  | AUC-ROC  | {m['auc']:.4f}  |
  | Accuracy | {m['acc']:.4f}  |
  | Precision| {m['prec']:.4f}  |
  | Recall   | {m['rec']:.4f}  |
  | F1       | {m['f1']:.4f}  |
  +----------+---------+

  Per-class breakdown (0=not-Bot, 1=Bot):""")
    preds.groupBy(BOT_COL, 'prediction').count().orderBy(BOT_COL, 'prediction').show()

    # Feature importances (top 15)
    sep('Top 15 features for Bot detection')
    from backend.processing.schema_maps import CANONICAL_FEATURE_COLS
    feat_names = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
    importances = sorted(
        enumerate(model.featureImportances.toArray()),
        key=lambda x: -x[1]
    )[:15]
    for idx, imp in importances:
        name = feat_names[idx] if idx < len(feat_names) else f'feat_{idx}'
        print(f'  {imp:.4f}  {name}')

    sep('DONE')
    print(f'  Model saved : {HDFS_MODEL_OUT}')
    print(f'  Bot recall  : {m["rec"]:.4f}  (was 0.0031 before)')
    spark.stop()


if __name__ == '__main__':
    main()
