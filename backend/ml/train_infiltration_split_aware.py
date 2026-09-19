"""
train_infiltration_split_aware.py — Step 5c: leak-free specialist measurement
=============================================================================
``evaluate_infiltration_split.py`` scored the *deployed* v1 models on the new
temporal Infiltration split, but those models trained on ALL 161,934 CICIDS2018
Infiltration rows — so their 99.97% recall there is an in-sample upper bound.

This script closes that gap:

  1. Trains the Bot-style 50/50 Infiltration specialist on the EARLY side of
     the temporal split only (``corpus/infiltration_train``) + a BENIGN sample
     from the training corpus.
  2. Evaluates it on the LATE, de-leaked side (``corpus/infiltration_test``,
     67,464 rows) — rows captured after every training row, with
     feature-hash duplicates of the training side removed.
  3. Reports Tier-3 rule recall/FPR on the same test side for context.

This produces the first statistically meaningful, leak-free Infiltration
generalisation number in the project (vs the previous 29/36-row supports).

Output model: {MODELS_OUT}/rf_infiltration_splitaware  (non-destructive)

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \\
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 4g \\
    /workspace/backend/ml/train_infiltration_split_aware.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassifier

HDFS_ROOT   = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN  = f'{HDFS_ROOT}/corpus/infiltration_train'   # temporal early side
HDFS_TEST   = f'{HDFS_ROOT}/corpus/infiltration_test'    # temporal late side, de-leaked
HDFS_CORPUS = f'{HDFS_ROOT}/corpus/train'                # BENIGN pool for balancing
MODELS      = f'{HDFS_ROOT}/models_clean'
MODELS_OUT  = os.getenv('MODELS_OUT', f'{HDFS_ROOT}/models_clean_v2')

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
INFIL_COL = 'is_infiltration'
SEED      = 42
NUM_TREES = 100
MAX_DEPTH = 12


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-InfilSplitAware')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('ERROR')

    from backend.processing.schema_maps import CANONICAL_FEATURE_COLS, LABEL_NORMALISE
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.sql.types import StringType

    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )

    pipe = PipelineModel.load(f'{MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}

    sep('1. Build the balanced 50/50 training set (EARLY side only)')
    infil_train = spark.read.parquet(HDFS_TRAIN)
    n_infil = infil_train.count()
    print(f'  Infiltration train rows (temporal early side): {n_infil:,}')

    corpus = spark.read.parquet(HDFS_CORPUS)
    benign_pool = corpus.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN')
    frac = min(1.0, float(n_infil) / max(benign_pool.count(), 1))
    benign_sample = benign_pool.sample(False, frac, seed=SEED)

    train_bal = (
        infil_train.withColumn(INFIL_COL, F.lit(1))
        .unionByName(benign_sample.withColumn(INFIL_COL, F.lit(0)),
                     allowMissingColumns=True)
        .fillna(0, subset=[INFIL_COL])
        # The corpus BENIGN pool carries helper columns (raw_features etc.)
        # that collide with the scaler pipeline's outputs — keep only what the
        # feature path needs.
        .select(*feat_cols, LABEL_COL, INFIL_COL)
    )
    train_scaled = clean_and_scale_external(
        spark, train_bal, feat_cols, pipe, label_udf, fill_map=medians).cache()
    n_train = train_scaled.count()
    print(f'  Balanced training set: {n_train:,}')

    sep(f'2. Train specialist RF ({NUM_TREES} trees, depth {MAX_DEPTH})')
    rf = RandomForestClassifier(
        featuresCol=FEAT_COL, labelCol=INFIL_COL,
        numTrees=NUM_TREES, maxDepth=MAX_DEPTH,
        seed=SEED, featureSubsetStrategy='sqrt',
    )
    model = rf.fit(train_scaled)
    out_path = f'{MODELS_OUT}/rf_infiltration_splitaware'
    model.write().overwrite().save(out_path)
    print(f'  Saved -> {out_path}')

    sep('3. Evaluate on the LATE, de-leaked temporal side (genuine holdout)')
    infil_test = spark.read.parquet(HDFS_TEST)
    n_test = infil_test.count()
    test_scaled = clean_and_scale_external(
        spark, infil_test, feat_cols, pipe, label_udf, fill_map=medians).cache()
    print(f'  Held-out rows: {n_test:,}')

    tp = model.transform(test_scaled) \
        .filter(F.col('prediction') == 1.0).count()   # every test row IS Infiltration
    print(f'  Specialist recall (LEAK-FREE): {tp / n_test * 100:.2f}%  ({tp:,}/{n_test:,})')

    sep('4. Tier-3 rules on the same holdout (context)')
    from backend.ml.infiltration_rules import apply_infiltration_rules
    ruled = apply_infiltration_rules(test_scaled)
    rtp = ruled.filter(F.col('rule_infiltration') == 1).count()
    print(f'  Tier-3 recall: {rtp / n_test * 100:.2f}%  ({rtp:,}/{n_test:,})')

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
