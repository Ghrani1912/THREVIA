"""
train_infiltration_classifier.py  (Tier-2b Infiltration Specialist)
===================================================================
Trains a dedicated binary Random Forest for Infiltration vs BENIGN, the
same way ``train_bot_classifier.py`` does for Bot.

Why a specialist instead of a bigger class weight
-------------------------------------------------
The Tier-1 multiclass RF has to separate 14 classes at once, and Infiltration
sits on top of BENIGN in feature space: CICIDS2018 Infiltration is a slow,
low-rate, long-duration data-transfer pattern, and so is a lot of legitimate
BENIGN traffic (idle SSH, heartbeats, keep-alives).  In a 15.69M-row corpus the
class carries only a 6.9x inverse-frequency weight, which is not enough to
carve out that boundary while 12 other classes compete for the same splits.

The Bot path is the precedent that this works: Bot carried a comparable 11.5x
weight in the multiclass model (0.31% recall unweighted, ~65% weighted) but a
focused 50/50 specialist took it to near-total recall -- see
``documentation/FINAL_MODEL_EVALUATION.md``.

The negative class is chosen as BENIGN (not "any non-Infiltration row"),
because the deployment question this model answers is exactly the one
``backend/ml/infiltration_rules.py`` answers today: *a flow the Tier-1 model
called BENIGN -- is it actually Infiltration?*

Evaluation is deliberately the hard one
---------------------------------------
The model is trained on CICIDS2018 Infiltration and evaluated on the CIC-2017
Thursday Afternoon Infiltration capture: different year, different environment,
different tooling.  That cross-dataset number is the one the existing docs
report (68.97%), so the comparison is like-for-like.  The script reports, on
the identical preprocessed holdout:

  * the specialist's Infiltration recall and BENIGN false-positive rate
  * the Tier-1 multiclass model's Infiltration recall
  * the Tier-3 rule detector's Infiltration recall

so it is visible whether the specialist actually beats what is already there.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    MODELS_OUT=hdfs://namenode:8020/threvia/models_clean_v2 \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/train_infiltration_classifier.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassifier, RandomForestClassificationModel

from backend.processing.schema_maps import CANONICAL_FEATURE_COLS

# ── HDFS paths ────────────────────────────────────────────────────────────────
HDFS_ROOT       = 'hdfs://namenode:8020/threvia'
HDFS_TRAIN      = f'{HDFS_ROOT}/corpus/train'
HDFS_MODELS     = f'{HDFS_ROOT}/models_clean'
HDFS_MODELS_OUT = os.getenv('MODELS_OUT', f'{HDFS_ROOT}/models_clean_v2')
LOCAL_CIC17_INFIL = ('file:///workspace/backend/data/CIC-IDS- 2017/'
                     'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv')

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
MULTI_COL = 'attack_type_idx'
INFIL_COL = 'is_infiltration'

SEED       = 42
NUM_TREES  = 100
MAX_DEPTH  = 12

# Raw CIC-2017 column name -> canonical, only where the source file differs.
RAW_ALIASES = {
    'Fwd Header Length.1': 'Fwd Header Length',
}


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-InfiltrationSpecialist')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def bin_metrics(preds, label_col):
    from pyspark.ml.evaluation import (
        BinaryClassificationEvaluator, MulticlassClassificationEvaluator)
    be = BinaryClassificationEvaluator(labelCol=label_col, rawPredictionCol='rawPrediction')
    me = MulticlassClassificationEvaluator(labelCol=label_col, predictionCol='prediction')
    return dict(
        auc=be.setMetricName('areaUnderROC').evaluate(preds),
        acc=me.setMetricName('accuracy').evaluate(preds),
        prec=me.setMetricName('weightedPrecision').evaluate(preds),
        rec=me.setMetricName('weightedRecall').evaluate(preds),
        f1=me.setMetricName('f1').evaluate(preds),
    )


def load_cic17_infiltration(spark, feat_cols, ext_pipe_model, label_udf, medians):
    """Read the CIC-2017 Thursday capture and put it through the SAME
    cleaning + log1p + saved-scaler path the training corpus used."""
    from backend.ml.train_clean_corpus import clean_and_scale_external

    raw = spark.read.option('header', True).option('inferSchema', False).csv(LOCAL_CIC17_INFIL)

    # CIC-2017 CSVs carry leading/trailing spaces in column names.
    for c in raw.columns:
        stripped = c.strip()
        if stripped != c:
            raw = raw.withColumnRenamed(c, stripped)
    for src, dst in RAW_ALIASES.items():
        if src in raw.columns and dst not in raw.columns:
            raw = raw.withColumnRenamed(src, dst)

    print(f'  Raw rows in file: {raw.count():,}')
    print('  Raw label distribution:')
    raw.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(10, truncate=False)

    keep = raw.filter(
        F.upper(F.trim(F.col(LABEL_COL))).isin(
            ['INFILTRATION', 'INFILTERATION', 'BENIGN'])
    )
    n_infil = keep.filter(
        F.upper(F.trim(F.col(LABEL_COL))).isin(['INFILTRATION', 'INFILTERATION'])
    ).count()
    n_benign = keep.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN').count()
    print(f'  Infiltration rows: {n_infil:,}')
    print(f'  BENIGN rows      : {n_benign:,}')

    # Collapse the CICIDS2018 spelling variant to one canonical name.
    keep = keep.withColumn(
        LABEL_COL,
        F.when(F.upper(F.col(LABEL_COL)).contains('INFIL'), F.lit('Infiltration'))
         .otherwise(F.col(LABEL_COL)),
    )

    df = clean_and_scale_external(
        spark, keep, feat_cols, ext_pipe_model, label_udf, fill_map=medians)
    df = df.withColumn(
        INFIL_COL,
        F.when(F.col(LABEL_COL) == 'Infiltration', F.lit(1)).otherwise(F.lit(0)),
    )
    df.cache()
    return df, n_infil, n_benign


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('ERROR')

    sep('THREVIA — Infiltration Specialist (Tier-2b)')
    print(f'  Training corpus : {HDFS_TRAIN}')
    print(f'  Model output    : {HDFS_MODELS_OUT}')
    print(f'  Cross-dataset holdout : CIC-2017 Thursday Afternoon Infiltration')

    from backend.processing.schema_maps import LABEL_NORMALISE
    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc_map = spark.sparkContext.broadcast(norm_map)
    from pyspark.sql.types import StringType
    label_udf = F.udf(
        lambda raw: bc_map.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    ext_pipe_model = PipelineModel.load(f'{HDFS_MODELS}/scaler_pipeline')
    try:
        med_row = spark.read.parquet(f'{HDFS_MODELS}/imputer_medians').first()
        medians = dict(med_row.asDict()) if med_row else {}
    except Exception as e:
        print(f'  WARNING: imputer medians unavailable ({e}); falling back to 0.0')
        medians = {}
    print(f'  Scaler pipeline + {len(medians)} imputer medians loaded.')

    # ── 1. Build the balanced 50/50 training set ──────────────────────────────
    sep('1. Building balanced training set (Infiltration vs BENIGN)')
    corpus = spark.read.parquet(HDFS_TRAIN)
    infil_rows = corpus.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'INFILTRATION')
    benign_rows = corpus.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN')

    n_infil_train = infil_rows.count()
    n_benign_pool = benign_rows.count()
    print(f'  Infiltration rows in corpus : {n_infil_train:,}')
    print(f'  BENIGN pool                 : {n_benign_pool:,}')

    frac = min(1.0, float(n_infil_train) / float(n_benign_pool))
    benign_sample = benign_rows.sample(withReplacement=False, fraction=frac, seed=SEED)

    balanced = (
        infil_rows.withColumn(INFIL_COL, F.lit(1))
        .unionByName(benign_sample.withColumn(INFIL_COL, F.lit(0)),
                     allowMissingColumns=True)
        .fillna(0, subset=[INFIL_COL])
    )
    balanced.cache()
    print(f'  Balanced set size : {balanced.count():,}')
    balanced.groupBy(INFIL_COL).count().orderBy(INFIL_COL).show()

    # ── 2. Train ──────────────────────────────────────────────────────────────
    sep(f'2. Training Infiltration RF ({NUM_TREES} trees, depth {MAX_DEPTH})')
    rf = RandomForestClassifier(
        featuresCol=FEAT_COL,
        labelCol=INFIL_COL,
        numTrees=NUM_TREES,
        maxDepth=MAX_DEPTH,
        seed=SEED,
        featureSubsetStrategy='sqrt',
    )
    model = rf.fit(balanced)
    out_path = f'{HDFS_MODELS_OUT}/rf_infiltration_binary'
    model.write().overwrite().save(out_path)
    print(f'  Saved -> {out_path}')

    # ── 3. Cross-dataset evaluation on CIC-2017 Thursday ──────────────────────
    sep('3. Cross-dataset holdout — CIC-2017 Thursday Afternoon')
    test, n_infil, n_benign = load_cic17_infiltration(
        spark, feat_cols, ext_pipe_model, label_udf, medians)

    preds = model.transform(test)
    m = bin_metrics(preds, INFIL_COL)
    tp = preds.filter((F.col(INFIL_COL) == 1) & (F.col('prediction') == 1.0)).count()
    fp = preds.filter((F.col(INFIL_COL) == 0) & (F.col('prediction') == 1.0)).count()
    specialist_recall = tp / n_infil if n_infil else 0.0
    specialist_fpr = fp / n_benign if n_benign else 0.0

    print(f'\n  Specialist (rf_infiltration_binary):')
    print(f'    AUC-ROC              : {m["auc"]:.4f}')
    print(f'    Accuracy             : {m["acc"]:.4f}')
    print(f'    Infiltration recall  : {specialist_recall:.4f}  ({tp:,}/{n_infil:,})')
    print(f'    BENIGN false-positive: {specialist_fpr:.4f}  ({fp:,}/{n_benign:,})')

    # ── 4. Same holdout through the existing detectors, for comparison ────────
    sep('4. Baseline comparison on the identical holdout')

    label_map_df = spark.read.parquet(f'{HDFS_MODELS}/label_index_map')
    idx_to_label = {int(r['idx']): r['label'] for r in label_map_df.collect()}
    infil_idx = [i for i, v in idx_to_label.items() if v == 'Infiltration']
    infil_idx = infil_idx[0] if infil_idx else None

    multi_recall = None
    if infil_idx is not None:
        multi_model = RandomForestClassificationModel.load(f'{HDFS_MODELS}/rf_multiclass')
        mp = multi_model.transform(test)
        mtp = mp.filter((F.col(INFIL_COL) == 1) & (F.col('prediction') == float(infil_idx))).count()
        multi_recall = mtp / n_infil if n_infil else 0.0
        print(f'  Tier-1 multiclass RF Infiltration recall : {multi_recall:.4f}  ({mtp:,}/{n_infil:,})')
    else:
        print('  Tier-1 multiclass RF: no Infiltration index in label_index_map')

    try:
        from backend.ml.infiltration_rules import apply_infiltration_rules
        ruled = apply_infiltration_rules(test)
        rtp = ruled.filter((F.col(INFIL_COL) == 1) & (F.col('rule_infiltration') == 1)).count()
        rfp = ruled.filter((F.col(INFIL_COL) == 0) & (F.col('rule_infiltration') == 1)).count()
        rule_recall = rtp / n_infil if n_infil else 0.0
        rule_fpr = rfp / n_benign if n_benign else 0.0
        print(f'  Tier-3 rule detector recall             : {rule_recall:.4f}  ({rtp:,}/{n_infil:,})')
        print(f'  Tier-3 rule detector BENIGN FP rate     : {rule_fpr:.4f}  ({rfp:,}/{n_benign:,})')
    except Exception as e:
        print(f'  Tier-3 rules could not be evaluated: {e}')

    # ── 5. Verdict ────────────────────────────────────────────────────────────
    sep('VERDICT')
    best_baseline = max([x for x in (multi_recall,) if x is not None], default=0.0)
    delta = specialist_recall - best_baseline
    print(f'  Specialist recall : {specialist_recall:.4f}')
    print(f'  Tier-1 recall     : {best_baseline:.4f}')
    print(f'  Delta             : {delta:+.4f}')
    if delta > 0.02:
        print('  => Specialist IMPROVES Infiltration recall. Worth routing.')
    elif delta > -0.02:
        print('  => No meaningful change. The domain shift, not the model shape, is binding.')
    else:
        print('  => Specialist is WORSE. Do not promote; keep the existing path.')

    # Feature importances
    sep('Top 12 features for Infiltration')
    feat_names = feat_cols
    for i, imp in sorted(enumerate(model.featureImportances.toArray()), key=lambda x: -x[1])[:12]:
        print(f'  {imp:.4f}  {feat_names[i] if i < len(feat_names) else f"feat_{i}"}')

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
