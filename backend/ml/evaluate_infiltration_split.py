"""
evaluate_infiltration_split.py — Step 5b: score detectors on the real split
===========================================================================
Evaluates, on the temporal held-out Infiltration split built by
``build_infiltration_split.py`` (67,464 rows after de-leaking):

  * Tier-1 multiclass RF   — how often the 14-way model *names* Infiltration
  * Tier-2b specialist      — rf_infiltration_binary (Bot-style 50/50 RF)
  * Tier-3 rule detector    — infiltration_rules.apply_infiltration_rules

Each is scored for recall on the held-out Infiltration rows and false-positive
rate on the Friday BENIGN temporal holdout (the same BENIGN rows used
throughout, so FP rates are comparable across this report).

Note on the specialist: it was trained on Infiltration rows sampled from the
TRAINING corpus, which includes the early (Feb 28) side of this temporal split.
Its number here is therefore still optimistic — but the split is temporal, so
it cannot have seen the test rows' capture window, and the 4,558-row hash
de-leak removes the exact duplicates.  Treat it as an upper bound.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 4g \
    /workspace/backend/ml/evaluate_infiltration_split.py"
"""

import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel

HDFS_ROOT  = 'hdfs://namenode:8020/threvia'
MODELS     = f'{HDFS_ROOT}/models_clean'
V2         = f'{HDFS_ROOT}/models_clean_v2'
INFIL_TEST = f'{HDFS_ROOT}/corpus/infiltration_test'
BENIGN_C2  = f'{HDFS_ROOT}/corpus/friday_benign_c2'

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
MULTI_COL = 'attack_type_idx'


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-EvalInfiltrationSplit')
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

    from backend.processing.schema_maps import LABEL_NORMALISE, CANONICAL_FEATURE_COLS
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from backend.ml.infiltration_rules import apply_infiltration_rules
    from pyspark.sql.types import StringType

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    pipe = PipelineModel.load(f'{MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}
    lm_df = spark.read.parquet(f'{MODELS}/label_index_map')
    idx_to_label = {int(r['idx']): r['label'] for r in lm_df.collect()}
    infil_idx = [i for i, v in idx_to_label.items() if v == 'Infiltration'][0]

    sep('Scoring the held-out Infiltration split')
    infil_test = spark.read.parquet(INFIL_TEST)
    infil_scaled = clean_and_scale_external(
        spark, infil_test, feat_cols, pipe, label_udf, fill_map=medians).cache()
    n_infil = infil_scaled.count()
    print(f'  Held-out Infiltration rows: {n_infil:,}')

    sep('Scoring the BENIGN holdout (FP measurement)')
    benign = spark.read.parquet(BENIGN_C2)
    benign_scaled = clean_and_scale_external(
        spark, benign, feat_cols, pipe, label_udf, fill_map=medians).cache()
    n_ben = benign_scaled.count()
    print(f'  BENIGN rows: {n_ben:,}')

    # ── Tier-1 multiclass ──────────────────────────────────────────────────────
    sep('Tier-1 multiclass RF')
    multi = RandomForestClassificationModel.load(f'{MODELS}/rf_multiclass')
    mp = multi.transform(infil_scaled)
    tp = mp.filter(F.col('prediction') == float(infil_idx)).count()
    print(f'  Infiltration recall: {tp / n_infil * 100:.2f}%  ({tp:,}/{n_infil:,})')
    print('  What the misses were labelled as:')
    misses = mp.filter(F.col('prediction') != float(infil_idx)).groupBy('prediction').count() \
        .orderBy(F.desc('count'))
    miss_rows = misses.collect()
    for r in miss_rows[:6]:
        name = idx_to_label.get(int(r['prediction']), f'idx_{r["prediction"]}')
        print(f'    {name:<28} {r["count"]:>8,}')

    mp_ben = multi.transform(benign_scaled)
    fp = mp_ben.filter(F.col('prediction') == float(infil_idx)).count()
    print(f'  BENIGN predicted as Infiltration: {fp:,}/{n_ben:,} = {fp / n_ben * 100:.3f}%')

    # ── Tier-2b specialist ─────────────────────────────────────────────────────
    sep('Tier-2b specialist (rf_infiltration_binary)')
    try:
        spec = RandomForestClassificationModel.load(f'{V2}/rf_infiltration_binary')
        sp = spec.transform(infil_scaled)
        stp = sp.filter(F.col('prediction') == 1.0).count()
        print(f'  Infiltration recall: {stp / n_infil * 100:.2f}%  ({stp:,}/{n_infil:,})')
        sp_ben = spec.transform(benign_scaled)
        sfp = sp_ben.filter(F.col('prediction') == 1.0).count()
        print(f'  BENIGN FP: {sfp:,}/{n_ben:,} = {sfp / n_ben * 100:.3f}%')
    except Exception as exc:
        print(f'  Specialist unavailable: {exc}')

    # ── Tier-3 rules ───────────────────────────────────────────────────────────
    sep('Tier-3 rule detector')
    ruled = apply_infiltration_rules(infil_scaled)
    rtp = ruled.filter(F.col('rule_infiltration') == 1).count()
    print(f'  Infiltration recall: {rtp / n_infil * 100:.2f}%  ({rtp:,}/{n_infil:,})')
    ruled_ben = apply_infiltration_rules(benign_scaled)
    rfp = ruled_ben.filter(F.col('rule_infiltration') == 1).count()
    print(f'  BENIGN FP: {rfp:,}/{n_ben:,} = {rfp / n_ben * 100:.3f}%')

    sep('DONE')
    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
