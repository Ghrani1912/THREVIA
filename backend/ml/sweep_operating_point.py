"""
sweep_operating_point.py — P(attack) sweep for the retrained binary model
=========================================================================
The per-target-weight retrain removes the false-positive flood, but it is also
a *less aggressive* binary model than the old over-amplified one: on the
cross-source IDS2025 set the old model caught 87.9% of attacks at a 21% BENIGN
false-positive rate, while the retrained one catches fewer attacks at a much
lower FPR.  That is a trade, not a pure win, and it moves where the operating
point should sit.

This script prints the whole curve so the threshold can be chosen from data:
for each raw P(attack) cut it reports

  * C2  Friday BENIGN temporal holdout  -> false-positive rate
  * IDS2025 validation                  -> attack recall and BENIGN FPR
  * C1  session-split DDoS + Bot        -> DDoS and Bot recall

``backend/realtime/detection_policy.py`` currently defaults to 0.65.  Whatever
cut this sweep supports can be written to ``backend/realtime/thresholds.json``
(see backend/ml/calibrate_thresholds.py) or set via ML_THRESHOLD.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    MODELS_DIR=hdfs://namenode:8020/threvia/models_clean_v2 \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/sweep_operating_point.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel

from backend.processing.schema_maps import CANONICAL_FEATURE_COLS

HDFS_ROOT   = 'hdfs://namenode:8020/threvia'
BASE_MODELS = f'{HDFS_ROOT}/models_clean'
MODELS_DIR  = os.getenv('MODELS_DIR', f'{HDFS_ROOT}/models_clean_v2')

C1_DDOS = f'{HDFS_ROOT}/corpus/friday_ddos_test'
C1_BOT  = f'{HDFS_ROOT}/corpus/friday_bot_test'
C2_BEN  = f'{HDFS_ROOT}/corpus/friday_benign_c2'
IDS25   = f'{HDFS_ROOT}/validation/ids2025_validation.csv'

FEAT_COL   = 'scaled_features'
LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'

# Override with e.g. THRESHOLDS=0.2,0.25,0.3,0.35,0.4,0.45,0.5
THRESHOLDS = [
    float(x) for x in os.getenv(
        'THRESHOLDS', '0.50,0.55,0.60,0.65,0.70,0.75,0.80,0.85,0.90'
    ).split(',')
]


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-SweepOperatingPoint')
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

    from backend.processing.schema_maps import LABEL_NORMALISE
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.sql.types import StringType

    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    bc_map = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc_map.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    sep('Sweep configuration')
    print(f'  Models   : {MODELS_DIR}')
    print(f'  Baseline : scaler + medians from {BASE_MODELS}')
    print(f'  Cuts     : {THRESHOLDS}')

    pipe = PipelineModel.load(f'{BASE_MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{BASE_MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}
    rf = RandomForestClassificationModel.load(f'{MODELS_DIR}/rf_binary')

    def scored(df, name, text_col=LABEL_COL):
        out = clean_and_scale_external(spark, df, feat_cols, pipe, label_udf, fill_map=medians)
        out = out.withColumn(
            BINARY_COL,
            F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0)).otherwise(F.lit(1)))
        out = rf.transform(out)
        # `probability` is a sparse-vector UDT, so it has to be densified
        # before indexing; probability[1] == P(attack).
        from pyspark.ml.functions import vector_to_array
        out = out.withColumn('p_attack', vector_to_array(F.col('probability'))[1])
        out.cache()
        print(f'  {name}: {out.count():,} rows')
        return out

    sep('Scoring holdouts')
    c2 = scored(spark.read.parquet(C2_BEN), 'C2 Friday BENIGN (temporal)')
    c1 = scored(
        spark.read.parquet(C1_DDOS).unionByName(spark.read.parquet(C1_BOT),
                                                allowMissingColumns=True),
        'C1 DDoS + Bot (session split)')
    ids = scored(
        spark.read.option('header', True).option('inferSchema', False).csv(IDS25),
        'IDS2025 validation (cross-source)')

    n_c2 = c2.count()
    ids_ben = ids.filter(F.col(BINARY_COL) == 0)
    ids_atk = ids.filter(F.col(BINARY_COL) == 1)
    n_ids_ben = ids_ben.count()
    n_ids_atk = ids_atk.count()
    c1_ddos = c1.filter(F.col(LABEL_COL) == 'DDoS')
    c1_bot = c1.filter(F.col(LABEL_COL) == 'Bot')
    n_ddos, n_bot = c1_ddos.count(), c1_bot.count()

    print(f'\n  C2 rows           : {n_c2:,} (all BENIGN)')
    print(f'  IDS2025 BENIGN    : {n_ids_ben:,}')
    print(f'  IDS2025 attack    : {n_ids_atk:,}')
    print(f'  C1 DDoS / Bot     : {n_ddos:,} / {n_bot:,}')

    sep('THRESHOLD SWEEP — flag as attack when P(attack) >= T')
    print(f'  {"T":>5} | {"C2 FPR":>8} | {"IDS atk rec":>11} | {"IDS BEN FPR":>11} | '
          f'{"DDoS rec":>9} | {"Bot rec":>8} | {"IDS F1(attack)":>14}')
    print('  ' + '-' * 82)

    rows_out = []
    for t in THRESHOLDS:
        c2_fp = c2.filter(F.col('p_attack') >= t).count()
        c2_fpr = c2_fp / n_c2 if n_c2 else 0.0

        ids_tp = ids_atk.filter(F.col('p_attack') >= t).count()
        ids_fp = ids_ben.filter(F.col('p_attack') >= t).count()
        atk_rec = ids_tp / n_ids_atk if n_ids_atk else 0.0
        ben_fpr = ids_fp / n_ids_ben if n_ids_ben else 0.0
        prec = ids_tp / (ids_tp + ids_fp) if (ids_tp + ids_fp) else 0.0
        f1 = 2 * prec * atk_rec / (prec + atk_rec) if (prec + atk_rec) else 0.0

        ddos_rec = c1_ddos.filter(F.col('p_attack') >= t).count() / n_ddos if n_ddos else 0.0
        bot_rec = c1_bot.filter(F.col('p_attack') >= t).count() / n_bot if n_bot else 0.0

        print(f'  {t:>5.2f} | {c2_fpr * 100:>7.2f}% | {atk_rec * 100:>10.2f}% | '
              f'{ben_fpr * 100:>10.2f}% | {ddos_rec * 100:>8.2f}% | {bot_rec * 100:>7.2f}% | '
              f'{f1:>14.4f}')
        rows_out.append(dict(T=t, c2_fpr=c2_fpr, ids_attack_recall=atk_rec,
                             ids_benign_fpr=ben_fpr, ids_attack_f1=f1,
                             ddos_recall=ddos_rec, bot_recall=bot_rec))

    sep('Reading the curve')
    cur = next((r for r in rows_out if abs(r['T'] - 0.65) < 1e-9), None)
    if cur:
        print(f'  At the current default T=0.65 (models = {MODELS_DIR}):')
        print(f'    C2 temporal FPR      : {cur["c2_fpr"] * 100:.2f}%')
        print(f'    IDS2025 attack recall: {cur["ids_attack_recall"] * 100:.2f}%')
        print(f'    IDS2025 BENIGN FPR   : {cur["ids_benign_fpr"] * 100:.2f}%')
        print(f'    DDoS / Bot recall    : {cur["ddos_recall"] * 100:.2f}% / {cur["bot_recall"] * 100:.2f}%')
    print('\n  Pick the lowest T whose C2 FPR is still acceptable; recall on the')
    print('  cross-source set falls steeply below ~0.60.')

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
