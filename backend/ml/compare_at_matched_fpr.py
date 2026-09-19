"""
compare_at_matched_fpr.py — honest v1-vs-v3 comparison
======================================================
The earlier v1-vs-v2 comparison was confounded: it compared the two models at a
fixed P(attack) cut, but the retrain had *rescaled* the scores, so the same cut
sits at a different false-positive rate for each model.  "v2 catches fewer
attacks at T=0.65" then mostly measured the rescaling, not discrimination.

This script compares arbitrary model directories at MATCHED FALSE-POSITIVE RATES.
For each model it finds the cut T that puts the clean Friday BENIGN temporal
holdout (C2) at a requested FPR, then reports every other metric at that same
FPR.  A difference in recall at matched FPR is real discrimination; a difference
at a fixed cut is not.

Model selection uses the BINARY (is_attack) model, because that is the gate the
detector actually alerts on, and per-class recall is read off the label column
rather than the multiclass head so no StringIndexer is needed.

Holdouts:

  C2  friday_benign_c2        286,785 BENIGN, temporal, 0% overlap with training
  DDOS19  corpus/ddos2019_test  CIC-DDoS2019 testing split — different year and
                                attack tooling, never in training.  THE clean
                                cross-environment probe.
  IDS25 validation/ids2025      CONTAMINATED: 86.9% of its PortScan rows and
                                63.9% of its Bot rows are the same physical
                                flows as training.  Kept only so numbers stay
                                comparable with the older documents.
  C1  friday_ddos_test + friday_bot_test   session-split, zero training overlap
  PS  corpus/portscan_test     port-grouped split

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    MODELS='v1:hdfs://namenode:8020/threvia/models_clean,v3:hdfs://namenode:8020/threvia/models_clean_v3' \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/compare_at_matched_fpr.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.functions import vector_to_array

HDFS_ROOT   = 'hdfs://namenode:8020/threvia'
BASE_MODELS = f'{HDFS_ROOT}/models_clean'

DEFAULT_MODELS = (
    f'v1:{HDFS_ROOT}/models_clean,'
    f'v3:{HDFS_ROOT}/models_clean_v3'
)
MODELS_SPEC = os.getenv('MODELS', DEFAULT_MODELS)

C1_DDOS   = f'{HDFS_ROOT}/corpus/friday_ddos_test'
C1_BOT    = f'{HDFS_ROOT}/corpus/friday_bot_test'
C2_BEN    = f'{HDFS_ROOT}/corpus/friday_benign_c2'
DDOS19    = f'{HDFS_ROOT}/corpus/ddos2019_test'
PS_TEST   = f'{HDFS_ROOT}/corpus/portscan_test'
IDS25     = f'{HDFS_ROOT}/validation/ids2025_validation.csv'

FEAT_COL   = 'scaled_features'
LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'

TARGET_FPRS = [float(x) for x in
               os.getenv('TARGET_FPRS', '0.05,0.01,0.005,0.0025').split(',')]

# Classes to report recall for, per holdout.
REPORT_CLASSES = {
    'C1': ['DDoS', 'Bot'],
    'IDS25': ['Brute Force', 'DoS/DDoS', 'PortScan', 'Bot',
              'Web Attack - Brute Force'],
    'DDOS19': ['DDoS'],
    'PS': ['PortScan'],
}


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-CompareMatchedFPR')
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

    from backend.processing.schema_maps import (
        CANONICAL_FEATURE_COLS, LABEL_NORMALISE, label_lookup_key)
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.sql.types import StringType

    norm_map = {label_lookup_key(k): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    label_udf = F.udf(
        lambda raw: bc.value.get(label_lookup_key(raw), raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    versions = []
    for item in MODELS_SPEC.split(','):
        name, path = item.split(':', 1)
        versions.append((name.strip(), path.strip()))

    sep('Configuration')
    print(f'  scaler + medians  : {BASE_MODELS}')
    for n, p in versions:
        print(f'  {n:<18}: {p}')
    print(f'  matched FPR targets: {TARGET_FPRS}')

    pipe = PipelineModel.load(f'{BASE_MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{BASE_MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}

    # ── prep holdouts once ────────────────────────────────────────────────────
    sep('Preparing holdouts (once, shared by every version)')

    def prep(df, name):
        if FEAT_COL in df.columns:
            out = df
            print(f'  {name}: pre-scaled, using as-is')
        else:
            out = clean_and_scale_external(spark, df, feat_cols, pipe, label_udf,
                                           fill_map=medians)
            print(f'  {name}: cleaned + scaled')
        return out.cache()

    hold = {}
    hold['C2'] = prep(spark.read.parquet(C2_BEN), 'C2 Friday BENIGN (temporal)')
    hold['DDOS19'] = prep(spark.read.parquet(DDOS19), 'CIC-DDoS2019 testing (cross-env)')
    hold['C1'] = prep(
        spark.read.parquet(C1_DDOS).unionByName(spark.read.parquet(C1_BOT),
                                               allowMissingColumns=True),
        'C1 DDoS + Bot (session split)')
    hold['PS'] = prep(spark.read.parquet(PS_TEST), 'PortScan held-out')
    hold['IDS25'] = prep(
        spark.read.option('header', True).option('inferSchema', False).csv(IDS25),
        'IDS2025 validation (CONTAMINATED)')

    for k, df in hold.items():
        n = df.count()
        by_label = df.groupBy(LABEL_COL).count().orderBy(F.desc('count')).collect()
        print(f'  {k} rows: {n:,}  [' +
              ', '.join(f'{r[LABEL_COL]}={r["count"]:,}' for r in by_label[:6]) + ']')

    def scored(df, model, name):
        if BINARY_COL not in df.columns:
            df = df.withColumn(
                BINARY_COL,
                F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0))
                 .otherwise(F.lit(1)))
        # Keep ONLY the scored columns.  Caching the transformed frame would
        # retain both 77-wide dense vectors per row for every holdout and every
        # model, which is what made the executor exit 137 repeatedly.
        out = (model.transform(df)
               .withColumn('p_attack', vector_to_array(F.col('probability'))[1])
               .select(LABEL_COL, BINARY_COL, 'p_attack', 'rawPrediction'))
        return out.cache()

    # ── score each version ────────────────────────────────────────────────────
    all_scores = {}
    for name, vdir in versions:
        sep(f'Scoring {name}  ({vdir})')
        try:
            rf_bin = RandomForestClassificationModel.load(f'{vdir}/rf_binary')
        except Exception as exc:
            print(f'  SKIP — {exc}')
            continue
        all_scores[name] = {k: scored(df, rf_bin, k) for k, df in hold.items()}
        print('  scored all holdouts')

    if len(all_scores) < 2:
        print('Need at least two scorable versions.')
        spark.stop()
        sys.exit(1)

    names = list(all_scores.keys())

    # ── threshold-free discrimination ───────────────────────────────────────
    # Matched FPR on ONE anchor is not enough: two models can sit at the same C2
    # FPR while having different score SHAPES, so their false-positive rates on a
    # different BENIGN population diverge.  AUC is immune to both the cut and the
    # calibration, so it is the honest "did discrimination improve" number.
    sep('THRESHOLD-FREE DISCRIMINATION (ROC-AUC)')
    aucs = {}
    for name in names:
        row = {}
        for key in ['DDOS19', 'IDS25']:
            df = all_scores[name][key]
            if BINARY_COL not in df.columns:
                df = df.withColumn(
                    BINARY_COL,
                    F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0))
                     .otherwise(F.lit(1)))
            ev = BinaryClassificationEvaluator(
                labelCol=BINARY_COL, rawPredictionCol='rawPrediction',
                metricName='areaUnderROC')
            row[key] = ev.evaluate(df)
        aucs[name] = row
    print(f'  {"holdout":<26}' + ''.join(f'{n:>12}' for n in names))
    print('  ' + '-' * (26 + 12 * len(names)))
    for key, label in [('DDOS19', 'CIC-DDoS2019 (CLEAN)'),
                       ('IDS25', 'IDS2025 (contaminated)')]:
        line = f'  {label:<26}'
        for n in names:
            line += f'{aucs[n][key]:>12.4f}'
        best = max(names, key=lambda n: aucs[n][key])
        print(line + f'   best: {best}')

    # ── matched-FPR table ────────────────────────────────────────────────────
    sep('MATCHED-FALSE-POSITIVE-RATE COMPARISON')
    print('  A cut T is chosen per model so that C2 (clean temporal BENIGN) sits')
    print('  at the target FPR; every other number is read at that same FPR.')

    summary = {}
    for target in TARGET_FPRS:
        print(f'\n  ---- target C2 FPR = {target * 100:.2f}% ----')
        hdr = f'  {"metric":<40}' + ''.join(f'{n:>13}' for n in names)
        print(hdr)
        print('  ' + '-' * (40 + 13 * len(names)))

        per_model = {}
        for name in names:
            c2 = all_scores[name]['C2']
            t = c2.approxQuantile('p_attack', [1.0 - target], 0.0005)[0]
            n_c2 = c2.count()
            fp = c2.filter(F.col('p_attack') >= t).count()
            per_model[name] = dict(T=t, c2_fp=fp, c2_n=n_c2,
                                   c2_fpr=fp / n_c2 if n_c2 else 0.0)

        line = f'  {"C2 FPR achieved":<40}'
        for name in names:
            line += f'{per_model[name]["c2_fpr"] * 100:>12.2f}%'
        print(line)
        line = f'  {"cut T (P(attack))":<40}'
        for name in names:
            line += f'{per_model[name]["T"]:>13.3f}'
        print(line)

        for key in ['DDOS19', 'IDS25', 'C1', 'PS']:
            for cls in REPORT_CLASSES[key]:
                line = f'  {"recall " + cls + " [" + key + "]":<40}'
                for name in names:
                    df = all_scores[name][key]
                    t = per_model[name]['T']
                    sub = df.filter(F.col(LABEL_COL) == cls)
                    n = sub.count()
                    hit = sub.filter(F.col('p_attack') >= t).count()
                    line += f'{(hit / n * 100 if n else 0.0):>12.2f}%'
                    per_model[name].setdefault('recall', {})[(key, cls)] = (
                        hit / n if n else 0.0, n)
                print(line)

            # BENIGN FPR on this holdout, at the same matched cut
            line = f'  {"BENIGN FPR [" + key + "]":<40}'
            for name in names:
                df = all_scores[name][key]
                t = per_model[name]['T']
                sub = df.filter(F.col(LABEL_COL) == 'BENIGN')
                n = sub.count()
                fp = sub.filter(F.col('p_attack') >= t).count()
                line += f'{(fp / n * 100 if n else 0.0):>12.2f}%'
                per_model[name].setdefault('ben_fpr', {})[key] = (fp / n if n else 0.0, n)
            print(line)

        summary[target] = per_model

    # ── verdict at the strictest matched FPR ─────────────────────────────────
    sep('AREA-UNDER-CURVE style read: recall at the strictest matched FPR')
    strict = TARGET_FPRS[-1]
    pm = summary[strict]
    for key in ['DDOS19', 'IDS25']:
        for cls in REPORT_CLASSES[key]:
            vals = {n: pm[n]['recall'][(key, cls)][0] for n in names}
            best = max(vals, key=lambda k: vals[k])
            print(f'  {cls + " [" + key + "]":<34}' +
                  '   '.join(f'{n}={vals[n] * 100:.2f}%' for n in names) +
                  f'   -> best: {best}')

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
