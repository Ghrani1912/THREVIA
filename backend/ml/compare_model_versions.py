"""
compare_model_versions.py — like-for-like scoring of two model directories
==========================================================================
``train_clean_corpus.py`` prints the metrics of whatever it just trained, but
that only gives one side of a comparison.  This script loads two model
directories and scores them on identical, identically-preprocessed holdouts, so
"did the retrain actually improve anything" has a measured answer rather than a
before-number copied out of a document.

Compared by default:

    v1  hdfs://.../models_clean      (multiclass inverse-frequency weights
                                      applied to BOTH models, uncapped)
    v2  hdfs://.../models_clean_v2   (per-target weights, capped at 100x)

Metrics, per version:

  * Friday BENIGN temporal holdout (C2)  -> false-positive rate and count
  * Session-split DDoS + Bot (C1)        -> per-class recall
  * PortScan held-out (grouped split)    -> per-class recall
  * IDS2025 validation (cross-source)    -> per-class recall

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[3] --driver-memory 3g \
    /workspace/backend/ml/compare_model_versions.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel

from backend.processing.schema_maps import CANONICAL_FEATURE_COLS

HDFS_ROOT   = 'hdfs://namenode:8020/threvia'
BASE_MODELS = f'{HDFS_ROOT}/models_clean'          # holds scaler + medians + label map

VERSIONS = {
    'v1 (uncapped, multiclass weights on both)':
        os.getenv('V1_DIR', f'{HDFS_ROOT}/models_clean'),
    'v2 (per-target weights, capped 100x)':
        os.getenv('V2_DIR', f'{HDFS_ROOT}/models_clean_v2'),
}

C1_DDOS = f'{HDFS_ROOT}/corpus/friday_ddos_test'
C1_BOT  = f'{HDFS_ROOT}/corpus/friday_bot_test'
C2_BEN  = f'{HDFS_ROOT}/corpus/friday_benign_c2'
PS_TEST = f'{HDFS_ROOT}/corpus/portscan_test'
IDS25   = f'{HDFS_ROOT}/validation/ids2025_validation.csv'

FEAT_COL   = 'scaled_features'
LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'
MULTI_COL  = 'attack_type_idx'


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-CompareModelVersions')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def per_class_recall(preds, label_col, idx_to_label):
    """Return {label_name: (recall, correct, support)} for the multiclass output."""
    from pyspark.sql.types import StringType
    mapper = F.udf(lambda i: idx_to_label.get(int(i)) if i is not None else None, StringType())
    df = preds.withColumn('_lbl', mapper(F.col(label_col)))
    total = {r['_lbl']: r['count'] for r in df.groupBy('_lbl').count().collect()}
    hit = {
        r['_lbl']: r['count']
        for r in df.filter(F.col(label_col) == F.col('prediction')).groupBy('_lbl').count().collect()
    }
    out = {}
    for lbl, sup in total.items():
        if lbl is None:
            continue
        corr = hit.get(lbl, 0)
        out[lbl] = (corr / sup if sup else 0.0, corr, sup)
    return out


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

    sep('Loading shared preprocessing artifacts')
    pipe = PipelineModel.load(f'{BASE_MODELS}/scaler_pipeline')
    med_row = spark.read.parquet(f'{BASE_MODELS}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}
    lm_df = spark.read.parquet(f'{BASE_MODELS}/label_index_map')
    idx_to_label = {int(r['idx']): r['label'] for r in lm_df.collect()}
    print(f'  label_index_map: {idx_to_label}')

    # A StringIndexer is needed to attach attack_type_idx to external sets.  It is
    # refit from the corpus, which is deterministic and matches the saved map.
    from pyspark.ml.feature import StringIndexer
    corpus_labels = spark.read.parquet(f'{HDFS_ROOT}/corpus/train').select(LABEL_COL)
    idx_model = StringIndexer(inputCol=LABEL_COL, outputCol=MULTI_COL,
                              handleInvalid='keep').fit(corpus_labels)
    assert {i: v for i, v in enumerate(idx_model.labels)} == idx_to_label, \
        'refit StringIndexer disagrees with label_index_map'
    print('  StringIndexer refit matches the saved label_index_map.')

    # ── Prepare each holdout once ─────────────────────────────────────────────
    sep('Preparing holdouts (once, shared by both versions)')

    def prep(df, name):
        if FEAT_COL in df.columns:
            # Some splits (portscan_test) were written already-scaled, and the
            # saved pipeline would collide with the raw_features column they
            # already carry.  Use them as-is and only re-derive the targets.
            out = df.withColumn(
                LABEL_COL, label_udf(F.col(LABEL_COL)))
            out = out.withColumn(
                BINARY_COL,
                F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0)).otherwise(F.lit(1)))
            print(f'  {name}: pre-scaled split, using as-is')
        else:
            out = clean_and_scale_external(spark, df, feat_cols, pipe, label_udf, fill_map=medians)
        out = idx_model.transform(out)
        out.cache()
        print(f'  {name}: {out.count():,} rows')
        return out

    c2 = prep(spark.read.parquet(C2_BEN), 'C2 Friday BENIGN (temporal)')
    c1 = prep(
        spark.read.parquet(C1_DDOS).unionByName(spark.read.parquet(C1_BOT),
                                               allowMissingColumns=True),
        'C1 DDoS + Bot (session split)',
    )
    ps = prep(spark.read.parquet(PS_TEST), 'PortScan held-out')
    ids = prep(
        spark.read.option('header', True).option('inferSchema', False).csv(IDS25),
        'IDS2025 validation (cross-source)',
    )

    # ── Score each version ────────────────────────────────────────────────────
    results = {}
    for vname, vdir in VERSIONS.items():
        sep(f'Scoring {vname}')
        print(f'  {vdir}')
        try:
            rf_bin = RandomForestClassificationModel.load(f'{vdir}/rf_binary')
            rf_multi = RandomForestClassificationModel.load(f'{vdir}/rf_multiclass')
        except Exception as exc:
            print(f'  SKIP — could not load models: {exc}')
            continue

        v = {}

        # C2: BENIGN-only set -> anything predicted attack is a false positive
        p = rf_bin.transform(c2)
        n_c2 = p.count()
        fp = p.filter(F.col('prediction') == 1.0).count()
        v['c2_fpr'] = fp / n_c2 if n_c2 else 0.0
        v['c2_fp'] = fp
        v['c2_rows'] = n_c2
        print(f'  C2 FPR @ default 0.50 cut : {v["c2_fpr"] * 100:.2f}%  ({fp:,}/{n_c2:,})')

        # C1: per-class recall (DDoS, Bot)
        v['c1'] = per_class_recall(rf_multi.transform(c1), MULTI_COL, idx_to_label)
        for lbl, (r, c, s) in sorted(v['c1'].items()):
            print(f'  C1 recall {lbl:<10}: {r * 100:6.2f}%  ({c:,}/{s:,})')

        # PortScan
        v['portscan'] = per_class_recall(rf_multi.transform(ps), MULTI_COL, idx_to_label)
        for lbl, (r, c, s) in sorted(v['portscan'].items()):
            print(f'  PortScan recall {lbl:<10}: {r * 100:6.2f}%  ({c:,}/{s:,})')

        # IDS2025 cross-source
        p = rf_bin.transform(ids)
        n_ids = p.count()
        v['ids_binary_acc'] = p.filter(F.col('prediction') == F.col(BINARY_COL)).count() / n_ids
        v['ids_binary_recall_attack'] = None
        atk = p.filter(F.col(BINARY_COL) == 1)
        n_atk = atk.count()
        if n_atk:
            v['ids_binary_recall_attack'] = atk.filter(F.col('prediction') == 1.0).count() / n_atk
        v['ids'] = per_class_recall(rf_multi.transform(ids), MULTI_COL, idx_to_label)
        print(f'  IDS2025 binary acc        : {v["ids_binary_acc"] * 100:.2f}%')
        if v['ids_binary_recall_attack'] is not None:
            print(f'  IDS2025 attack recall     : {v["ids_binary_recall_attack"] * 100:.2f}%')
        for lbl, (r, c, s) in sorted(v['ids'].items()):
            print(f'  IDS2025 recall {lbl:<26}: {r * 100:6.2f}%  ({c:,}/{s:,})')

        results[vname] = v

    # ── Side-by-side ──────────────────────────────────────────────────────────
    sep('SIDE-BY-SIDE')
    names = list(results.keys())
    if len(names) < 2:
        print('  Need two versions to compare.')
        spark.stop()
        sys.exit(1)

    a, b = names[0], names[1]
    ra, rb = results[a], results[b]

    def row(label, va, vb, fmt='{:.2f}%', better='lower'):
        if va is None or vb is None:
            print(f'  {label:<34} {va!s:>16} {vb!s:>16}')
            return
        delta = vb - va
        mark = ''
        if abs(delta) > 1e-9:
            improved = (delta < 0) if better == 'lower' else (delta > 0)
            mark = '  <= BETTER' if improved else '  <= worse'
        print(f'  {label:<34} {fmt.format(va * 100 if "%" in fmt else va):>16} '
              f'{fmt.format(vb * 100 if "%" in fmt else vb):>16}{mark}')

    print(f'  {"metric":<34} {a[:16]:>16} {b[:16]:>16}')
    print('  ' + '-' * 70)
    row('C2 BENIGN FPR (temporal)  [lower]', ra['c2_fpr'], rb['c2_fpr'])
    row('C2 false positives       [lower]', float(ra['c2_fp']), float(rb['c2_fp']),
        fmt='{:.0f}')
    for lbl in sorted(set(ra['c1']) | set(rb['c1'])):
        row(f'C1 recall {lbl}          [higher]',
            ra['c1'].get(lbl, (None,))[0], rb['c1'].get(lbl, (None,))[0], better='higher')
    for lbl in sorted(set(ra['portscan']) | set(rb['portscan'])):
        row(f'PortScan recall {lbl}   [higher]',
            ra['portscan'].get(lbl, (None,))[0],
            rb['portscan'].get(lbl, (None,))[0], better='higher')
    row('IDS2025 binary accuracy [higher]',
        ra['ids_binary_acc'], rb['ids_binary_acc'], better='higher')
    row('IDS2025 attack recall   [higher]',
        ra['ids_binary_recall_attack'], rb['ids_binary_recall_attack'], better='higher')
    for lbl in sorted(set(ra['ids']) | set(rb['ids'])):
        row(f'IDS2025 recall {lbl}  [higher]',
            ra['ids'].get(lbl, (None,))[0], rb['ids'].get(lbl, (None,))[0], better='higher')

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
