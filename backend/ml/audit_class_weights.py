"""
audit_class_weights.py — per-class support and the class weights actually used
=============================================================================
``train_clean_corpus.py`` (pre-fix) computed ONE weight column from the
*multiclass* label distribution and handed it to BOTH the binary and the
multiclass RandomForest.  Because CICIDS2018 is dominated by a handful of
flood attacks, the rarest Web-Attack classes received four-to-five figure
weights:

    weight_i = N / (K * count_i)

and those weights then applied to the *binary* benign-vs-attack model too,
where every attack row should carry roughly the same weight.  That is the
mechanism behind the documented class-weight over-amplification FPR.

This script prints, for the training corpus:

  * the multiclass support of every label
  * the uncapped and capped (``WEIGHT_CAP``) multiclass inverse-frequency weight
  * the binary (BENIGN vs attack) support and weight
  * how many labels the cap actually moves

so the cap can be chosen from data instead of guessed.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[2] --driver-memory 1g \
    /workspace/backend/ml/audit_class_weights.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

HDFS_TRAIN = 'hdfs://namenode:8020/threvia/corpus/train'
LABEL_COL = 'Label'
CAP = float(os.getenv('WEIGHT_CAP', '100.0'))


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-ClassWeightAudit')
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

    sep('Class weight audit — Threvia training corpus')
    print(f'  Source : {HDFS_TRAIN}')
    print(f'  WEIGHT_CAP = {CAP:g}')

    train = spark.read.parquet(HDFS_TRAIN)
    n_total = train.count()
    print(f'  Rows   : {n_total:,}')

    # Does the corpus already carry the binary target the trainer expects?
    # train_clean_corpus.py uses labelCol='is_attack', so this must exist for
    # the pre-fix script to have worked at all -- and its definition (not a
    # re-derived one) is what the published baselines were measured against.
    sep('Corpus schema check')
    print(f'  Columns ({len(train.columns)}): {train.columns}')
    if 'is_attack' in train.columns:
        print('\n  is_attack already present in corpus:')
        (
            train.groupBy('is_attack')
            .agg(F.count(F.lit(1)).alias('rows'), F.countDistinct(LABEL_COL).alias('labels'))
            .orderBy('is_attack')
            .show(10, truncate=False)
        )
        # Cross-check the stored flag against a BENIGN-string derivation.
        mismatch = train.filter(
            (F.col('is_attack').cast('int') == 0)
            & (F.upper(F.trim(F.col(LABEL_COL))) != 'BENIGN')
        ).count()
        mismatch += train.filter(
            (F.col('is_attack').cast('int') == 1)
            & (F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN')
        ).count()
        print(f'  Rows where stored is_attack disagrees with Label==BENIGN: {mismatch:,}')
        print('  (0 => safe to derive the binary weight from either column)')
    else:
        print('\n  is_attack NOT present -- trainer must derive it.')

    # ── Multiclass distribution + inverse-frequency weight ────────────────────
    freq = train.groupBy(LABEL_COL).count().withColumnRenamed('count', 'support')
    n_classes = freq.count()

    freq = freq.withColumn(
        'inv_freq_weight',
        F.lit(float(n_total)) / (F.lit(float(n_classes)) * F.col('support')),
    )

    # Binary target: BENIGN vs everything else
    bin_counts = (
        train.withColumn(
            '_is_attack',
            F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0)).otherwise(F.lit(1)),
        )
        .groupBy('_is_attack')
        .count()
        .collect()
    )
    bin_map = {int(r['_is_attack']): int(r['count']) for r in bin_counts}
    n_benign = bin_map.get(0, 0)
    n_attack = bin_map.get(1, 0)

    sep('BINARY target (benign vs attack) — support and correct-weight')
    print(f'  BENIGN (0) : {n_benign:>12,}   ({n_benign / n_total * 100:6.2f}%)')
    print(f'  ATTACK (1) : {n_attack:>12,}   ({n_attack / n_total * 100:6.2f}%)')
    w_bin_benign = n_total / (2.0 * n_benign) if n_benign else 0.0
    w_bin_attack = n_total / (2.0 * n_attack) if n_attack else 0.0
    print(f'\n  Correct binary weights: BENIGN {w_bin_benign:.4f}x  ATTACK {w_bin_attack:.4f}x')
    print(f'  (ratio {w_bin_benign / w_bin_attack:.2f}:1)' if w_bin_attack else '')
    print(
        '\n  >> The pre-fix script instead applied the MULTICLASS weights below to\n'
        '     this binary model, so an Sql-Injection row carried ~20,000x the\n'
        '     weight of a DDoS row when deciding "attack or not".'
    )

    sep('MULTICLASS target — per-class support and weight')
    rows = (
        freq.withColumn('capped_weight', F.least(F.col('inv_freq_weight'), F.lit(CAP)))
        .withColumn('capped', F.col('inv_freq_weight') > F.lit(CAP))
        .orderBy(F.desc('support'))
        .collect()
    )

    print(f'  {"label":<34} {"support":>11} {"weight":>13} {"capped":>13}  moved')
    print('  ' + '-' * 84)
    n_moved = 0
    for r in rows:
        moved = 'YES' if r['capped'] else ''
        if r['capped']:
            n_moved += 1
        print(
            f'  {r[LABEL_COL][:33]:<34} {r["support"]:>11,} '
            f'{r["inv_freq_weight"]:>12.1f}x {r["capped_weight"]:>12.1f}x  {moved}'
        )

    sep('Summary')
    print(f'  Labels                 : {n_classes}')
    print(f'  Labels moved by cap    : {n_moved}')
    print(f'  Largest uncapped weight: {max(r["inv_freq_weight"] for r in rows):,.0f}x')
    print(f'  Largest capped weight  : {max(r["capped_weight"] for r in rows):,.0f}x')
    print(
        '\n  Recommendation: cap the MULTICLASS weights for the multiclass model and\n'
        '  use the BINARY weights above for the binary model.  Applying multiclass\n'
        '  inverse-frequency weights to the binary model is the documented cause of\n'
        '  the slow/sparse-BENIGN false positives.'
    )

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
