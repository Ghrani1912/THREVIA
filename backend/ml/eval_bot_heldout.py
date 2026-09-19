"""
eval_bot_heldout.py — Step 4: is the Bot specialist's "100% recall" real?
=========================================================================
The 95.56% precision / 100.00% recall figure quoted for ``rf_bot_binary`` was
measured on the *streamed demo corpus*, whose Bot rows are sampled from
``friday_bot_train`` — the same rows the specialist (and every Tier-1 model)
trained on.  It is an **in-sample** number and cannot be trusted as a
generalisation claim.

This script measures the same model on:

  1. ``friday_bot_test``  — the genuinely held-out 30% Bot split (570 rows)
  2. ``friday_bot_train`` — the in-sample rows (for contrast, quantifying the gap)
  3. the Friday BENIGN holdout (C2) — the specialist's false-positive rate on
     benign traffic, which is the other half of the operating claim

and prints the raw-cut sweep for each, so the "RECOVERED / 99.5%" dashboard
label can be replaced with a defensible number.

Also worth noting for the split-methodology record: ``split_friday_sessions.py``
documented that its own port-bucket attempt was degenerate and fell back to a
row-level ``randomSplit`` — so TEST-C1 is *not* session-grouped, and near-duplicate
Bot flows may straddle the split.  The held-out numbers here are therefore an
upper bound on true generalisation, not a lower bound.

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \
    /opt/spark/bin/spark-submit --master local[2] --driver-memory 3g \
    /workspace/backend/ml/eval_bot_heldout.py"
"""

import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.functions import vector_to_array

HDFS_ROOT = 'hdfs://namenode:8020/threvia'
MODELS    = f'{HDFS_ROOT}/models_clean'
BOT_TEST  = f'{HDFS_ROOT}/corpus/friday_bot_test'
BOT_TRAIN = f'{HDFS_ROOT}/corpus/friday_bot_train'
BENIGN_C2 = f'{HDFS_ROOT}/corpus/friday_benign_c2'

FEAT_COL  = 'scaled_features'
LABEL_COL = 'Label'
CUTS = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-EvalBotHeldout')
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
    rf_bot = RandomForestClassificationModel.load(f'{MODELS}/rf_bot_binary')

    def prep_bot(raw, name):
        df = clean_and_scale_external(spark, raw, feat_cols, pipe, label_udf, fill_map=medians)
        df = df.withColumn('is_bot', F.when(F.col(LABEL_COL) == 'Bot', F.lit(1)).otherwise(F.lit(0)))
        scored = (
            rf_bot.transform(df)
            .withColumn('_bp', vector_to_array('probability'))
            .withColumn('p_bot', F.col('_bp')[1])
            .select('is_bot', 'p_bot')
            .cache()
        )
        n = scored.count()
        n_pos = scored.filter(F.col('is_bot') == 1).count()
        print(f'  {name}: {n:,} rows (Bot={n_pos:,})')
        return scored, n_pos

    sep('Loading + scoring sets')
    test_scored, n_test_bot = prep_bot(spark.read.parquet(BOT_TEST), 'friday_bot_test (HELD-OUT)')
    train_scored, n_train_bot = prep_bot(spark.read.parquet(BOT_TRAIN), 'friday_bot_train (IN-SAMPLE)')
    benign_scored, _ = prep_bot(spark.read.parquet(BENIGN_C2), 'friday_benign_c2 (BENIGN only)')

    def sweep(scored, n_pos, name):
        sep(f'Raw-cut sweep — {name}')
        hdr = f"  {'CUT':>5} | {'LABELLED':>9} | {'TRULY BOT':>9} | {'PREC%':>7} | {'RECALL%':>8}"
        print(hdr)
        print('  ' + '-' * (len(hdr) - 2))
        for cut in CUTS:
            sel = scored.filter(F.col('p_bot') >= cut)
            labelled = sel.count()
            tp = sel.filter(F.col('is_bot') == 1).count()
            prec = tp / labelled * 100 if labelled else 0.0
            rec = tp / n_pos * 100 if n_pos else 0.0
            print(f'  {cut:>5.2f} | {labelled:>9,} | {tp:>9,} | {prec:>6.2f}% | {rec:>7.2f}%')

    sweep(test_scored, n_test_bot, 'HELD-OUT bot_test')
    sweep(train_scored, n_train_bot, 'IN-SAMPLE bot_train (contrast)')

    sep('BENIGN false-positive rate of the specialist (held-out C2)')
    n_ben = benign_scored.count()
    for cut in (0.50, 0.60, 0.70):
        fp = benign_scored.filter(F.col('p_bot') >= cut).count()
        print(f'  raw cut {cut:.2f}: {fp:,}/{n_ben:,} = {fp / n_ben * 100:.3f}%')

    sep('Reading')
    print("""
  Compare the held-out sweep with the in-sample one at the production raw cut
  of 0.50.  The gap between them is training-set leakage in the streamed-corpus
  measurement: the demo corpus samples Bot rows from friday_bot_train, so a
  near-perfect in-sample number says nothing about unseen Bot traffic.
  The held-out numbers are the ones a dashboard may quote.
  NOTE: split_friday_sessions.py fell back to a row-level randomSplit, so some
  near-duplicate Bot flows straddle the split -- treat held-out recall as an
  upper bound on true generalisation.
""")

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
