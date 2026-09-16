"""
infiltration_rules.py  (Tier-3 Rule-Based Infiltration Detector)
================================================================
Infiltration recall = 0% in the main RF because the CICIDS2018 training
Infiltration and CIC-2017 Infiltration have different feature distributions
(cross-dataset mismatch). ML cannot fix a data mismatch.

Instead we use deterministic rules derived from the known characteristics
of Infiltration traffic:
  - Very long flow duration (slow exfiltration or covert C2 channels)
  - Targets typical data-exfiltration ports (80, 443, 8080, etc.)
  - Low data rate relative to duration (slow/covert transfer)
  - Asymmetric traffic (large Bwd bytes, small Fwd bytes)

These rules act as a Tier-3 fallback AFTER the main RF classifies a flow.
If the main RF predicts BENIGN with confidence > CONF_THRESHOLD but the
rules fire, the prediction is overridden to 'Infiltration'.

Usage (standalone analysis):
  docker exec threvia-spark-master spark-submit \
      --master spark://spark-master:7077 \
      /workspace/backend/ml/infiltration_rules.py

Usage (as module in inference pipeline):
  from backend.ml.infiltration_rules import apply_infiltration_rules
  df = apply_infiltration_rules(df)   # adds 'rule_infiltration' column (0/1)
"""

import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F

# ── Thresholds ────────────────────────────────────────────────────────────────
# Flow Duration is stored as log1p(microseconds) in the corpus.
# log1p(300_000_000 µs) = log1p(300s) ≈ 19.52
# log1p(60_000_000 µs)  = log1p(60s)  ≈ 17.92
DURATION_MIN_LOG = 17.92         # >= 60 seconds in log1p space

# Target ports typical of HTTP exfiltration / C2 channels
INFILTRATION_PORTS = {80, 443, 8080, 8443, 3389, 22, 21, 25, 53}

# Low data rate: Flow Bytes/s < 500 after log1p -> log1p(500) ≈ 6.21
FLOW_BYTES_MAX_LOG = 6.21        # <= ~500 bytes/s (covert/slow transfer)

# Asymmetric: backward bytes >> forward bytes (data leaving victim)
BWD_FWD_RATIO_MIN = 3.0          # Bwd / Fwd packet lengths > 3x

# ── Rule application ──────────────────────────────────────────────────────────
def apply_infiltration_rules(df):
    """
    Adds column 'rule_infiltration' (1 = likely Infiltration, 0 = not).
    Input df must have the canonical feature columns in log1p-scaled form
    (as produced by merge_corpus.py / clean_and_scale_external).
    """
    # Rule 1: Long duration + low data rate (slow exfiltration)
    r1 = (
        (F.col('Flow Duration') >= DURATION_MIN_LOG) &
        (F.col('Flow Bytes/s')  <= FLOW_BYTES_MAX_LOG)
    )

    # Rule 2: Long duration + target port (C2 channel)
    r2 = (
        (F.col('Flow Duration') >= DURATION_MIN_LOG) &
        (F.col('Destination Port').cast('int').isin(list(INFILTRATION_PORTS)))
    )

    # Rule 3: Asymmetric bwd/fwd (data exfiltration pattern)
    # Bwd total bytes >> Fwd total bytes AND duration >= 60s
    bwd = F.col('Total Length of Bwd Packets')
    fwd = F.greatest(F.col('Total Length of Fwd Packets'), F.lit(1.0))
    r3 = (
        (F.col('Flow Duration') >= DURATION_MIN_LOG) &
        ((bwd / fwd) >= BWD_FWD_RATIO_MIN)
    )

    df = df.withColumn(
        'rule_infiltration',
        F.when(r1 | r2 | r3, F.lit(1)).otherwise(F.lit(0))
    )
    return df


# ── Standalone evaluation ─────────────────────────────────────────────────────
def main():
    spark = SparkSession.builder \
        .appName('Threvia-InfiltrationRules') \
        .config('spark.sql.shuffle.partitions', '16') \
        .getOrCreate()
    spark.sparkContext.setLogLevel('WARN')

    HDFS_CORPUS     = 'hdfs://namenode:8020/threvia/corpus/train'
    HDFS_VALIDATION = 'hdfs://namenode:8020/threvia/validation/ids2025_validation.csv'
    LABEL_COL       = 'Label'

    def sep(msg=''):
        print('\n' + '=' * 72 + (f'\n  {msg}\n' + '=' * 72 if msg else ''))

    sep('Infiltration Rule Evaluator')
    print(f"""
  Rules:
    R1: Flow Duration >= {DURATION_MIN_LOG} (log1p ~60s) AND Flow Bytes/s <= {FLOW_BYTES_MAX_LOG} (log1p ~500 B/s)
    R2: Flow Duration >= {DURATION_MIN_LOG} AND Destination Port in {sorted(INFILTRATION_PORTS)}
    R3: Flow Duration >= {DURATION_MIN_LOG} AND Bwd/Fwd bytes ratio >= {BWD_FWD_RATIO_MIN}x
  """)

    # Evaluate on training corpus (sanity check — should fire on Infiltration rows)
    sep('Sanity check on training corpus')
    corpus = spark.read.parquet(HDFS_CORPUS)

    # Apply log1p to Duration if not already done (corpus already has log1p applied)
    df = apply_infiltration_rules(corpus)

    infiltration_rows = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'INFILTRATION')
    n_infil = infiltration_rows.count()
    print(f'  Infiltration rows in corpus : {n_infil:,}')

    if n_infil > 0:
        tp = infiltration_rows.filter(F.col('rule_infiltration') == 1).count()
        print(f'  True Positives (rule fires on Infiltration) : {tp:,}')
        print(f'  Recall on training Infiltration             : {tp/n_infil:.4f}')

    # False positive rate on BENIGN
    benign_rows = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN')
    n_benign = benign_rows.count()
    fp = benign_rows.filter(F.col('rule_infiltration') == 1).count()
    print(f'  BENIGN rows                : {n_benign:,}')
    print(f'  False positives on BENIGN  : {fp:,}  ({fp/n_benign*100:.3f}%)')

    # Full rule firing rate per class
    sep('Rule firing rate by class')
    df.groupBy(LABEL_COL, 'rule_infiltration').count() \
      .orderBy(LABEL_COL, 'rule_infiltration') \
      .show(40, truncate=False)

    sep('DONE')
    print("""
  Integration instructions:
  ─────────────────────────
  In your inference pipeline, after the main RF scores a flow:

      from backend.ml.infiltration_rules import apply_infiltration_rules
      df = apply_infiltration_rules(df)

      # Override BENIGN prediction to Infiltration when rule fires
      df = df.withColumn(
          'final_label',
          F.when(
              (F.col('prediction_label') == 'BENIGN') &
              (F.col('rule_infiltration') == 1),
              F.lit('Infiltration')
          ).otherwise(F.col('prediction_label'))
      )
  """)
    spark.stop()


if __name__ == '__main__':
    main()
