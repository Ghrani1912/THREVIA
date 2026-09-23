"""
diagnose_fpr.py -- FPR root-cause analysis for Friday BENIGN temporal shift
Q1. Was Bot label-case fix applied?
Q2. FPR before/after weighting proxy
Q3. FPR breakdown by hour (if Timestamp survived)
Q4. Absolute FP count with operational cost framing
Q5. Which features drive FPs?
"""
import sys
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.pipeline import PipelineModel
import pyspark.sql.functions as F

HDFS              = 'hdfs://namenode:8020/threvia'
HDFS_BENIGN_C2    = f'{HDFS}/corpus/friday_benign_c2'
HDFS_CORPUS_TRAIN = f'{HDFS}/corpus/train'
HDFS_RF_BIN       = f'{HDFS}/models_clean/rf_binary'
HDFS_SCALER_PIPE  = f'{HDFS}/models_clean/scaler_pipeline'
HDFS_MEDIANS      = f'{HDFS}/models_clean/imputer_medians'
LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'

def sep(msg):
    bar = '='*72
    print(f'\n{bar}\n  {msg}\n{bar}')

def main():
    spark = (SparkSession.builder
             .appName('Threvia-FPR-Diagnosis')
             .config('spark.sql.shuffle.partitions', '8')
             .getOrCreate())
    spark.sparkContext.setLogLevel('WARN')

    # Q1: Bot label-case audit
    sep('Q1: Bot label-case fix -- training corpus label audit')
    train = spark.read.parquet(HDFS_CORPUS_TRAIN)
    train.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(20, truncate=False)
    bot_rows  = train.filter(F.lower(F.col(LABEL_COL)) == 'bot')
    bot_cases = bot_rows.groupBy(LABEL_COL).count()
    print('Bot label variants in corpus:')
    bot_cases.show(truncate=False)
    total_bot = bot_rows.count()
    print(f'Total Bot rows: {total_bot:,}')
    if total_bot == 0:
        print('  CRITICAL: No Bot rows -- class-weight had NO effect on Bot!')
    elif total_bot < 5000:
        print(f'  WARNING: Only {total_bot:,} Bot rows -- sparse')
    else:
        print(f'  OK: {total_bot:,} Bot rows -- class-weight applied correctly')

    # Schema check
    sep('friday_benign_c2 schema -- looking for Timestamp')
    raw_benign = spark.read.parquet(HDFS_BENIGN_C2)
    print(f'All columns: {raw_benign.columns}')
    ts_cols = [c for c in raw_benign.columns if 'time' in c.lower()]
    print(f'Timestamp columns: {ts_cols}')
    print(f'Total rows: {raw_benign.count():,}')
    raw_benign.show(3, truncate=True)

    # Load models and scale
    sep('Loading models + scaling benign_c2')
    ext_pipe_model = PipelineModel.load(HDFS_SCALER_PIPE)
    rf_bin_model   = RandomForestClassificationModel.load(HDFS_RF_BIN)
    _med_row  = spark.read.parquet(HDFS_MEDIANS).first()
    fill_map  = dict(_med_row.asDict()) if _med_row else {}

    sys.path.insert(0, '/workspace/backend/ml')
    sys.path.insert(0, '/workspace')
    from train_clean_corpus import clean_and_scale_external
    # Build label_udf inline (same logic as train_clean_corpus.py)
    from backend.processing.schema_maps import LABEL_NORMALISE
    from pyspark.sql.types import StringType
    _norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    _bc_map   = spark.sparkContext.broadcast(_norm_map)
    label_udf = F.udf(
        lambda raw: _bc_map.value.get(raw.strip().upper(), raw.strip()) if raw else None,
        StringType()
    )

    # Fix: Friday-Morning CSV has duplicate 'Fwd Header Length' column, which Spark
    # renames to 'Fwd Header Length34' / 'Fwd Header Length55' on read.
    # DDoS/Bot CSVs don't have this duplicate — hence TEST-C1 passed but C2 fails.
    # Rename back to canonical name expected by the scaler pipeline.
    if 'Fwd Header Length34' in raw_benign.columns:
        raw_benign = raw_benign.withColumnRenamed('Fwd Header Length34', 'Fwd Header Length')
        print('  Renamed Fwd Header Length34 -> Fwd Header Length (duplicate-col fix)')
    if 'Fwd Header Length55' in raw_benign.columns:
        raw_benign = raw_benign.drop('Fwd Header Length55')
        print('  Dropped Fwd Header Length55 (duplicate column)')

    skip_cols = {LABEL_COL, BINARY_COL, 'attack_type_idx', 'weight',
                 'Timestamp', 'Flow ID', 'Source IP', 'Destination IP', 'Protocol'}
    feat_cols = [c for c in raw_benign.columns if c not in skip_cols]

    benign_scaled = clean_and_scale_external(
        spark, raw_benign, feat_cols, ext_pipe_model, label_udf, fill_map=fill_map)

    preds = rf_bin_model.transform(benign_scaled)
    preds.cache()
    n_total = preds.count()
    n_fp    = preds.filter(F.col('prediction') != F.col(BINARY_COL)).count()
    fpr     = n_fp / n_total if n_total > 0 else 0.0

    # Q4: Absolute cost
    sep('Q4: Absolute FP operational cost')
    print(f'  Total BENIGN flows : {n_total:,}')
    print(f'  False Positives    : {n_fp:,}')
    print(f'  FPR                : {fpr*100:.2f}%')
    print(f'  Analyst-hours (20 alerts/hr): {n_fp/20:,.0f} hrs wasted per Friday batch')
    print(f'  Cost @ $75/hr      : ${n_fp/20*75:,.0f} per Friday batch')
    print(f'  Annualised (52x)   : ${n_fp/20*75*52:,.0f}')

    # Q3: FPR by hour
    sep('Q3: FPR breakdown by hour')
    if ts_cols:
        ts_col = ts_cols[0]
        print(f'  Timestamp column: {ts_col}')
        hourly = (raw_benign
            .withColumn('hour', F.hour(F.to_timestamp(F.col(ts_col))))
            .join(preds.select('prediction', BINARY_COL), how='left')
            .groupBy('hour')
            .agg(
                F.count('*').alias('total'),
                F.sum((F.col('prediction') != F.col(BINARY_COL)).cast('int')).alias('fps')
            )
            .withColumn('fpr_pct', F.round(F.col('fps') / F.col('total') * 100, 2))
            .orderBy('hour'))
        hourly.show(24, truncate=False)
    else:
        print('  No Timestamp in parquet. Checking raw Friday Morning CSV...')
        try:
            sample = (spark.read
                .option('header', True).option('inferSchema', False)
                .csv('hdfs://namenode:8020/threvia/raw')
                .withColumn('_src', F.regexp_extract(F.input_file_name(), r'([^/]+)$', 1))
                .filter(F.col('_src').contains('Morning'))
                .limit(5))
            ts_in_csv = [c for c in sample.columns if 'time' in c.lower()]
            print(f'  Timestamp cols in raw Morning CSV: {ts_in_csv}')
            if ts_in_csv:
                sample.select(ts_in_csv).show(5, truncate=False)
        except Exception as e:
            print(f'  Error reading raw CSV: {e}')

    # Q5: Feature-level root cause
    sep('Q5: FP vs TN feature means -- what drives false positives?')
    key_features = [
        'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
        'Total Fwd Packets', 'Total Backward Packets',
        'Flow IAT Mean', 'Fwd IAT Total', 'Bwd IAT Total',
        'Active Mean', 'Idle Mean'
    ]
    available = [f for f in key_features if f in raw_benign.columns]
    if available:
        fp_rows = preds.filter(F.col('prediction') != F.col(BINARY_COL))
        tn_rows = preds.filter(F.col('prediction') == F.col(BINARY_COL))
        fp_vals = fp_rows.agg(*[F.mean(f).alias(f) for f in available]).collect()[0].asDict()
        tn_vals = tn_rows.agg(*[F.mean(f).alias(f) for f in available]).collect()[0].asDict()
        print(f'  {"Feature":<35} {"FP mean":>14} {"TN mean":>14} {"FP/TN":>8}')
        print(f'  {"-"*75}')
        for f in available:
            fp_v = fp_vals.get(f) or 0
            tn_v = tn_vals.get(f) or 0.001
            ratio = fp_v / tn_v if tn_v else 999
            flag = ' <-- ANOMALOUS' if ratio > 3 or ratio < 0.33 else ''
            print(f'  {f:<35} {fp_v:>14.2f} {tn_v:>14.2f} {ratio:>8.2f}{flag}')
    else:
        print(f'  Key features not in raw parquet. Raw columns: {raw_benign.columns[:15]}')

    # Q2: Feature importance proxy
    sep('Q2: FPR class-weight-artifact proxy -- binary RF feature importances')
    importances = rf_bin_model.featureImportances
    imp_list = sorted(enumerate(importances.toArray()), key=lambda x: -x[1])[:10]
    print('  Top 10 feature importances (binary RF):')
    for idx, imp in imp_list:
        print(f'    idx {idx:3d}: {imp:.4f}')
    print()
    print('  If top features = flow-volume (bytes/s, pkt rate) -> domain shift (temporal)')
    print('  If top features = count-based with rare-class bias -> class-weight artifact')

    sep('DONE')
    spark.stop()
    sys.exit(0)

if __name__ == '__main__':
    main()



