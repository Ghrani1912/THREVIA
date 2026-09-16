"""
Task 4 â€” Merge Unified Training Corpus  (v3 â€” log1p + CIC-2017 BENIGN mix)
========================================
Assembles the clean training corpus from FOUR sources:

  SOURCE A  LycoS-IDS2018
            13.69M rows, re-extracted from raw pcaps
            â†’ column rename via LYCOS_RENAME, drop LYCOS_EXTRA_DROP

  SOURCE B  CICIDS2018 Thursday + Wednesday (Infiltration only)
            161,934 rows of Infiltration
            â†’ column rename via CIC18_RENAME, drop CIC18_EXTRA_DROP

  SOURCE C  CIC-2017 PortScan (train split only)
            72,706 rows, deduped (42.9% removed), port-grouped split

  SOURCE D  CIC-2017 BENIGN (train split only)   â† NEW in v3
            1,677,188 rows, deduped (7.8% removed), protocol-bucket
            grouped split (high-vol ports sharded, low-vol by exact port)
            Teaches the model "busy CIC-2017 network traffic looks like BENIGN"
            â€” addresses the 8% BENIGN recall on Friday temporal test.

v3 changes vs v2:
  + Source D added (CIC-2017 BENIGN train split)
  = log1p on Flow Duration, Flow Bytes/s, Flow Packets/s (unchanged)
  = Scaler fit on train only (unchanged)

Bot/DDoS recall note:
  CIC-2017 Friday DDoS and Bot are SIGNATURE MISMATCH classes
  (different tool signatures from training data). Adding BENIGN will NOT
  fix their recall â€” that is documented as a generalisation limitation.


  SOURCE A  LycoS-IDS2018
            13.69M rows, re-extracted from raw pcaps (no zero-var signatures
            beyond tool artifacts), no PortScan, no Infiltration
            â†’ column rename via LYCOS_RENAME, drop LYCOS_EXTRA_DROP
            â†’ null-fill LYCOS_MISSING_FROM_LYCOS

  SOURCE B  CICIDS2018 Thursday + Wednesday (Infiltration only)
            93,063 + 68,871 = 161,934 rows of Infiltration
            Diagnostic: 8 zero-var cols, all shared CICFlowMeter artifacts
            â†’ column rename via CIC18_RENAME, drop CIC18_EXTRA_DROP
            â†’ header-contamination rows ("Label" in label col) dropped

  SOURCE C  CIC-2017 PortScan (train split only)
            72,706 rows, deduped (42.9% dups removed), port-grouped split
            (port overlap=0, vec leakage=0 across train/test boundary)
            â†’ already uses canonical column names (just strip whitespace)

Outputs:
  HDFS /threvia/corpus/train     â€” merged training Parquet (snappy)
  HDFS /threvia/corpus/portscan_test  â€” held-out PortScan test split

Pipeline per source:
  1. Read CSV(s)
  2. Rename columns to canonical schema
  3. Drop source-only columns
  4. Normalise Label via LABEL_NORMALISE
  5. Cast all feature cols to double
  6. Replace inf/-inf/NaN with null; impute nulls with column median
  7. Clip Flow Duration negatives to DURATION_FLOOR (47 CICFlowMeter rows)
  8. Apply log1p to Flow Duration, Flow Bytes/s, Flow Packets/s
     (compresses 15â€“19x scale gap between LycoS and CIC-2017 environments)
  9. Add is_attack binary (0=BENIGN, 1=attack)

After merge:
  - Log final label distribution
  - Write to HDFS as Parquet

Usage:
  docker exec threvia-spark-master spark-submit \\
      --master spark://spark-master:7077 \\
      --driver-memory 3g --executor-memory 3g \\
      /workspace/backend/processing/merge_corpus.py
"""

import sys
import os
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml.feature import VectorAssembler, StandardScaler
from pyspark.ml import Pipeline

# Import schema maps (available in /workspace/backend/processing/)
from backend.processing.schema_maps import (
    CANONICAL_FEATURE_COLS,
    LYCOS_RENAME, LYCOS_EXTRA_DROP, LYCOS_MISSING_FROM_LYCOS,
    CIC18_RENAME, CIC18_EXTRA_DROP,
    LABEL_NORMALISE,
    normalise_label,
)

# â”€â”€ HDFS paths â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
HDFS_ROOT       = 'hdfs://namenode:8020/threvia'
HDFS_LYCOS      = f'{HDFS_ROOT}/lycos_raw'          # uploaded separately (see below)
HDFS_CIC18      = f'{HDFS_ROOT}/cic18_raw'          # uploaded separately
HDFS_PS_TRAIN   = f'{HDFS_ROOT}/portscan_clean_raw/portscan_train'
HDFS_PS_TEST    = f'{HDFS_ROOT}/portscan_clean_raw/portscan_test'
HDFS_BN_TRAIN   = f'{HDFS_ROOT}/benign_clean_raw/benign_train'   # Source D

HDFS_TRAIN_OUT  = f'{HDFS_ROOT}/corpus/train'
HDFS_PSTEST_OUT = f'{HDFS_ROOT}/corpus/portscan_test'
HDFS_DDOS_TRAIN = f'{HDFS_ROOT}/corpus/friday_ddos_train'  # Source E
HDFS_BOT_TRAIN  = f'{HDFS_ROOT}/corpus/friday_bot_train'   # Source F

# Feature cols (no Label, no derived cols)
FEAT_COLS = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
LABEL_COL = 'Label'

# â”€â”€ log1p transform config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# These two rate features have a genuine 15â€“19x scale difference between
# LycoS (quiet lab traffic) and CIC-2017 (busier capture environment).
# log1p compresses the high-volume tail so the scaler centres both sources
# in a comparable z-score space, without destroying signal.
# Applied BEFORE assembly+scaling so the scaler fits on transformed values.
#
# Also applied to Flow Duration â€” right-skewed, spans 0â†’120s in microseconds.
# log1p is safe for all three: values are non-negative after the inf/NaN pass
# (the 47 negative-duration rows are clipped to a small floor first).
LOG1P_COLS = ['Flow Bytes/s', 'Flow Packets/s', 'Flow Duration']

# Small positive floor for duration before log1p (avoids log(0) = 0 confusion
# with genuinely zero-duration flows; 1Âµs is below any real flow).
DURATION_FLOOR = 1.0   # microseconds


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-MergeCorpus')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.driver.memory', '3g')
        .config('spark.executor.memory', '3g')
        .config('spark.executor.instances', '1')
        .config('spark.executor.cores', '2')
        .config('spark.network.timeout', '800s')
        .config('spark.sql.files.maxPartitionBytes', '134217728')  # 128 MB
        .config('spark.serializer', 'org.apache.spark.serializer.KryoSerializer')
        .config('spark.memory.fraction', '0.6')
        .getOrCreate()
    )


def sep(title):
    print('\n' + '=' * 72)
    print(f'  {title}')
    print('=' * 72)


# â”€â”€ label normalisation UDF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def make_label_udf(spark):
    """Return a Spark UDF that applies LABEL_NORMALISE (upper-keyed)."""
    norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    broadcast_map = spark.sparkContext.broadcast(norm_map)

    def _norm(raw):
        if raw is None:
            return None
        key = raw.strip().upper()
        return broadcast_map.value.get(key, raw.strip())

    from pyspark.sql.types import StringType
    return F.udf(_norm, StringType())


# â”€â”€ shared cleaning pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def clean_features(df, feat_cols, label_udf):
    """
    Cast feature cols to double, replace inf/NaN with null,
    normalise Label, add is_attack.
    """
    # Cast all feature cols to double
    for c in feat_cols:
        if c in df.columns:
            df = df.withColumn(c, F.col(c).cast('double'))
        else:
            # Column missing in this source â€” add as null
            df = df.withColumn(c, F.lit(None).cast('double'))

    # Replace inf / -inf / NaN with null
    inf_val  = float('inf')
    ninf_val = float('-inf')
    df = df.select([
        F.when(
            F.isnan(F.col(c)) | F.col(c).isin(inf_val, ninf_val), None
        ).otherwise(F.col(c)).alias(c)
        if c in feat_cols
        else F.col(c)
        for c in df.columns
    ])

    # â”€â”€ log1p transform for right-skewed rate/duration features â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Flow Duration: clip negatives (47 rows, 0.01% â€” CICFlowMeter timestamp
    # overflow) to DURATION_FLOOR before log1p so they don't produce NaN.
    # Flow Bytes/s, Flow Packets/s: already non-negative after inf pass above.
    if 'Flow Duration' in feat_cols:
        df = df.withColumn(
            'Flow Duration',
            F.log1p(F.greatest(F.col('Flow Duration'), F.lit(DURATION_FLOOR)))
        )
    for c in ['Flow Bytes/s', 'Flow Packets/s']:
        if c in feat_cols:
            # greatest(x, 0) guards against the tiny number of remaining
            # negatives (e.g. from IAT overflow) without destroying signal
            df = df.withColumn(c, F.log1p(F.greatest(F.col(c), F.lit(0.0))))

    # Normalise label
    df = df.withColumn(LABEL_COL, label_udf(F.col(LABEL_COL)))
    # Drop rows with null / empty Label
    df = df.filter(F.col(LABEL_COL).isNotNull() & (F.trim(F.col(LABEL_COL)) != ''))

    # Add binary is_attack
    df = df.withColumn(
        'is_attack',
        F.when(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN', F.lit(0))
         .otherwise(F.lit(1))
    )

    return df


def impute_nulls(df, feat_cols):
    """Impute nulls with column medians (computed on df itself - train only).

    Returns:
        (df_imputed, fill_map) - fill_map maps col->median for every imputed
        column so callers can persist and apply identical values to external sets.
    """
    null_cols = [c for c in feat_cols
                 if df.filter(F.col(c).isNull()).count() > 0]
    if not null_cols:
        print('  No nulls to impute.')
        return df, {}
    print(f'  Imputing {len(null_cols)} columns with median ...')
    medians = (
        df.select([
            F.percentile_approx(F.col(c), 0.5, 1000).alias(c)
            for c in null_cols
        ]).first().asDict()
    )
    fill_map = {c: float(medians[c]) for c in null_cols if medians[c] is not None}
    return df.fillna(fill_map, subset=list(fill_map.keys())), fill_map


def select_canonical(df, feat_cols):
    """Return df with exactly feat_cols + Label + is_attack columns."""
    all_out = feat_cols + [LABEL_COL, 'is_attack']
    cols_to_select = []
    for c in all_out:
        if c in df.columns:
            cols_to_select.append(F.col(c))
        else:
            cols_to_select.append(F.lit(None).cast('double').alias(c))
    return df.select(cols_to_select)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SOURCE LOADERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def load_lycos(spark, label_udf):
    sep('SOURCE A â€” LycoS-IDS2018')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)   # all string initially â€” we cast below
        .csv(HDFS_LYCOS)
    )
    print(f'  Raw rows   : {df.count():,}')
    print(f'  Raw cols   : {len(df.columns)}')

    # Rename columns
    for src, tgt in LYCOS_RENAME.items():
        if src in df.columns:
            df = df.withColumnRenamed(src, tgt)

    # Drop LycoS-only cols
    for c in LYCOS_EXTRA_DROP:
        if c in df.columns:
            df = df.drop(c)

    df = clean_features(df, FEAT_COLS, label_udf)
    df = select_canonical(df, FEAT_COLS)
    n = df.count()
    print(f'  Clean rows : {n:,}')
    return df


def load_cic18_infiltration(spark, label_udf):
    sep('SOURCE B â€” CICIDS2018 Infiltration (Thu + Wed)')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)
        .csv(HDFS_CIC18)
    )
    print(f'  Raw rows (all labels) : {df.count():,}')

    # Drop CIC18-only cols (Protocol, Timestamp)
    for c in CIC18_EXTRA_DROP:
        if c in df.columns:
            df = df.drop(c)

    # Rename
    for src, tgt in CIC18_RENAME.items():
        if src in df.columns:
            df = df.withColumnRenamed(src, tgt)

    # Keep Infiltration only (drop header-contamination rows and other labels)
    label_udf_local = label_udf
    df = df.withColumn(LABEL_COL, label_udf_local(F.col(LABEL_COL)))
    df = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'INFILTRATION')
    print(f'  Infiltration rows     : {df.count():,}')

    df = clean_features(df, FEAT_COLS, label_udf)
    df = select_canonical(df, FEAT_COLS)
    n = df.count()
    print(f'  Clean rows            : {n:,}')
    return df


def load_portscan(spark, label_udf, hdfs_path, split_name):
    sep(f'SOURCE C â€” CIC-2017 PortScan ({split_name})')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)
        .csv(hdfs_path)
    )
    print(f'  Raw rows : {df.count():,}')

    # CIC-2017 cols already canonical â€” just strip spaces from names
    for c in df.columns:
        stripped = c.strip()
        if stripped != c:
            df = df.withColumnRenamed(c, stripped)

    # Handle the duplicate 'Fwd Header Length' col (index 34 vs 55)
    # After strip+dedup in portscan_split.py it's named 'Fwd Header Length_2'
    if 'Fwd Header Length_2' in df.columns:
        df = df.drop('Fwd Header Length_2')

    df = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'PORTSCAN')
    df = clean_features(df, FEAT_COLS, label_udf)
    df = select_canonical(df, FEAT_COLS)
    n = df.count()
    print(f'  Clean rows : {n:,}')
    return df


def load_cic17_benign(spark, label_udf):
    sep('SOURCE D â€” CIC-2017 BENIGN (train split, deduped+grouped)')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)
        .csv(HDFS_BN_TRAIN)
    )
    print(f'  Raw rows : {df.count():,}')

    # CIC-2017 cols already canonical â€” strip whitespace
    for c in df.columns:
        stripped = c.strip()
        if stripped != c:
            df = df.withColumnRenamed(c, stripped)

    # Drop the duplicate Fwd Header Length col if present
    if 'Fwd Header Length_2' in df.columns:
        df = df.drop('Fwd Header Length_2')

    # Keep BENIGN only (the split file should only have BENIGN, but be safe)
    df = df.filter(F.upper(F.trim(F.col(LABEL_COL))) == 'BENIGN')
    df = clean_features(df, FEAT_COLS, label_udf)
    df = select_canonical(df, FEAT_COLS)
    n = df.count()
    print(f'  Clean rows : {n:,}')
    return df


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MAIN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    sep('THREVIA â€” Merge Unified Training Corpus')
    label_udf = make_label_udf(spark)

    # â”€â”€ Load sources â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    df_lycos    = load_lycos(spark, label_udf)
    df_cic18    = load_cic18_infiltration(spark, label_udf)
    df_ps_train = load_portscan(spark, label_udf, HDFS_PS_TRAIN, 'train')
    df_ps_test  = load_portscan(spark, label_udf, HDFS_PS_TEST,  'test')
    df_benign   = load_cic17_benign(spark, label_udf)          # Source D

    # â”€â”€ Merge training sources â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sep('MERGE â€” Training corpus (LycoS + CIC18-Infiltration + PortScan-train + CIC17-BENIGN)')

    # Source E: Friday DDoS train split (random 70%)
    sep('SOURCE E - Friday DDoS train split')
    df_ddos = spark.read.option('compression','snappy').parquet(HDFS_DDOS_TRAIN)
    df_ddos = clean_features(df_ddos, FEAT_COLS, label_udf)
    df_ddos = select_canonical(df_ddos, FEAT_COLS)
    print(f'  DDoS train rows : {df_ddos.count():,}')

    # Source F: Friday Bot train split (random 70%)
    sep('SOURCE F - Friday Bot train split')
    df_bot = spark.read.option('compression','snappy').parquet(HDFS_BOT_TRAIN)
    df_bot = clean_features(df_bot, FEAT_COLS, label_udf)
    df_bot = select_canonical(df_bot, FEAT_COLS)
    print(f'  Bot train rows  : {df_bot.count():,}')

    df_train = df_lycos.union(df_cic18).union(df_ps_train).union(df_benign).union(df_ddos).union(df_bot)
    df_train.cache()

    train_total = df_train.count()
    print(f'\n  Total training rows : {train_total:,}')

    # Impute nulls (LycoS is missing 5 canonical cols â†’ null-filled above)
    print('\n  Running null imputation on merged training set ...')
    df_train, _imputer_fill_map = impute_nulls(df_train, FEAT_COLS)

    # Label distribution
    sep('Training label distribution')
    label_dist = df_train.groupBy(LABEL_COL).count().orderBy(F.desc('count'))
    label_dist.show(30, truncate=False)

    benign_n  = df_train.filter(F.upper(F.col(LABEL_COL)) == 'BENIGN').count()
    attack_n  = train_total - benign_n
    print(f'  BENIGN : {benign_n:,}  ({benign_n/train_total*100:.1f}%)')
    print(f'  ATTACK : {attack_n:,}  ({attack_n/train_total*100:.1f}%)')
    print(f'  Imbalance ratio : {benign_n/max(attack_n,1):.2f}x')

    # â”€â”€ Assemble + Scale feature vector â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sep('Feature assembly + StandardScaler (fit on training only)')
    assembler = VectorAssembler(
        inputCols=FEAT_COLS, outputCol='raw_features', handleInvalid='keep'
    )
    scaler = StandardScaler(
        inputCol='raw_features', outputCol='scaled_features',
        withMean=True, withStd=True,
    )
    pipeline = Pipeline(stages=[assembler, scaler])
    pipe_model = pipeline.fit(df_train)   # FIT ON TRAIN ONLY - no leakage
    df_train = pipe_model.transform(df_train)

    # -- Save scaler pipeline to HDFS (Bug-1 fix) --------------------------
    # train_clean_corpus.py loads this instead of refitting on 10% sample,
    # ensuring external test sets are z-scored on identical mu/sigma to training.
    HDFS_SCALER  = f'{HDFS_ROOT}/models_clean/scaler_pipeline'
    HDFS_MEDIANS = f'{HDFS_ROOT}/models_clean/imputer_medians'
    sep(f'Saving scaler pipeline -> {HDFS_SCALER}')
    pipe_model.write().overwrite().save(HDFS_SCALER)
    print(f'  Scaler pipeline saved -> {HDFS_SCALER}')

    # Save imputer fill_map as single-row Parquet (Bug-2 fix).
    # External test sets impute with SAME medians as training.
    sep(f'Saving imputer medians -> {HDFS_MEDIANS}')
    if _imputer_fill_map:
        from pyspark.sql.types import StructType, StructField, DoubleType
        med_schema = StructType([
            StructField(c, DoubleType(), True) for c in _imputer_fill_map
        ])
        (spark.createDataFrame([_imputer_fill_map], schema=med_schema)
             .write.mode('overwrite').parquet(HDFS_MEDIANS))
        print(f'  Imputer medians saved ({len(_imputer_fill_map)} cols) -> {HDFS_MEDIANS}')
    else:
        print('  No nulls in training set - no imputer medians to save.')

    # -- Write training corpus ----------------------------------------------
    sep(f'Writing training corpus to {HDFS_TRAIN_OUT}')
    (
        df_train.write.mode('overwrite')
        .option('compression', 'snappy')
        .parquet(HDFS_TRAIN_OUT)
    )
    print(f'  Written : {train_total:,} rows -> {HDFS_TRAIN_OUT}')

    # â”€â”€ PortScan held-out test split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sep(f'Writing PortScan test split to {HDFS_PSTEST_OUT}')
    # Apply SAME pipeline transform (scaler fitted on train â€” correct)
    # Apply same training fill_map (not recomputed) - identical treatment to training
    if _imputer_fill_map:
        df_ps_test = df_ps_test.fillna(_imputer_fill_map, subset=list(_imputer_fill_map.keys()))
    df_ps_test = pipe_model.transform(df_ps_test)
    (
        df_ps_test.write.mode('overwrite')
        .option('compression', 'snappy')
        .parquet(HDFS_PSTEST_OUT)
    )
    ps_test_n = df_ps_test.count()
    print(f'  Written : {ps_test_n:,} rows -> {HDFS_PSTEST_OUT}')

    # â”€â”€ Final summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    sep('CORPUS MERGE COMPLETE')
    print(f"""
  Training corpus (v3 â€” log1p + CIC-2017 BENIGN mix):
    Sources    : LycoS + CICIDS2018-Infiltration + CIC-2017-PortScan(train) + CIC-2017-BENIGN(train)
    Total rows : {train_total:,}
    Features   : {len(FEAT_COLS)}  (scaled_features = StandardScaler output)
    log1p cols : Flow Duration, Flow Bytes/s, Flow Packets/s
    HDFS path  : {HDFS_TRAIN_OUT}

  Held-out PortScan test split:
    Rows       : {ps_test_n:,}
    HDFS path  : {HDFS_PSTEST_OUT}

  Scaler fit   : TRAIN ONLY (no test leakage)
  Dedup        : Done at source (PortScan: 42.9% removed, CIC18: deduped)
  Session split: PortScan grouped by Dst Port (port overlap=0)
    """)

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
