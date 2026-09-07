"""
Task 4 — Merge Unified Training Corpus
========================================
Assembles the clean training corpus from four sources:

  SOURCE A  LycoS-IDS2018
            13.69M rows, re-extracted from raw pcaps (no zero-var signatures
            beyond tool artifacts), no PortScan, no Infiltration
            → column rename via LYCOS_RENAME, drop LYCOS_EXTRA_DROP
            → null-fill LYCOS_MISSING_FROM_LYCOS

  SOURCE B  CICIDS2018 Thursday + Wednesday (Infiltration only)
            93,063 + 68,871 = 161,934 rows of Infiltration
            Diagnostic: 8 zero-var cols, all shared CICFlowMeter artifacts
            → column rename via CIC18_RENAME, drop CIC18_EXTRA_DROP
            → header-contamination rows ("Label" in label col) dropped

  SOURCE C  CIC-2017 PortScan (train split only)
            72,706 rows, deduped (42.9% dups removed), port-grouped split
            (port overlap=0, vec leakage=0 across train/test boundary)
            → already uses canonical column names (just strip whitespace)

Outputs:
  HDFS /threvia/corpus/train     — merged training Parquet (snappy)
  HDFS /threvia/corpus/portscan_test  — held-out PortScan test split

Pipeline per source:
  1. Read CSV(s)
  2. Rename columns to canonical schema
  3. Drop source-only columns
  4. Normalise Label via LABEL_NORMALISE
  5. Cast all feature cols to double
  6. Replace inf/-inf/NaN with null; impute nulls with column median
  7. Add is_attack binary (0=BENIGN, 1=attack)

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

# ── HDFS paths ────────────────────────────────────────────────────────────────
HDFS_ROOT       = 'hdfs://namenode:8020/threvia'
HDFS_LYCOS      = f'{HDFS_ROOT}/lycos_raw'          # uploaded separately (see below)
HDFS_CIC18      = f'{HDFS_ROOT}/cic18_raw'          # uploaded separately
HDFS_PS_TRAIN   = f'{HDFS_ROOT}/portscan_clean_raw/portscan_train'
HDFS_PS_TEST    = f'{HDFS_ROOT}/portscan_clean_raw/portscan_test'

HDFS_TRAIN_OUT  = f'{HDFS_ROOT}/corpus/train'
HDFS_PSTEST_OUT = f'{HDFS_ROOT}/corpus/portscan_test'

# Feature cols (no Label, no derived cols)
FEAT_COLS = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']
LABEL_COL = 'Label'


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


# ── label normalisation UDF ────────────────────────────────────────────────────
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


# ── shared cleaning pipeline ───────────────────────────────────────────────────
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
            # Column missing in this source — add as null
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
    """Impute nulls with column medians (computed on df itself — train only)."""
    null_cols = [c for c in feat_cols
                 if df.filter(F.col(c).isNull()).count() > 0]
    if not null_cols:
        print('  No nulls to impute.')
        return df
    print(f'  Imputing {len(null_cols)} columns with median ...')
    medians = (
        df.select([
            F.percentile_approx(F.col(c), 0.5, 1000).alias(c)
            for c in null_cols
        ]).first().asDict()
    )
    fill_map = {c: float(medians[c]) for c in null_cols if medians[c] is not None}
    return df.fillna(fill_map, subset=list(fill_map.keys()))


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


# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE LOADERS
# ═══════════════════════════════════════════════════════════════════════════════

def load_lycos(spark, label_udf):
    sep('SOURCE A — LycoS-IDS2018')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)   # all string initially — we cast below
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
    sep('SOURCE B — CICIDS2018 Infiltration (Thu + Wed)')
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
    sep(f'SOURCE C — CIC-2017 PortScan ({split_name})')
    df = (
        spark.read.option('header', True)
        .option('inferSchema', False)
        .csv(hdfs_path)
    )
    print(f'  Raw rows : {df.count():,}')

    # CIC-2017 cols already canonical — just strip spaces from names
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


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    sep('THREVIA — Merge Unified Training Corpus')
    label_udf = make_label_udf(spark)

    # ── Load sources ──────────────────────────────────────────────────────────
    df_lycos   = load_lycos(spark, label_udf)
    df_cic18   = load_cic18_infiltration(spark, label_udf)
    df_ps_train = load_portscan(spark, label_udf, HDFS_PS_TRAIN, 'train')
    df_ps_test  = load_portscan(spark, label_udf, HDFS_PS_TEST,  'test')

    # ── Merge training sources ────────────────────────────────────────────────
    sep('MERGE — Training corpus (LycoS + CIC18-Infiltration + PortScan-train)')
    df_train = df_lycos.union(df_cic18).union(df_ps_train)
    df_train.cache()

    train_total = df_train.count()
    print(f'\n  Total training rows : {train_total:,}')

    # Impute nulls (LycoS is missing 5 canonical cols → null-filled above)
    print('\n  Running null imputation on merged training set ...')
    df_train = impute_nulls(df_train, FEAT_COLS)

    # Label distribution
    sep('Training label distribution')
    label_dist = df_train.groupBy(LABEL_COL).count().orderBy(F.desc('count'))
    label_dist.show(30, truncate=False)

    benign_n  = df_train.filter(F.upper(F.col(LABEL_COL)) == 'BENIGN').count()
    attack_n  = train_total - benign_n
    print(f'  BENIGN : {benign_n:,}  ({benign_n/train_total*100:.1f}%)')
    print(f'  ATTACK : {attack_n:,}  ({attack_n/train_total*100:.1f}%)')
    print(f'  Imbalance ratio : {benign_n/max(attack_n,1):.2f}x')

    # ── Assemble + Scale feature vector ──────────────────────────────────────
    sep('Feature assembly + StandardScaler (fit on training only)')
    assembler = VectorAssembler(
        inputCols=FEAT_COLS, outputCol='raw_features', handleInvalid='keep'
    )
    scaler = StandardScaler(
        inputCol='raw_features', outputCol='scaled_features',
        withMean=True, withStd=True,
    )
    pipeline = Pipeline(stages=[assembler, scaler])
    pipe_model = pipeline.fit(df_train)   # FIT ON TRAIN ONLY — no leakage
    df_train = pipe_model.transform(df_train)

    # ── Write training corpus ─────────────────────────────────────────────────
    sep(f'Writing training corpus to {HDFS_TRAIN_OUT}')
    (
        df_train.write.mode('overwrite')
        .option('compression', 'snappy')
        .parquet(HDFS_TRAIN_OUT)
    )
    print(f'  Written : {train_total:,} rows -> {HDFS_TRAIN_OUT}')

    # ── PortScan held-out test split ──────────────────────────────────────────
    sep(f'Writing PortScan test split to {HDFS_PSTEST_OUT}')
    # Apply SAME pipeline transform (scaler fitted on train — correct)
    df_ps_test = impute_nulls(df_ps_test, FEAT_COLS)
    df_ps_test = pipe_model.transform(df_ps_test)
    (
        df_ps_test.write.mode('overwrite')
        .option('compression', 'snappy')
        .parquet(HDFS_PSTEST_OUT)
    )
    ps_test_n = df_ps_test.count()
    print(f'  Written : {ps_test_n:,} rows -> {HDFS_PSTEST_OUT}')

    # ── Final summary ─────────────────────────────────────────────────────────
    sep('CORPUS MERGE COMPLETE')
    print(f"""
  Training corpus:
    Sources    : LycoS + CICIDS2018-Infiltration + CIC-2017-PortScan(train)
    Total rows : {train_total:,}
    Features   : {len(FEAT_COLS)}  (scaled_features = StandardScaler output)
    HDFS path  : {HDFS_TRAIN_OUT}

  Held-out PortScan test split:
    Rows       : {ps_test_n:,}
    HDFS path  : {HDFS_PSTEST_OUT}

  Scaler fit : TRAIN ONLY (no test leakage)
  Dedup      : Done at source (PortScan: 42.9% removed, CIC18: deduped)
  Session split: PortScan grouped by Dst Port (port overlap=0)
    """)

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
