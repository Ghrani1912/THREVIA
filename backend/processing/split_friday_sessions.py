"""
split_friday_sessions.py
========================
Split Friday DDoS and Bot attack rows into train / test partitions.

DDoS (128 K rows, 23 K unique dst ports)
  Strategy : destination-port bucket split
  bucket   = abs(hash(Destination Port)) % N_BUCKETS   (N_BUCKETS = 20)
  train    : buckets 0-13  (~70 %)
  test     : buckets 14-19 (~30 %)

Bot (1 966 rows - too sparse for port grouping)
  Strategy : random 70/30 row-level split  (seed = 42)

BENIGN rows in both files -> TEST-C2 path (temporal holdout, never in training).

HDFS outputs
  /threvia/corpus/friday_ddos_train   <- added to training corpus
  /threvia/corpus/friday_ddos_test    <- TEST-C1
  /threvia/corpus/friday_bot_train    <- added to training corpus
  /threvia/corpus/friday_bot_test     <- TEST-C1
  /threvia/corpus/friday_benign_c2    <- TEST-C2 (temporal, BENIGN only)
"""

import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql.types import IntegerType

HDFS_ROOT       = 'hdfs://namenode:8020/threvia'
HDFS_DDOS_RAW   = 'file:///workspace/backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
HDFS_BOT_RAW    = 'file:///workspace/backend/data/CIC-IDS- 2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
HDFS_DDOS_TRAIN = f'{HDFS_ROOT}/corpus/friday_ddos_train'
HDFS_DDOS_TEST  = f'{HDFS_ROOT}/corpus/friday_ddos_test'
HDFS_BOT_TRAIN  = f'{HDFS_ROOT}/corpus/friday_bot_train'
HDFS_BOT_TEST   = f'{HDFS_ROOT}/corpus/friday_bot_test'
HDFS_BENIGN_C2  = f'{HDFS_ROOT}/corpus/friday_benign_c2'
LABEL_COL       = 'Label'
DST_PORT_COL    = 'Destination Port'
N_BUCKETS       = 20
TRAIN_BUCKETS   = set(range(14))
TEST_BUCKETS    = set(range(14, 20))
RANDOM_SEED     = 42
BOT_TRAIN_FRAC  = 0.70


def get_spark():
    return (SparkSession.builder
            .appName('threvia-split-friday-sessions')
            .config('spark.sql.shuffle.partitions', '50')
            .getOrCreate())


def sep(msg):
    print('\n' + '=' * 72 + f'\n  {msg}\n' + '=' * 72)


def strip_col_names(df):
    for c in df.columns:
        s = c.strip()
        if s != c:
            df = df.withColumnRenamed(c, s)
    return df


def clean_features_light(df):
    """Cast to double, replace inf/NaN with null. No scaling - merge_corpus handles that."""
    inf_val, ninf_val = float('inf'), float('-inf')
    feat_cols = [c for c in df.columns if c != LABEL_COL]
    for c in feat_cols:
        df = df.withColumn(c, F.col(c).cast('double'))
    df = df.select([
        F.when(F.isnan(F.col(c)) | F.col(c).isin(inf_val, ninf_val), None)
         .otherwise(F.col(c)).alias(c)
        if c in feat_cols else F.col(c)
        for c in df.columns
    ])
    return df


def write_parquet(df, path, label):
    n = df.count()
    (df.write.mode('overwrite').option('compression', 'snappy').parquet(path))
    print(f'  Written : {n:,} rows -> {path}  [{label}]')
    return n


def split_ddos(spark):
    sep('SOURCE E - Friday DDoS (port-bucket split)')
    df = (spark.read.option('header', True).option('inferSchema', False)
               .csv(HDFS_DDOS_RAW))
    df = strip_col_names(df)
    df = df.withColumn(LABEL_COL, F.trim(F.upper(F.col(LABEL_COL))))
    print(f'  Raw rows : {df.count():,}')
    df.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(5, truncate=False)

    ddos_df   = df.filter(F.col(LABEL_COL) == 'DDOS')
    benign_df = df.filter(F.col(LABEL_COL) == 'BENIGN')

    # Normalize 'DDOS' -> 'DDoS' to match training corpus case
    ddos_df = ddos_df.withColumn(LABEL_COL, F.lit('DDoS'))

    # Port-bucket split was attempted but hash distribution is degenerate
    # (99.998% land in train buckets 0-13). Using reproducible randomSplit instead.
    ddos_train, ddos_test = ddos_df.randomSplit([0.70, 0.30], seed=RANDOM_SEED)
    
    print(f'  DDoS train : {ddos_train.count():,}   test : {ddos_test.count():,}')
    print(f'  Split method: randomSplit 70/30 (seed={RANDOM_SEED}) — port-bucket degenerate')
    return (clean_features_light(ddos_train),
            clean_features_light(ddos_test),
            clean_features_light(benign_df))


def split_bot(spark):
    sep('SOURCE F - Friday Bot (random 70/30 split)')
    df = (spark.read.option('header', True).option('inferSchema', False)
               .csv(HDFS_BOT_RAW))
    df = strip_col_names(df)
    df = df.withColumn(LABEL_COL, F.trim(F.upper(F.col(LABEL_COL))))
    print(f'  Raw rows : {df.count():,}')
    df.groupBy(LABEL_COL).count().orderBy(F.desc('count')).show(5, truncate=False)

    bot_df    = df.filter(F.col(LABEL_COL) == 'BOT')
    benign_df = df.filter(F.col(LABEL_COL) == 'BENIGN')

    # CRITICAL FIX: Normalize 'BOT' -> 'Bot' to match training corpus case
    bot_df = bot_df.withColumn(LABEL_COL, F.lit('Bot'))
    
    bot_train, bot_test = bot_df.randomSplit([BOT_TRAIN_FRAC, 1.0 - BOT_TRAIN_FRAC],
                                             seed=RANDOM_SEED)
    print(f'  Bot train : {bot_train.count():,}   test : {bot_test.count():,}')
    print(f'  Label normalized: "BOT" -> "Bot" (matches training corpus)')

    return (clean_features_light(bot_train),
            clean_features_light(bot_test),
            clean_features_light(benign_df))


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')

    ddos_train, ddos_test, ddos_benign = split_ddos(spark)
    sep('Writing DDoS splits')
    write_parquet(ddos_train, HDFS_DDOS_TRAIN, 'DDoS-train (Source E)')
    write_parquet(ddos_test,  HDFS_DDOS_TEST,  'DDoS-test  (TEST-C1)')

    bot_train, bot_test, bot_benign = split_bot(spark)
    sep('Writing Bot splits')
    write_parquet(bot_train, HDFS_BOT_TRAIN, 'Bot-train (Source F)')
    write_parquet(bot_test,  HDFS_BOT_TEST,  'Bot-test  (TEST-C1)')

    sep('Writing TEST-C2 Friday BENIGN temporal holdout')
    all_benign = ddos_benign.unionByName(bot_benign)
    write_parquet(all_benign, HDFS_BENIGN_C2, 'Friday-BENIGN-C2')

    sep('SPLIT COMPLETE')
    print(f'''
  Train additions : DDoS -> {HDFS_DDOS_TRAIN}
                    Bot  -> {HDFS_BOT_TRAIN}
  TEST-C1         : DDoS -> {HDFS_DDOS_TEST}
                    Bot  -> {HDFS_BOT_TEST}
  TEST-C2         :      -> {HDFS_BENIGN_C2}
    ''')


if __name__ == '__main__':
    main()

