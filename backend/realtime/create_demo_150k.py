#!/usr/bin/env python3
"""
Create 150K balanced demo dataset for Phase 4 streaming
50% BENIGN (75K) + 50% Attacks (37.5K DDoS + 37.5K Bot)
"""
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

spark = SparkSession.builder \
    .appName("Demo150K") \
    .master("local[2]") \
    .config("spark.driver.memory", "2g") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

corpus = "hdfs://namenode:8020/threvia/corpus"

print("\n" + "="*80)
print("CREATING 150K BALANCED DEMO DATASET")
print("="*80)

# Load datasets
print("\n1. Loading data...")
ddos_df = spark.read.parquet(f"{corpus}/friday_ddos_test")
bot_df = spark.read.parquet(f"{corpus}/friday_bot_test")
benign_df = spark.read.parquet(f"{corpus}/friday_benign_c2")

# Fix duplicate 'Fwd Header Length' column (Friday CSV bug)
# CIC-2017 Friday has duplicate columns at positions 34 and 55
# Spark renames them to 'Fwd Header Length34' and 'Fwd Header Length55'
# Models expect canonical 'Fwd Header Length' - rename and drop duplicate
print("\n2. Fixing 'Fwd Header Length' duplicate columns...")
for df_name, df in [("DDoS", ddos_df), ("Bot", bot_df), ("BENIGN", benign_df)]:
    if 'Fwd Header Length34' in df.columns:
        df = df.withColumnRenamed('Fwd Header Length34', 'Fwd Header Length')
        print(f"   {df_name}: Renamed 'Fwd Header Length34' → 'Fwd Header Length'")
    if 'Fwd Header Length55' in df.columns:
        df = df.drop('Fwd Header Length55')
        print(f"   {df_name}: Dropped 'Fwd Header Length55'")
    # Update references
    if df_name == "DDoS":
        ddos_df = df
    elif df_name == "Bot":
        bot_df = df
    else:
        benign_df = df

ddos_count = ddos_df.count()
bot_count = bot_df.count()
benign_count = benign_df.count()

print(f"\n3. Dataset sizes:")
print(f"   DDoS:   {ddos_count:,} rows")
print(f"   Bot:    {bot_count:,} rows")
print(f"   BENIGN: {benign_count:,} rows")

# Target counts
TARGET_BENIGN = 75000
TARGET_DDOS = 37500
TARGET_BOT = 37500

print(f"\n4. Sampling to target:")
print(f"   BENIGN: {TARGET_BENIGN:,} rows (50%)")
print(f"   DDoS:   {TARGET_DDOS:,} rows (25%)")
print(f"   Bot:    {TARGET_BOT:,} rows (25%)")

# Sample with replacement if needed
benign_sample = benign_df.sample(withReplacement=False, fraction=TARGET_BENIGN/benign_count, seed=42).limit(TARGET_BENIGN)
ddos_sample = ddos_df.sample(withReplacement=True, fraction=TARGET_DDOS/ddos_count, seed=42).limit(TARGET_DDOS)
bot_sample = bot_df.sample(withReplacement=True, fraction=TARGET_BOT/bot_count, seed=42).limit(TARGET_BOT)

actual_benign = benign_sample.count()
actual_ddos = ddos_sample.count()
actual_bot = bot_sample.count()

print(f"\n5. Sampled:")
print(f"   BENIGN: {actual_benign:,}")
print(f"   DDoS:   {actual_ddos:,}")
print(f"   Bot:    {actual_bot:,}")

# Combine and shuffle
print(f"\n6. Combining and shuffling...")
demo_df = benign_sample.union(ddos_sample).union(bot_sample)

# Shuffle by adding random column, sorting, then dropping it
demo_df = demo_df.withColumn("_rand", F.rand(seed=42)).orderBy("_rand").drop("_rand")

total = demo_df.count()
print(f"   Total: {total:,} rows")

# Save to HDFS
output = f"{corpus}/demo_balanced_150k"
print(f"\n7. Saving to: {output}")
demo_df.coalesce(4).write.mode("overwrite").parquet(output)

print("\n" + "="*80)
print("✓ DEMO DATASET CREATED!")
print("="*80)

# Verify
print("\nFinal distribution:")
verify_df = spark.read.parquet(output)
verify_df.groupBy("Label").count().orderBy("Label").show(10, False)

print(f"\nTo use this dataset:")
print(f"  1. Edit: backend/realtime/stream_simulator.py")
print(f"  2. Change _FRIDAY_PATHS to:")
print(f"     _FRIDAY_PATHS = [")
print(f"         f\"{{_HDFS_CORPUS}}/demo_balanced_150k\",")
print(f"     ]")
print(f"  3. Restart Terminal 1 (simulator)")
print(f"  4. You'll see attacks much sooner (every ~75K rows)")

spark.stop()
