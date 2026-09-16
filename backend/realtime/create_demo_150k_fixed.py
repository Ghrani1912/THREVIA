#!/usr/bin/env python3
"""
Create 150K balanced demo dataset for Phase 4 streaming - FIXED VERSION
Uses TRAINING data (real attacks) instead of TEST data (mislabeled)

50% BENIGN (75K) + 25% DDoS (37.5K) + 25% Bot (37.5K)
"""
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

spark = SparkSession.builder \
    .appName("Demo150K-Fixed") \
    .master("local[2]") \
    .config("spark.driver.memory", "2g") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

corpus = "hdfs://namenode:8020/threvia/corpus"

print("\n" + "="*80)
print("CREATING 150K BALANCED DEMO DATASET (FIXED - FROM TRAINING DATA)")
print("="*80)

# Load datasets - USE TRAINING DATA (real attacks)
print("\n1. Loading TRAINING data (real attacks)...")
ddos_df = spark.read.parquet(f"{corpus}/friday_ddos_train")    # ← CHANGED from _test
bot_df = spark.read.parquet(f"{corpus}/friday_bot_train")      # ← CHANGED from _test
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

print(f"\n3. Dataset sizes (TRAINING data):")
print(f"   DDoS:   {ddos_count:,} rows")
print(f"   Bot:    {bot_count:,} rows")
print(f"   BENIGN: {benign_count:,} rows")

# Verify DDoS quality - check avg Flow Packets/s (should be HIGH for real DDoS)
print(f"\n4. Verifying attack data quality...")
ddos_stats = ddos_df.agg(
    F.avg("Flow Packets/s").alias("avg_pps"),
    F.avg("Flow Duration").alias("avg_duration")
).collect()[0]
print(f"   DDoS avg Flow Packets/s: {ddos_stats['avg_pps']:.2f} (should be >1)")
print(f"   DDoS avg Flow Duration:  {ddos_stats['avg_duration']:.0f}")

if ddos_stats['avg_pps'] < 1.0:
    print(f"   ⚠️  WARNING: Low packets/s suggests BENIGN-like traffic!")
else:
    print(f"   ✓ Attack data looks legitimate")

# Target counts
TARGET_BENIGN = 75000
TARGET_DDOS = 37500
TARGET_BOT = 37500

print(f"\n5. Sampling to target:")
print(f"   BENIGN: {TARGET_BENIGN:,} rows (50%)")
print(f"   DDoS:   {TARGET_DDOS:,} rows (25%)")
print(f"   Bot:    {TARGET_BOT:,} rows (25%)")

# Sample with replacement if needed
benign_fraction = TARGET_BENIGN / benign_count
ddos_fraction = TARGET_DDOS / ddos_count
bot_fraction = TARGET_BOT / bot_count

# Use withReplacement=True if fraction > 1.0
benign_sample = benign_df.sample(
    withReplacement=(benign_fraction > 1.0), 
    fraction=min(benign_fraction, 1.0), 
    seed=42
).limit(TARGET_BENIGN)

ddos_sample = ddos_df.sample(
    withReplacement=(ddos_fraction > 1.0), 
    fraction=min(ddos_fraction, 1.0), 
    seed=42
).limit(TARGET_DDOS)

bot_sample = bot_df.sample(
    withReplacement=(bot_fraction > 1.0), 
    fraction=min(bot_fraction, 1.0), 
    seed=42
).limit(TARGET_BOT)

actual_benign = benign_sample.count()
actual_ddos = ddos_sample.count()
actual_bot = bot_sample.count()

print(f"\n6. Sampled:")
print(f"   BENIGN: {actual_benign:,}")
print(f"   DDoS:   {actual_ddos:,}")
print(f"   Bot:    {actual_bot:,}")

# Combine and shuffle
print(f"\n7. Combining and shuffling...")
demo_df = benign_sample.union(ddos_sample).union(bot_sample)

# Shuffle by adding random column, sorting, then dropping it
demo_df = demo_df.withColumn("_rand", F.rand(seed=42)).orderBy("_rand").drop("_rand")

total = demo_df.count()
print(f"   Total: {total:,} rows")

# Save to HDFS
output = f"{corpus}/demo_balanced_150k_fixed"
print(f"\n8. Saving to: {output}")
demo_df.coalesce(4).write.mode("overwrite").parquet(output)

print("\n" + "="*80)
print("✓ FIXED DEMO DATASET CREATED!")
print("="*80)

# Verify quality
print("\n9. Verifying final dataset quality:")
verify_df = spark.read.parquet(output)

print("\nLabel distribution:")
verify_df.groupBy("Label").count().orderBy("Label").show(10, False)

print("\nAverage Flow Packets/s by label (DDoS should be HIGH):")
verify_df.groupBy("Label").agg(
    F.avg("Flow Packets/s").alias("avg_pps")
).orderBy("avg_pps", ascending=False).show()

print("\nSample 5 DDoS rows:")
verify_df.filter(verify_df.Label == "DDoS").select(
    "Label", "Flow Duration", "Total Fwd Packets", "Flow Packets/s"
).show(5, False)

print(f"\n" + "="*80)
print(f"To use this dataset, update stream_simulator.py:")
print(f"")
print(f"_FRIDAY_PATHS = [")
print(f"    f\"{{_HDFS_CORPUS}}/demo_balanced_150k_fixed\",")
print(f"]")
print("="*80)

spark.stop()
