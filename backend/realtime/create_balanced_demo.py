#!/usr/bin/env python3
"""
Create balanced demo dataset (100-150K rows) with all attack types
Uses actual HDFS corpus data that simulator streams from
"""
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

spark = SparkSession.builder \
    .appName("CreateBalancedDemo") \
    .master("local[*]") \
    .config("spark.driver.memory", "4g") \
    .getOrCreate()

print("=" * 80)
print("THREVIA Phase 4 - Balanced Demo Dataset Creator")
print("=" * 80)

# Load all available corpus data
corpus_base = "hdfs://namenode:8020/threvia/corpus"

datasets = [
    ("friday_ddos_test", f"{corpus_base}/friday_ddos_test"),
    ("friday_ddos_train", f"{corpus_base}/friday_ddos_train"),
    ("friday_bot_test", f"{corpus_base}/friday_bot_test"),
    ("friday_bot_train", f"{corpus_base}/friday_bot_train"),
    ("friday_benign_c2", f"{corpus_base}/friday_benign_c2"),
]

print("\n1. Loading all corpus datasets...")
all_dfs = []
for name, path in datasets:
    try:
        df = spark.read.parquet(path)
        count = df.count()
        print(f"   ✓ {name:25} {count:>8,} rows")
        all_dfs.append(df)
    except Exception as e:
        print(f"   ✗ {name:25} (not found or error)")

# Combine all datasets
print("\n2. Combining all datasets...")
combined_df = all_dfs[0]
for df in all_dfs[1:]:
    combined_df = combined_df.union(df)

total_rows = combined_df.count()
print(f"   Total combined: {total_rows:,} rows")

# Check label distribution
print("\n3. Attack type distribution:")
label_dist = combined_df.groupBy("Label").count().orderBy("count", ascending=False)
label_dist.show(50, False)

# Get unique labels
labels_df = label_dist.collect()
labels = [row["Label"] for row in labels_df]

print(f"\n4. Found {len(labels)} unique attack types:")
for label in labels:
    print(f"   - {label}")

# Target configuration
TARGET_TOTAL = 150000
BENIGN_RATIO = 0.50  # 50% benign
ATTACK_RATIO = 0.50   # 50% attacks (distributed across all types)

benign_count = int(TARGET_TOTAL * BENIGN_RATIO)
attack_labels = [l for l in labels if l.upper() != "BENIGN"]
attacks_total = TARGET_TOTAL - benign_count
per_attack_count = attacks_total // len(attack_labels) if attack_labels else 0

print(f"\n5. Demo dataset configuration:")
print(f"   Total target:         {TARGET_TOTAL:,} rows")
print(f"   BENIGN:               {benign_count:,} rows ({BENIGN_RATIO*100:.0f}%)")
print(f"   Attacks (total):      {attacks_total:,} rows ({ATTACK_RATIO*100:.0f}%)")
print(f"   Per attack type:      ~{per_attack_count:,} rows")

# Sample data
print(f"\n6. Sampling data...")
sampled_parts = []

# Sample BENIGN
benign_df = combined_df.filter(F.upper(F.col("Label")) == "BENIGN")
benign_available = benign_df.count()
if benign_available > 0:
    if benign_available >= benign_count:
        fraction = min(1.0, (benign_count * 1.5) / benign_available)
        benign_sample = benign_df.sample(fraction=fraction, seed=42).limit(benign_count)
    else:
        benign_sample = benign_df
    actual_benign = benign_sample.count()
    sampled_parts.append(benign_sample)
    print(f"   ✓ BENIGN: {actual_benign:,} rows")

# Sample each attack type
for attack_label in attack_labels:
    attack_df = combined_df.filter(F.col("Label") == attack_label)
    attack_available = attack_df.count()
    
    if attack_available > 0:
        if attack_available >= per_attack_count:
            fraction = min(1.0, (per_attack_count * 1.5) / attack_available)
            attack_sample = attack_df.sample(fraction=fraction, seed=42).limit(per_attack_count)
        else:
            attack_sample = attack_df  # Take all available
        
        actual_count = attack_sample.count()
        sampled_parts.append(attack_sample)
        print(f"   ✓ {attack_label}: {actual_count:,} rows")

# Combine and shuffle
print(f"\n7. Combining and shuffling samples...")
demo_df = sampled_parts[0]
for part in sampled_parts[1:]:
    demo_df = demo_df.union(part)

# Shuffle rows for realistic streaming (attacks mixed throughout)
demo_df = demo_df.orderBy(F.rand(seed=42))

final_count = demo_df.count()
print(f"   Final dataset: {final_count:,} rows")

# Save to HDFS
output_path = f"{corpus_base}/demo_balanced_150k"
print(f"\n8. Saving to HDFS: {output_path}")
demo_df.write.mode("overwrite").parquet(output_path)

print("\n" + "=" * 80)
print("✓ BALANCED DEMO DATASET CREATED!")
print("=" * 80)
print("\nFinal distribution:")
demo_df.groupBy("Label").count().orderBy("Label").show(50, False)

print(f"\nTo use this dataset:")
print(f"  1. Edit: backend/realtime/stream_simulator.py")
print(f"  2. Replace _FRIDAY_PATHS with:")
print(f"     [\"{output_path}\"]")
print(f"  3. Restart Terminal 1 (simulator)")
print(f"  4. Clear MongoDB: docker exec threvia-mongodb mongosh threvia --quiet --eval \"db.stream_alerts.deleteMany({{}}); db.ml_alerts.deleteMany({{}}); db.bloom_hits.deleteMany({{}})\"")

spark.stop()
