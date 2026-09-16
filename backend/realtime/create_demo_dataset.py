#!/usr/bin/env python3
"""
Create a balanced demo dataset for Phase 4 streaming
Includes all attack types + benign traffic for realistic dashboard demo
"""
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# Initialize Spark
spark = SparkSession.builder \
    .appName("CreateDemoDataset") \
    .master("local[*]") \
    .getOrCreate()

# Load the full training dataset
print("Loading full dataset from HDFS...")
df = spark.read.parquet("hdfs://namenode:8020/threvia/data_clean/combined_train.parquet")

print(f"Total rows: {df.count():,}")
print("\nLabel distribution:")
df.groupBy("Label").count().orderBy("count", ascending=False).show(20, False)

# Get attack types the model can classify
attack_types = [
    "BENIGN",           # Normal traffic
    "DoS Hulk",         # DDoS attack
    "PortScan",         # Port scanning
    "DDoS",             # Distributed DoS
    "DoS GoldenEye",    # DoS variant
    "FTP-Patator",      # FTP brute force
    "SSH-Patator",      # SSH brute force
    "DoS slowloris",    # Slow DoS
    "DoS Slowhttptest", # HTTP DoS
    "Bot",              # Botnet traffic
    "Web Attack – Brute Force",
    "Web Attack – XSS",
    "Web Attack – Sql Injection",
    "Infiltration",     # Infiltration attack
]

# Sample configuration: 150k total rows
target_total = 150000
benign_ratio = 0.50  # 50% benign traffic (realistic)
attack_ratio = 0.50   # 50% attacks

benign_count = int(target_total * benign_ratio)
attack_count = target_total - benign_count

# Distribute attacks equally across types
attack_types_only = [a for a in attack_types if a != "BENIGN"]
per_attack_count = attack_count // len(attack_types_only)

print(f"\nCreating demo dataset:")
print(f"  Total: {target_total:,} rows")
print(f"  BENIGN: {benign_count:,} rows ({benign_ratio*100:.0f}%)")
print(f"  Each attack type: ~{per_attack_count:,} rows")

# Sample from each category
sampled_dfs = []

# Sample BENIGN traffic
benign_df = df.filter(F.col("Label") == "BENIGN").sample(fraction=0.1, seed=42)
benign_sample = benign_df.limit(benign_count)
sampled_dfs.append(benign_sample)
print(f"✓ Sampled {benign_sample.count():,} BENIGN rows")

# Sample each attack type
for attack_type in attack_types_only:
    attack_df = df.filter(F.col("Label") == attack_type)
    attack_count_available = attack_df.count()
    
    if attack_count_available > 0:
        if attack_count_available < per_attack_count:
            # Take all available
            attack_sample = attack_df
            actual_count = attack_count_available
        else:
            # Sample the target amount
            fraction = min(1.0, (per_attack_count * 1.2) / attack_count_available)
            attack_sample = attack_df.sample(fraction=fraction, seed=42).limit(per_attack_count)
            actual_count = attack_sample.count()
        
        sampled_dfs.append(attack_sample)
        print(f"✓ Sampled {actual_count:,} {attack_type} rows")
    else:
        print(f"✗ No data for {attack_type}")

# Combine all samples
print("\nCombining samples...")
demo_df = sampled_dfs[0]
for df_part in sampled_dfs[1:]:
    demo_df = demo_df.union(df_part)

# Shuffle to mix attack types throughout the stream
print("Shuffling rows for realistic streaming...")
demo_df = demo_df.orderBy(F.rand(seed=42))

final_count = demo_df.count()
print(f"\nFinal dataset: {final_count:,} rows")

# Save to HDFS
output_path = "hdfs://namenode:8020/threvia/data_clean/demo_stream_dataset.parquet"
print(f"\nSaving to {output_path}...")
demo_df.write.mode("overwrite").parquet(output_path)

print("\n✓ Demo dataset created successfully!")
print("\nTo use this dataset:")
print("  1. Edit stream_simulator.py")
print("  2. Change HDFS_INPUT_PATH to:")
print(f"     {output_path}")
print("  3. Restart Terminal 1 (simulator)")

# Show distribution
print("\nFinal distribution:")
demo_df.groupBy("Label").count().orderBy("Label").show(30, False)

spark.stop()
