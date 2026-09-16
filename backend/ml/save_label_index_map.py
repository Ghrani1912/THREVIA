"""
save_label_index_map.py -- Exports the StringIndexer label order used during
training as a Parquet table at hdfs://namenode:8020/threvia/models_clean/label_index_map
so the streaming detector can load label_index_map[idx] -> label_name at runtime.
"""
import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession
import pyspark.sql.functions as F
from pyspark.sql.types import IntegerType, StringType, StructType, StructField

HDFS = "hdfs://namenode:8020/threvia"
HDFS_TRAIN = f"{HDFS}/corpus/train"
HDFS_OUT   = f"{HDFS}/models_clean/label_index_map"

spark = (SparkSession.builder
         .appName("Threvia-SaveLabelMap")
         .config("spark.sql.shuffle.partitions", "4")
         .getOrCreate())
spark.sparkContext.setLogLevel("WARN")

from pyspark.ml.feature import StringIndexer

# Fit StringIndexer on training corpus to get canonical label order
train = spark.read.parquet(HDFS_TRAIN)
indexer = StringIndexer(inputCol="Label", outputCol="attack_type_idx", handleInvalid="keep")
idx_model = indexer.fit(train)

labels = idx_model.labels
print(f"  Found {len(labels)} labels:")
for i, label in enumerate(labels):
    print(f"    {i}: {label}")

# Build a small 2-column dataframe: idx (int) -> label (str)
schema = StructType([
    StructField("idx",   IntegerType(), False),
    StructField("label", StringType(),  False),
])
rows = [(i, label) for i, label in enumerate(labels)]
lm_df = spark.createDataFrame(rows, schema=schema)
lm_df.write.mode("overwrite").parquet(HDFS_OUT)
print(f"\n  Saved label_index_map to {HDFS_OUT}")

spark.stop()
