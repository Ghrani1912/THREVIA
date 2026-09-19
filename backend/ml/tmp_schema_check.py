from pyspark.sql import SparkSession
import pyspark.sql.functions as F

spark = SparkSession.builder.appName("schema2").config("spark.ui.enabled", "false").getOrCreate()
spark.sparkContext.setLogLevel("ERROR")

for p in ["demo_balanced_150k_fixed", "demo_balanced_150k"]:
    df = spark.read.parquet(f"hdfs://namenode:8020/threvia/corpus/{p}")
    cols = df.columns
    has_fhl = "Fwd Header Length" in cols
    has_fhl34 = "Fwd Header Length34" in cols
    print(f"{p}: FHL={has_fhl} FHL34={has_fhl34} scaled={'scaled_features' in cols} ncols={len(cols)}")
    if has_fhl:
        nn = df.filter(F.col("Fwd Header Length").isNotNull()).count()
        tot = df.count()
        print(f"   FHL non-null: {nn:,}/{tot:,}")
    if has_fhl34:
        nn34 = df.filter(F.col("Fwd Header Length34").isNotNull()).count()
        print(f"   FHL34 non-null: {nn34:,}")

spark.stop()
