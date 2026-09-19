from pyspark.sql import SparkSession
import pyspark.sql.functions as F

spark = SparkSession.builder.appName("fhl_audit").config("spark.ui.enabled", "false").getOrCreate()
spark.sparkContext.setLogLevel("ERROR")

df = spark.read.parquet("hdfs://namenode:8020/threvia/corpus/train")
tot = df.count()
print(f"corpus/train rows: {tot:,}")

if "Fwd Header Length" in df.columns:
    nn = df.filter(F.col("Fwd Header Length").isNotNull())
    n_nn = nn.count()
    print(f"Fwd Header Length non-null: {n_nn:,}/{tot:,} ({n_nn/tot*100:.2f}%)")
    print("Non-null breakdown by Label (top 8):")
    nn.groupBy("Label").count().orderBy(F.desc("count")).show(8, False)
    print("Null breakdown by Label (top 8):")
    df.filter(F.col("Fwd Header Length").isNull()).groupBy("Label").count().orderBy(F.desc("count")).show(8, False)
else:
    print("corpus/train has NO 'Fwd Header Length' column at all")

spark.stop()
