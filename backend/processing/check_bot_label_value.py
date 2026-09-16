from pyspark.sql import SparkSession
spark = SparkSession.builder.appName('check').getOrCreate()
bot_test = spark.read.parquet('hdfs://namenode:8020/threvia/corpus/friday_bot_test')
labels = bot_test.select('Label').distinct().collect()
for row in labels:
    print(f"Label value: '{row['Label']}'")
print(f'Count: {bot_test.count()}')
spark.stop()
