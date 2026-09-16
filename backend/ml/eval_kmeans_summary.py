"""
Quick K-Means Clustering Summary
=================================
Reads the trained K-Means model and cluster assignments to provide a verdict.

Usage:
    spark-submit eval_kmeans_summary.py
"""

from pyspark.sql import SparkSession
import pyspark.sql.functions as F

HDFS_CLUSTERS = 'hdfs://namenode:8020/threvia/output/clusters'

def get_spark():
    return SparkSession.builder.appName('kmeans-summary').getOrCreate()

def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('WARN')
    
    print('\n' + '=' * 72)
    print('  K-MEANS CLUSTERING SUMMARY')
    print('=' * 72)
    
    # Load cluster assignments
    clusters = spark.read.parquet(HDFS_CLUSTERS)
    total = clusters.count()
    
    print(f'\n  Total flows clustered: {total:,}')
    print(f'  Columns: {clusters.columns}')
    
    # Cluster sizes
    print('\n  Cluster distribution:')
    cluster_sizes = clusters.groupBy('cluster').count().orderBy('cluster')
    cluster_sizes.show(20, truncate=False)
    
    # Purity analysis: what % of each cluster is attack vs benign?
    print('\n  Cluster purity (attack vs BENIGN):')
    purity = (
        clusters.groupBy('cluster', 'is_attack')
        .count()
        .orderBy('cluster', F.desc('count'))
    )
    
    # Pivot to show attack/benign split per cluster
    purity_pivot = purity.groupBy('cluster').pivot('is_attack', [0, 1]).sum('count')
    purity_pivot = purity_pivot.fillna(0)
    purity_pivot = purity_pivot.withColumn(
        'total', F.col('0') + F.col('1')
    ).withColumn(
        'attack_pct', (F.col('1') / (F.col('0') + F.col('1')) * 100).cast('decimal(10,2)')
    )
    print('\n  Cluster | BENIGN | ATTACK | Total | Attack %')
    print('  ' + '-' * 60)
    for row in purity_pivot.orderBy('cluster').collect():
        print(f"  {row['cluster']:<8} | {int(row['0']):>6,} | {int(row['1']):>6,} | {int(row['total']):>6,} | {row['attack_pct']:>7}%")
    
    # Label diversity: how many unique attack types per cluster?
    print('\n  Label diversity per cluster:')
    label_div = (
        clusters.groupBy('cluster')
        .agg(
            F.countDistinct('Label').alias('unique_labels'),
            F.collect_set('Label').alias('labels')
        )
        .orderBy('cluster')
    )
    label_div.show(20, truncate=False)
    
    # Overall purity score
    # For each cluster, find dominant label and count how many rows match it
    from pyspark.sql.window import Window
    
    dominant = (
        clusters.groupBy('cluster', 'Label')
        .count()
        .withColumn('rank', F.row_number().over(
            Window.partitionBy('cluster').orderBy(F.desc('count'))
        ))
        .filter(F.col('rank') == 1)
        .select('cluster', F.col('Label').alias('dominant_label'), F.col('count').alias('dominant_count'))
    )
    
    cluster_totals = clusters.groupBy('cluster').count().withColumnRenamed('count', 'total')
    purity_score = dominant.join(cluster_totals, 'cluster')
    purity_score = purity_score.withColumn('purity', F.col('dominant_count') / F.col('total'))
    
    avg_purity = purity_score.agg(F.avg('purity')).collect()[0][0]
    
    print(f'\n  Average cluster purity: {avg_purity:.2%}')
    print('  (% of flows in each cluster matching the dominant label)')
    
    print('\n' + '=' * 72)
    print('  VERDICT')
    print('=' * 72)
    print(f"""
  K-Means Clustering (k=10):
    - Average purity: {avg_purity:.2%}
    - {"✅ HIGH PURITY — Clusters align well with attack types" if avg_purity > 0.80
       else "⚠️  MODERATE PURITY — Some mixed clusters" if avg_purity > 0.60
       else "❌ LOW PURITY — Clusters don't align with attack labels"}
    
  Unsupervised clustering is useful for:
    ✓ Anomaly detection (outliers from all clusters)
    ✓ Discovering unknown attack patterns
    ✓ Grouping similar behaviors without labels
    
  But for classification (known attack types):
    → Supervised models (Random Forest) are more accurate
    → K-Means cannot predict attack type names, only cluster IDs
    """)
    
    spark.stop()

if __name__ == '__main__':
    main()
