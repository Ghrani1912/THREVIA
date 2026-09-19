"""Measure the split-aware specialist's BENIGN FPR on the C2 holdout."""
import sys
sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel

HDFS_ROOT = 'hdfs://namenode:8020/threvia'

spark = (
    SparkSession.builder.appName('InfilSA-FPR')
    .config('spark.sql.shuffle.partitions', '16')
    .config('spark.ui.enabled', 'false')
    .getOrCreate()
)
spark.sparkContext.setLogLevel('ERROR')

from backend.processing.schema_maps import CANONICAL_FEATURE_COLS, LABEL_NORMALISE
from backend.ml.train_clean_corpus import clean_and_scale_external
from pyspark.sql.types import StringType

norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
bc = spark.sparkContext.broadcast(norm_map)
label_udf = F.udf(
    lambda raw: bc.value.get(raw.strip().upper(), raw.strip()) if raw else None,
    StringType(),
)
feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

pipe = PipelineModel.load(f'{HDFS_ROOT}/models_clean/scaler_pipeline')
med_row = spark.read.parquet(f'{HDFS_ROOT}/models_clean/imputer_medians').first()
medians = dict(med_row.asDict()) if med_row else {}
model = RandomForestClassificationModel.load(
    f'{HDFS_ROOT}/models_clean_v2/rf_infiltration_splitaware')

# NOTE: do NOT pre-select columns here.  The Friday parquets carry the
# 'Fwd Header Length34'/'Fwd Header Length55' duplicates and lack the canonical
# name; clean_and_scale_external renames them internally (the Step-7 fix).
benign = spark.read.parquet(f'{HDFS_ROOT}/corpus/friday_benign_c2')
scaled = clean_and_scale_external(
    spark, benign, feat_cols, pipe, label_udf, fill_map=medians).cache()
n = scaled.count()

# prediction == 1.0 means "Infiltration" at the model's default 0.5 cut
fp = model.transform(scaled).filter(F.col('prediction') == 1.0).count()
print(f'BENIGN rows: {n:,}')
print(f'Split-aware specialist BENIGN FP at default 0.5 cut: '
      f'{fp:,}/{n:,} = {fp / n * 100:.3f}%')

spark.stop()
sys.exit(0)
