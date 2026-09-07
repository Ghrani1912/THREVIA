#!/bin/bash
# Phase 3 runner — trains classifiers then clustering inside Spark container.
set -e
SPARK_SUBMIT=/opt/spark/bin/spark-submit
MASTER="spark://spark-master:7077"

echo "========================================"
echo " THREVIA Phase 3 — Machine Learning"
echo "========================================"

echo ""
echo "=== Job 1/2: Classification (RF + LR, binary + multi-class) ==="
$SPARK_SUBMIT --master "$MASTER" \
  --driver-memory 2g \
  --executor-memory 2g \
  /workspace/backend/ml/train_classifier.py

echo ""
echo "=== Job 2/2: K-Means Clustering ==="
$SPARK_SUBMIT --master "$MASTER" \
  --driver-memory 2g \
  --executor-memory 2g \
  /workspace/backend/ml/train_clustering.py

echo ""
echo "========================================"
echo " PHASE 3 ALL JOBS DONE"
echo "========================================"
