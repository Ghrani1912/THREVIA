#!/bin/bash
# Phase 2 runner — executes both batch jobs inside the Spark container.
set -e
SPARK_SUBMIT=/opt/spark/bin/spark-submit
MASTER="spark://spark-master:7077"

echo "=== Job 1/2: Preprocessing ==="
$SPARK_SUBMIT --master "$MASTER" /workspace/backend/processing/preprocess.py

echo ""
echo "=== Job 2/2: MapReduce Attack Frequency ==="
$SPARK_SUBMIT --master "$MASTER" /workspace/backend/processing/attack_frequency_mapreduce.py

echo ""
echo "=== PHASE 2 ALL JOBS DONE ==="
