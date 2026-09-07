#!/bin/bash
set -e
SS="/opt/spark/bin/spark-submit"
M="spark://spark-master:7077"
SCRIPT="/workspace/backend/ml/advanced_eval.py"

echo "Running Parts C + D..."
for PART in openset clusters; do
  echo "=== START: $PART ==="
  $SS --master "$M" --driver-memory 2g --executor-memory 2g "$SCRIPT" "$PART"
  echo "=== DONE: $PART ==="
done
echo "ALL DONE"
