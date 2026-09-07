#!/bin/bash
# Run all 4 advanced evaluation experiments sequentially.
set -e
SS="/opt/spark/bin/spark-submit"
M="spark://spark-master:7077"
SCRIPT="/workspace/backend/ml/advanced_eval.py"

echo "============================================================"
echo " THREVIA — Advanced Evaluation (4 experiments)"
echo "============================================================"

for PART in stratified leakage openset clusters; do
  echo ""
  echo "============================================================"
  echo " >>> PART: $PART <<<"
  echo "============================================================"
  $SS --master "$M" --driver-memory 2g --executor-memory 2g "$SCRIPT" "$PART"
  echo " >>> DONE: $PART <<<"
done

echo ""
echo "============================================================"
echo " ALL 4 EXPERIMENTS COMPLETE"
echo "============================================================"
