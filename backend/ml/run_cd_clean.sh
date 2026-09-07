#!/bin/bash
# Kill any zombie CoarseGrainedExecutorBackend processes left by cancelled jobs
echo "[cleanup] Scanning for zombie executors in worker container..."
PIDS=$(docker exec threvia-spark-worker ps aux 2>/dev/null | grep CoarseGrained | grep -v grep | awk '{print $1}')
if [ -n "$PIDS" ]; then
  echo "[cleanup] Killing PIDs: $PIDS"
  for PID in $PIDS; do
    docker exec threvia-spark-worker kill -9 "$PID" 2>/dev/null && echo "[cleanup] killed $PID" || echo "[cleanup] $PID already gone"
  done
  sleep 4
else
  echo "[cleanup] No zombie executors found."
fi

echo ""
echo "=== START: openset ==="
docker exec threvia-spark-master /opt/spark/bin/spark-submit \
  --master spark://spark-master:7077 \
  --driver-memory 2g --executor-memory 2g \
  /workspace/backend/ml/advanced_eval.py openset
echo "=== DONE: openset ==="

echo ""
echo "[cleanup] Killing any new zombie executors before Part D..."
PIDS=$(docker exec threvia-spark-worker ps aux 2>/dev/null | grep CoarseGrained | grep -v grep | awk '{print $1}')
for PID in $PIDS; do
  docker exec threvia-spark-worker kill -9 "$PID" 2>/dev/null || true
done
sleep 4

echo ""
echo "=== START: clusters ==="
docker exec threvia-spark-master /opt/spark/bin/spark-submit \
  --master spark://spark-master:7077 \
  --driver-memory 2g --executor-memory 2g \
  /workspace/backend/ml/advanced_eval.py clusters
echo "=== DONE: clusters ==="

echo ""
echo "ALL DONE"
