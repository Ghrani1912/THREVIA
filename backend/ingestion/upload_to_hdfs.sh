#!/bin/bash
set -e
echo "=== THREVIA Phase 1: Uploading CICIDS2017 to HDFS ==="
DATA_DIR="/workspace/backend/data"
HDFS_PATH="/threvia/raw"

for f in "$DATA_DIR"/*.csv; do
    filename=$(basename "$f")
    echo "Uploading: $filename"
    hdfs dfs -put -f "$f" "$HDFS_PATH/"
    echo "  Done: $filename"
done

echo ""
echo "=== Upload complete. Listing /threvia/raw: ==="
hdfs dfs -ls "$HDFS_PATH"
echo "=== ALL DONE ==="
