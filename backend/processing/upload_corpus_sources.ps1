# upload_corpus_sources.ps1
# Uploads the new dataset CSVs into HDFS so merge_corpus.py can read them.
# Run this ONCE from the host before running merge_corpus.py.
#
# Usage:
#   .\backend\processing\upload_corpus_sources.ps1

$NAMENODE = "threvia-namenode"
$WORKSPACE = "/workspace/backend"

function hdfs_mkdir($path) {
    docker exec $NAMENODE hdfs dfs -mkdir -p $path
}

function hdfs_put($local, $hdfs) {
    Write-Host "  Uploading $local -> $hdfs ..."
    docker exec $NAMENODE hdfs dfs -put -f $local $hdfs
    if ($LASTEXITCODE -eq 0) {
        $size = docker exec $NAMENODE hdfs dfs -du -h $hdfs 2>$null
        Write-Host "  OK  $size"
    } else {
        Write-Host "  FAILED -- check Docker mount and file path"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  THREVIA -- Upload corpus source files to HDFS"
Write-Host "============================================================"

# ── Create HDFS directories ───────────────────────────────────────────────────
Write-Host "`n[1] Creating HDFS directories ..."
hdfs_mkdir "/threvia/lycos_raw"
hdfs_mkdir "/threvia/cic18_raw"
hdfs_mkdir "/threvia/portscan_clean_raw/portscan_train"
hdfs_mkdir "/threvia/portscan_clean_raw/portscan_test"
hdfs_mkdir "/threvia/validation"
Write-Host "  Done."

# ── SOURCE A: LycoS (5.2 GB -- will take several minutes) ────────────────────
Write-Host "`n[2] Uploading LycoS-IDS2018.csv (5.2 GB -- be patient) ..."
hdfs_put "$WORKSPACE/data/LYCSOS/LycoS-Unicas-IDS2018.csv" "/threvia/lycos_raw/"

# ── SOURCE B: CICIDS2018 Thursday + Wednesday ─────────────────────────────────
Write-Host "`n[3] Uploading CICIDS2018 files ..."
hdfs_put "$WORKSPACE/data/CICIDS2018/CICIDS2018_Thursday.csv" "/threvia/cic18_raw/"
hdfs_put "$WORKSPACE/data/CICIDS2018/CICIDS2018_Wednesday.csv" "/threvia/cic18_raw/"

# ── SOURCE C: PortScan clean splits ──────────────────────────────────────────
Write-Host "`n[4] Uploading PortScan clean splits ..."
hdfs_put "$WORKSPACE/data/portscan_clean/portscan_train.csv" "/threvia/portscan_clean_raw/portscan_train/"
hdfs_put "$WORKSPACE/data/portscan_clean/portscan_test.csv"  "/threvia/portscan_clean_raw/portscan_test/"

# ── IDS2025 validation ────────────────────────────────────────────────────────
Write-Host "`n[5] Uploading IDS2025 validation CSV ..."
hdfs_put "$WORKSPACE/data/ids2025_clean/ids2025_validation.csv" "/threvia/validation/"

# ── Final listing ─────────────────────────────────────────────────────────────
Write-Host "`n[6] HDFS /threvia listing:"
docker exec $NAMENODE hdfs dfs -ls -R /threvia/ 2>&1 | Select-String "^d|^-" | ForEach-Object { Write-Host "  $_" }

Write-Host ""
Write-Host "============================================================"
Write-Host "  Upload complete. Now run merge_corpus.py."
Write-Host "  docker exec threvia-spark-master spark-submit \"
Write-Host "      --master spark://spark-master:7077 \"
Write-Host "      --driver-memory 3g --executor-memory 3g \"
Write-Host "      /workspace/backend/processing/merge_corpus.py"
Write-Host "============================================================"
