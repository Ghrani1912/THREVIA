# THREVIA — Upload raw datasets to HDFS
# =====================================
# Phase 1 (validate_hdfs.py) checks that the eight CIC-IDS-2017 CSVs exist in
# HDFS at /threvia/raw, and Phase 2 reads its sources from /threvia/*.
# Something has to put them there: this script. It replaces the old one-shot
# `hdfs-init` container, which ran at `docker compose up` — before the datasets
# (which are not in git) had necessarily been downloaded.
#
# Usage:
#   .\upload_datasets.ps1           # raw CIC-IDS-2017 CSVs -> /threvia/raw
#   .\upload_datasets.ps1 -All      # also upload the Phase 2 corpus sources
#   .\upload_datasets.ps1 -Force    # re-upload files that already exist in HDFS
#
# Safe to re-run: files already present in HDFS are skipped unless -Force.

param(
    [switch]$All,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$NAMENODE = "threvia-namenode"
$LOCAL_RAW = "backend/data/CIC-IDS- 2017"
$HDFS_RAW = "/threvia/raw"

$RAW_FILES = @(
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
)

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  THREVIA -- Upload datasets to HDFS" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# The NameNode container must be up; it is the only service with the HDFS CLI.
$running = docker ps --format "{{.Names}}" 2>$null | Select-String -SimpleMatch $NAMENODE
if (-not $running) {
    Write-Host "ERROR: $NAMENODE is not running." -ForegroundColor Red
    Write-Host "  Start the stack first:  docker compose up -d`n" -ForegroundColor Gray
    exit 1
}

if (-not (Test-Path $LOCAL_RAW)) {
    Write-Host "ERROR: $LOCAL_RAW not found." -ForegroundColor Red
    Write-Host "  Datasets are not in git. See documentation/DATA_SETUP_GUIDE.md," -ForegroundColor Gray
    Write-Host "  then re-run:  .\verify_datasets.ps1`n" -ForegroundColor Gray
    exit 1
}

# ── Directories Phase 1 expects ───────────────────────────────────────────────
Write-Host "[1/3] Creating HDFS directories ..." -ForegroundColor Yellow
foreach ($dir in @("/threvia/raw", "/threvia/processed", "/threvia/output")) {
    docker exec $NAMENODE hdfs dfs -mkdir -p $dir | Out-Null
    Write-Host "  ok  $dir" -ForegroundColor Gray
}

# ── The eight CIC-IDS-2017 CSVs ───────────────────────────────────────────────
Write-Host "`n[2/3] Uploading CIC-IDS-2017 CSVs to $HDFS_RAW ..." -ForegroundColor Yellow
$uploaded = 0
$skipped = 0
$missing = 0

foreach ($name in $RAW_FILES) {
    $local = Join-Path $LOCAL_RAW $name
    if (-not (Test-Path $local)) {
        Write-Host "  MISSING locally: $name" -ForegroundColor Red
        $missing++
        continue
    }

    $exists = $false
    if (-not $Force) {
        docker exec $NAMENODE hdfs dfs -test -e "$HDFS_RAW/$name" 2>$null
        $exists = ($LASTEXITCODE -eq 0)
    }

    if ($exists) {
        Write-Host "  skip  $name (already in HDFS)" -ForegroundColor DarkGray
        $skipped++
        continue
    }

    # The NameNode mounts ./backend at /workspace/backend (see docker-compose.yml).
    docker exec $NAMENODE hdfs dfs -put -f "/workspace/$local" "$HDFS_RAW/" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  ok    $name" -ForegroundColor Green
        $uploaded++
    } else {
        Write-Host "  FAILED $name" -ForegroundColor Red
    }
}

# ── Phase 2 corpus sources (optional) ─────────────────────────────────────────
Write-Host "`n[3/3] Phase 2 corpus sources ..." -ForegroundColor Yellow
if ($All) {
    Write-Host "  Running backend/processing/upload_corpus_sources.ps1 ..." -ForegroundColor Gray
    & "backend/processing/upload_corpus_sources.ps1"
} else {
    Write-Host "  Skipped. Phase 2 (corpus merge) also needs LycoS-IDS2018, CICIDS2018 Thu/Wed" -ForegroundColor Gray
    Write-Host "  and the PortScan splits in HDFS. Upload them with:" -ForegroundColor Gray
    Write-Host "    .\upload_datasets.ps1 -All" -ForegroundColor Gray
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  uploaded=$uploaded  already-present=$skipped  missing-local=$missing" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

if ($missing -gt 0) {
    Write-Host "Some files were missing locally -- Phase 1 will report them." -ForegroundColor Yellow
    Write-Host "See documentation/DATA_SETUP_GUIDE.md for download instructions.`n" -ForegroundColor Gray
    exit 1
}

Write-Host "Next: validate the upload" -ForegroundColor Green
Write-Host "  docker exec $NAMENODE python3 /workspace/backend/ingestion/validate_hdfs.py`n" -ForegroundColor Gray
