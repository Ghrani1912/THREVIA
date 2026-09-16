# THREVIA Phase 4 - Detector Only (No Simulator)
# ================================================
# Runs ONLY the streaming detector to process data from the simulator
# The simulator must be started separately (in Docker)
#
# Usage:
#   Terminal 1: .\run_detector_only.ps1
#   Terminal 2: docker exec -it threvia-spark-master python3 /workspace/backend/realtime/run_phase4.py simulate

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREVIA STREAMING DETECTOR" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check Docker containers
$sparkMaster = docker ps --filter "name=threvia-spark-master" --format "{{.Names}}" 2>$null
$mongodb = docker ps --filter "name=threvia-mongodb" --format "{{.Names}}" 2>$null

if (-not $sparkMaster) {
    Write-Host "ERROR: threvia-spark-master container not running" -ForegroundColor Red
    Write-Host "Start it with: docker compose up -d" -ForegroundColor Yellow
    exit 1
}

if (-not $mongodb) {
    Write-Host "ERROR: threvia-mongodb container not running" -ForegroundColor Red
    Write-Host "Start it with: docker compose up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host "SUCCESS: Docker containers are running`n" -ForegroundColor Green

# Check models
Write-Host "Checking trained models on HDFS..." -ForegroundColor Yellow
$modelCheck = docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean/rf_binary 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Models not found on HDFS" -ForegroundColor Red
    Write-Host "Train models first with Phase 3" -ForegroundColor Yellow
    exit 1
}

Write-Host "SUCCESS: Models found on HDFS`n" -ForegroundColor Green

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  STARTING DETECTOR" -ForegroundColor Cyan  
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "INFO: Make sure the simulator is running:" -ForegroundColor Yellow
Write-Host "  docker exec -it threvia-spark-master python3 /workspace/backend/realtime/run_phase4.py simulate`n" -ForegroundColor Yellow

Write-Host "Starting detector (press Ctrl+C to stop)...`n" -ForegroundColor Green

docker exec -it threvia-spark-master spark-submit `
    --master spark://spark-master:7077 `
    --driver-memory 2g `
    --executor-memory 2g `
    --conf spark.driver.host=spark-master `
    --conf spark.executor.cores=2 `
    /workspace/backend/realtime/streaming_detector.py

Write-Host "`nDetector stopped." -ForegroundColor Yellow
