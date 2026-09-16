# THREVIA Phase 4 Launcher (Docker-based)
# =========================================
# Runs the real-time detection pipeline inside the Spark container
#
# Usage:
#   .\run_phase4_docker.ps1 bloom      # Build Bloom filter only
#   .\run_phase4_docker.ps1 simulate   # Run simulator only
#   .\run_phase4_docker.ps1 detect     # Run detector only
#   .\run_phase4_docker.ps1 all        # Run both (recommended)

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("bloom", "simulate", "detect", "all")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREVIA PHASE 4 - REAL-TIME DETECTION" -ForegroundColor Cyan
Write-Host "  Mode: $Mode" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if containers are running
Write-Host "INFO: Checking Docker containers..." -ForegroundColor Yellow
$containers = docker ps --filter "name=threvia" --format "{{.Names}}" | Select-String "spark-master|mongodb"

if ($containers.Count -lt 2) {
    Write-Host "ERROR: Required containers not running. Start them first:" -ForegroundColor Red
    Write-Host "  docker compose up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host "SUCCESS: Docker containers are running" -ForegroundColor Green

# Check if models exist on HDFS
if ($Mode -eq "detect" -or $Mode -eq "all") {
    Write-Host "`nINFO: Verifying trained models on HDFS..." -ForegroundColor Yellow
    
    $modelCheck = docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean/rf_binary 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Trained models not found on HDFS." -ForegroundColor Red
        Write-Host "  Run Phase 3 first to train the models:" -ForegroundColor Yellow
        Write-Host "  docker exec threvia-spark-master spark-submit --master spark://spark-master:7077 /workspace/backend/ml/train_clean_corpus.py" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "SUCCESS: Models found on HDFS" -ForegroundColor Green
}

# MongoDB connection check
Write-Host "`nINFO: Testing MongoDB connection..." -ForegroundColor Yellow
$mongoTest = docker exec threvia-mongodb mongosh threvia --quiet --eval "db.runCommand({ping:1}).ok" 2>$null
if ($mongoTest -match "1") {
    Write-Host "SUCCESS: MongoDB is accessible" -ForegroundColor Green
} else {
    Write-Host "WARNING: MongoDB may not be ready (continuing anyway)" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  STARTING PHASE 4: $Mode" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

switch ($Mode) {
    "bloom" {
        Write-Host "Building Bloom Filter (this may take ~30 seconds)...`n" -ForegroundColor Yellow
        docker exec -it threvia-spark-master bash -c `
            "export PYTHONPATH=/workspace && /opt/spark/bin/spark-submit --master local[1] --driver-memory 1g /workspace/backend/realtime/run_phase4.py bloom"
    }
    
    "simulate" {
        Write-Host "Starting Stream Simulator on port 9999..." -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow
        docker exec -it threvia-spark-master bash -c `
            "export PYTHONPATH=/workspace && /opt/spark/bin/spark-submit --master local[1] --driver-memory 1g /workspace/backend/realtime/run_phase4.py simulate"
    }
    
    "detect" {
        Write-Host "Starting Spark Streaming Detector..." -ForegroundColor Yellow
        Write-Host "Make sure simulator is running in another terminal!" -ForegroundColor Yellow
        Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow
        docker exec -it threvia-spark-master bash -c `
            "export PYTHONPATH=/workspace && export MONGO_URI=mongodb://threvia-mongodb:27017/ && /opt/spark/bin/spark-submit --master local[2] --driver-memory 1g /workspace/backend/realtime/streaming_detector.py"
    }
    
    "all" {
        Write-Host "Starting both Simulator and Detector...`n" -ForegroundColor Yellow
        Write-Host "INFO: The simulator will run in the background" -ForegroundColor Yellow
        Write-Host "INFO: The detector will run in the foreground" -ForegroundColor Yellow
        Write-Host "INFO: Press Ctrl+C to stop both`n" -ForegroundColor Yellow
        
        # Start simulator in background
        Write-Host "Starting simulator in background..." -ForegroundColor Yellow
        $simJob = Start-Job -ScriptBlock {
            docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && /opt/spark/bin/spark-submit --master local[1] --driver-memory 1g /workspace/backend/realtime/run_phase4.py simulate"
        }
        
        Write-Host "Waiting 5 seconds for simulator to initialize...`n" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        
        # Start detector in foreground (blocks until Ctrl+C)
        Write-Host "Starting detector...`n" -ForegroundColor Green
        try {
            docker exec -it threvia-spark-master bash -c `
                "export PYTHONPATH=/workspace && export MONGO_URI=mongodb://threvia-mongodb:27017/ && /opt/spark/bin/spark-submit --master local[2] --driver-memory 1g /workspace/backend/realtime/streaming_detector.py"
        }
        finally {
            Write-Host "`nStopping simulator..." -ForegroundColor Yellow
            Stop-Job -Job $simJob
            Remove-Job -Job $simJob
            Write-Host "Cleanup complete." -ForegroundColor Green
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PHASE 4 STOPPED" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
