# THREVIA Quick Start
# ====================
# Use this to start THREVIA after initial setup is complete
# This does NOT rebuild models or reprocess data

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREVIA Quick Start" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Step 1: Check if Docker is running
Write-Host "[1/3] Checking Docker..." -ForegroundColor Yellow
$dockerRunning = docker ps 2>$null
if (-not $dockerRunning) {
    Write-Host "Docker not running. Starting containers..." -ForegroundColor Yellow
    docker compose up -d
    Write-Host "Waiting 30 seconds for services to start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
} else {
    Write-Host "Docker containers already running" -ForegroundColor Green
}

# Step 2: Check if MongoDB has data
Write-Host "`n[2/3] Checking MongoDB..." -ForegroundColor Yellow
try {
    $count = docker exec threvia-mongo mongosh threvia --quiet --eval 'db.security_events.countDocuments()' 2>$null
    if ($count -and $count -gt 0) {
        Write-Host "MongoDB has $count threat events" -ForegroundColor Green
    } else {
        Write-Host "MongoDB is empty. Populating with sample data..." -ForegroundColor Yellow
        python backend/realtime/stream_simulator.py --quick-populate
    }
} catch {
    Write-Host "Warning: Could not check MongoDB (container may still be starting)" -ForegroundColor Yellow
}

# Step 3: Start API server
Write-Host "`n[3/3] Starting API server..." -ForegroundColor Yellow

# Check if API is already running
$apiRunning = $false
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        $apiRunning = $true
    }
} catch {
    $apiRunning = $false
}

if ($apiRunning) {
    Write-Host "API server already running" -ForegroundColor Green
} else {
    Write-Host "Starting API server..." -ForegroundColor Yellow
    
    # Check if venv exists
    if (-not (Test-Path "backend/api/.venv")) {
        Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
        python -m venv backend/api/.venv
        & backend/api/.venv/Scripts/Activate.ps1
        pip install -q -r backend/api/requirements.txt
    }
    
    # Start API server in background
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; & backend/api/.venv/Scripts/Activate.ps1; python backend/api/main.py" -WindowStyle Minimized
    
    Write-Host "Waiting for API server to start..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}

# Step 4: Open dashboard
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  THREVIA Ready!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Dashboard: http://localhost:8000/dashboard" -ForegroundColor Cyan
Write-Host "API Docs:  http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "Spark UI:  http://localhost:8080" -ForegroundColor Cyan
Write-Host "HDFS UI:   http://localhost:9870`n" -ForegroundColor Cyan

Write-Host "Opening dashboard..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
Start-Process "http://localhost:8000/dashboard"

Write-Host "`nPress Ctrl+C to stop (or just close this window)" -ForegroundColor Gray
Write-Host "Dashboard will keep running in background`n" -ForegroundColor Gray

# Keep script alive so user knows it's running
while ($true) {
    Start-Sleep -Seconds 300
}
