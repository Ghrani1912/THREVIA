# THREVIA Dashboard Launcher
# =============================
# Starts ONLY the dashboard and API without re-running training phases
#
# Usage:
#   .\start_dashboard.ps1

$ErrorActionPreference = "Stop"

function Write-Success($msg) {
    Write-Host "SUCCESS: $msg" -ForegroundColor Green
}

function Write-Info($msg) {
    Write-Host "INFO: $msg" -ForegroundColor Yellow
}

function Write-Error($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREVIA DASHBOARD LAUNCHER" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Verify trained models exist on HDFS
Write-Info "Checking trained models on HDFS..."
try {
    # Gate model is versioned (models_clean_v3 promoted); scaler/medians and the
    # Tier-2 Bot specialist stay in models_clean.
    docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean_v3/rf_binary 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Gate model found on HDFS (models_clean_v3, promoted)"
    } else {
        Write-Host "
WARNING: Trained models not found on HDFS." -ForegroundColor Red
        Write-Host "  Run the full pipeline first: .\\run_threvia_pipeline.ps1 -Phases 3" -ForegroundColor Yellow
        Write-Host "  Continuing anyway - API may return errors until models are trained.
" -ForegroundColor Yellow
    }
    docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean/rf_bot_binary 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Bot classifier (Tier-2) found on HDFS"
    } else {
        Write-Info "Bot specialist model not found (optional Tier-2 - run Phase 3 to build)"
    }
} catch {
    Write-Info "Could not check HDFS models (Docker may not be running yet)"
}

# Check Docker
Write-Info "Checking Docker containers..."
$containers = docker ps --format "{{.Names}}" 2>$null | Select-String "threvia"
if ($containers.Count -lt 1) {
    Write-Error "THREVIA containers not running."
    Write-Info "Starting Docker containers..."
    docker compose up -d
    Start-Sleep -Seconds 10
    Write-Success "Docker containers started"
} else {
    Write-Success "Docker containers running"
}

# Check/Create Python virtual environment for API
if (-not (Test-Path "backend/api/.venv")) {
    Write-Info "Creating Python virtual environment..."
    python -m venv backend/api/.venv
    Write-Success "Virtual environment created"
    
    Write-Info "Installing API dependencies..."
    & backend/api/.venv/Scripts/Activate.ps1
    pip install -q -r backend/api/requirements.txt
    Write-Success "Dependencies installed"
} else {
    Write-Success "Python virtual environment exists"
}

# Check if MongoDB has data
Write-Info "Checking MongoDB data..."
try {
    $evalCmd = 'db.security_events.countDocuments()'
    $mongoCheck = docker exec threvia-mongodb mongosh threvia --quiet --eval $evalCmd 2>$null
    $threatCount = [int]$mongoCheck
    
    if ($threatCount -eq 0) {
        Write-Info "MongoDB is empty. Populating with sample data..."
        & backend/api/.venv/Scripts/Activate.ps1
        python backend/realtime/populate_mongo.py
        Write-Success "Sample data populated"
    } else {
        Write-Success "MongoDB has $threatCount security events"
    }
} catch {
    Write-Info "Could not check MongoDB status (might not be running yet)"
}

# Start FastAPI server
Write-Info "Starting FastAPI backend server..."

# Check if server is already running
$existingServer = Get-Process python -ErrorAction SilentlyContinue | Where-Object {
    $_.CommandLine -like "*backend/api/main.py*"
}

if ($existingServer) {
    Write-Info "API server already running (PID: $($existingServer.Id))"
    Write-Info "To restart, first stop it with: Stop-Process -Id $($existingServer.Id)"
} else {
    # Start in new PowerShell window
    $scriptBlock = "cd '$PWD'; & backend/api/.venv/Scripts/Activate.ps1; Write-Host 'THREVIA API Server Starting...' -ForegroundColor Cyan; Write-Host 'Access dashboard at: http://localhost:8000/dashboard' -ForegroundColor Green; Write-Host 'Press Ctrl+C to stop' -ForegroundColor Yellow; python backend/api/main.py"
    
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $scriptBlock
    
    Write-Info "Waiting for API server to start..."
    Start-Sleep -Seconds 5
    
    # Test if API is responding
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/api/v1/health" -Method GET -TimeoutSec 5 -UseBasicParsing
        Write-Success "API server is responding"
    } catch {
        Write-Info "API server is starting (may take a few more seconds)"
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  DASHBOARD READY" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Success "THREVIA Dashboard is ready!"
Write-Host ""
Write-Info "Dashboard URL: http://localhost:8000/dashboard"
Write-Info "API Docs: http://localhost:8000/docs"
Write-Info "Health Check: http://localhost:8000/api/v1/health"
Write-Host ""
Write-Info "To stop the API server, close the PowerShell window or press Ctrl+C in it"
Write-Host ""

# Open dashboard in browser
Write-Info "Opening dashboard in browser..."
Start-Sleep -Seconds 2
Start-Process "http://localhost:8000/dashboard"

Write-Success "Done! Dashboard should open in your browser."
