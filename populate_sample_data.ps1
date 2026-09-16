# THREVIA Sample Data Populator
# ===============================
# Populates MongoDB with sample security events for dashboard testing
#
# Usage:
#   .\populate_sample_data.ps1

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
Write-Host "  THREVIA SAMPLE DATA POPULATOR" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if MongoDB container is running
$mongoRunning = docker ps --format "{{.Names}}" | Select-String "threvia-mongodb"
if (-not $mongoRunning) {
    Write-Error "MongoDB container is not running!"
    Write-Info "Start it with: docker compose up -d"
    exit 1
}
Write-Success "MongoDB container is running"

# Check current document count
Write-Info "Checking current database status..."
try {
    $evalCmd = 'db.security_events.countDocuments()'
    $currentCount = docker exec threvia-mongodb mongosh threvia --quiet --eval $evalCmd 2>$null
    $count = [int]$currentCount
    Write-Info "Current documents in database: $count"
    
    if ($count -gt 0) {
        Write-Host "`nDatabase already has data." -ForegroundColor Yellow
        $response = Read-Host "Do you want to add more sample data anyway? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Info "Cancelled by user"
            exit 0
        }
    }
} catch {
    Write-Info "Could not check database status, proceeding anyway..."
}

# Check if virtual environment exists
if (-not (Test-Path "backend/api/.venv")) {
    Write-Info "Python virtual environment not found. Creating it..."
    python -m venv backend/api/.venv
    Write-Success "Virtual environment created"
    
    Write-Info "Installing dependencies..."
    & backend/api/.venv/Scripts/Activate.ps1
    pip install -q pymongo
    Write-Success "Dependencies installed"
} else {
    Write-Success "Virtual environment exists"
}

# Activate virtual environment
& backend/api/.venv/Scripts/Activate.ps1

# Check if stream_simulator.py exists
if (-not (Test-Path "backend/realtime/stream_simulator.py")) {
    Write-Error "stream_simulator.py not found at backend/realtime/"
    exit 1
}

Write-Info "Starting sample data generation..."
Write-Host "`nThis will create sample security events in MongoDB"
Write-Host "Press Ctrl+C to cancel`n" -ForegroundColor Gray

# Run the populator
Write-Info "Running MongoDB populator..."
try {
    python backend/realtime/populate_mongo.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "`nSample data population complete!"
        
        # Check new count
        Start-Sleep -Seconds 2
        $newCount = docker exec threvia-mongodb mongosh threvia --quiet --eval $evalCmd 2>$null
        $finalCount = [int]$newCount
        Write-Success "Database now has $finalCount documents"
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  NEXT STEPS" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        Write-Info "1. Start the dashboard (if not running):"
        Write-Host "   .\start_dashboard.ps1`n" -ForegroundColor Gray
        
        Write-Info "2. Open in browser:"
        Write-Host "   http://localhost:8000/dashboard`n" -ForegroundColor Gray
        
        Write-Info "3. Refresh the page (F5) if already open"
        
    } else {
        Write-Error "Sample data population failed"
        Write-Info "Make sure pymongo is installed: pip install pymongo"
        exit 1
    }
} catch {
    Write-Error "Error during population: $($_.Exception.Message)"
    exit 1
}

Write-Success "`nDone!"
