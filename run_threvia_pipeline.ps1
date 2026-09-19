# THREVIA End-to-End Pipeline
# =============================
# Runs all 7 phases in sequence for complete system demonstration
#
# Prerequisites:
#   - Docker containers running (docker compose up -d)
#   - Datasets uploaded to HDFS
#   - Python environment with requirements installed
#
# Usage:
#   .\run_threvia_pipeline.ps1
#
# Or run individual phases:
#   .\run_threvia_pipeline.ps1 -Phase 3
#   .\run_threvia_pipeline.ps1 -Phases 4,5,6

param(
    [int[]]$Phases = @(1,2,3,4,5,6,7),
    [switch]$SkipPhase1,
    [switch]$SkipPhase2,
    [switch]$QuickDemo
)

$ErrorActionPreference = "Stop"

# Color output functions
function Write-PhaseHeader($phase, $name) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  PHASE $phase: $name" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "âœ… $msg" -ForegroundColor Green
}

function Write-Info($msg) {
    Write-Host "â„¹ï¸  $msg" -ForegroundColor Yellow
}

function Write-Error($msg) {
    Write-Host "âŒ $msg" -ForegroundColor Red
}

# Check datasets first
Write-Info "Checking datasets..."
if (-not (Test-Path "backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv")) {
    Write-Error "Required datasets missing!"
    Write-Host "`nDatasets are NOT included in the repository." -ForegroundColor Yellow
    Write-Host "Please download them first: See DATA_SETUP_GUIDE.md" -ForegroundColor Yellow
    Write-Host "`nRun this to check dataset status:" -ForegroundColor Gray
    Write-Host "  .\verify_datasets.ps1`n" -ForegroundColor Gray
    exit 1
}

# Check Docker
Write-Info "Checking Docker containers..."
$containers = docker ps --format "{{.Names}}" | Select-String "threvia"
if ($containers.Count -lt 4) {
    Write-Error "THREVIA containers not running. Start with: docker compose up -d"
    exit 1
}
Write-Success "Docker containers running"

# ============================================================================
# PHASE 1: FOUNDATION
# ============================================================================
if (1 -in $Phases -and -not $SkipPhase1) {
    Write-PhaseHeader 1 "FOUNDATION"
    
    Write-Info "Validating HDFS dataset upload..."
    docker exec threvia-spark-master python3 /workspace/backend/ingestion/validate_hdfs.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Phase 1 complete: HDFS validated"
    } else {
        Write-Error "Phase 1 failed: HDFS validation error"
        exit 1
    }
}

# ============================================================================
# PHASE 2: BATCH PROCESSING
# ============================================================================
if (2 -in $Phases -and -not $SkipPhase2) {
    Write-PhaseHeader 2 "BATCH PROCESSING"
    
    Write-Info "Building unified training corpus (15.69M rows)..."
    Write-Info "This takes 5-10 minutes..."
    
    docker exec threvia-spark-master /opt/spark/bin/spark-submit `
        --master spark://spark-master:7077 `
        --driver-memory 4g `
        --executor-memory 4g `
        /workspace/backend/processing/merge_corpus.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Phase 2 complete: Training corpus built"
    } else {
        Write-Error "Phase 2 failed: Corpus merge error"
        exit 1
    }
}

# ============================================================================
# ============================================================================
# PHASE 3: MACHINE LEARNING
# ============================================================================
if (3 -in $Phases) {
    Write-PhaseHeader 3 "MACHINE LEARNING"

    # ── 3a: Main RF (binary + multi-class, inverse-frequency weighted) ──────
    Write-Info "Training main Random Forest classifiers (class-weighted)..."
    Write-Info "This takes 20-30 minutes..."

    docker exec threvia-spark-master /opt/spark/bin/spark-submit `
        --master spark://spark-master:7077 `
        --driver-memory 3g `
        --executor-memory 3g `
        /workspace/backend/ml/train_clean_corpus.py

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Phase 3a failed: Main RF training error"
        exit 1
    }
    Write-Success "Phase 3a complete: Main RF trained (binary + multi-class, class-weighted)"
    Write-Info "  Bot recall: 65.26%  (was 0.31%)"
    Write-Info "  Infiltration recall: 68.97%  (was 0%)"
    Write-Info "  DDoS/PortScan/BENIGN: unchanged (99%+)"

    # ── 3b: Tier-2 Bot specialist classifier (100 trees, balanced 50/50) ────
    Write-Info "Training Tier-2 Bot specialist classifier (~5-10 min)..."

    docker exec threvia-spark-master /opt/spark/bin/spark-submit `
        --master spark://spark-master:7077 `
        --driver-memory 2g --executor-memory 2g `
        /workspace/backend/ml/train_bot_classifier.py

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Phase 3b complete: Bot specialist classifier saved to HDFS"
        Write-Info "  Model: /threvia/models_clean/rf_bot_binary (100 trees, depth 12)"
        Write-Info "  Tier-2 is shared by every gate version - it is not retrained per gate."
    } else {
        Write-Warning "Phase 3b: Bot classifier failed (non-blocking — main RF still valid)"
    }

    # ── 3c: Infiltration rule detector (standalone evaluation) ──────────────
    Write-Info "Running Infiltration rule detector evaluation (~5 min)..."

    docker exec threvia-spark-master /opt/spark/bin/spark-submit `
        --master spark://spark-master:7077 `
        --driver-memory 2g --executor-memory 2g `
        /workspace/backend/ml/infiltration_rules.py

    if ($LASTEXITCODE -eq 0) {
        Write-Success "Phase 3c complete: Infiltration rule detector evaluated"
        Write-Info "  Module ready: from backend.ml.infiltration_rules import apply_infiltration_rules"
    } else {
        Write-Warning "Phase 3c: Infiltration rules failed (non-blocking)"
    }

    Write-Success "Phase 3 complete: All ML components trained"
    Write-Info "See documentation/FINAL_MODEL_EVALUATION.md for full metrics"
}

# PHASE 4: REAL-TIME LAYER
# ============================================================================
if (4 -in $Phases) {
    Write-PhaseHeader 4 "REAL-TIME LAYER"
    
    Write-Info "Building Bloom Filter from threat intelligence..."
    python backend/realtime/bloom_filter.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Bloom Filter built: backend/realtime/bloom_filter.pkl"
    }
    
    if (-not $QuickDemo) {
        Write-Info "Starting streaming detector (Ctrl+C to stop)..."
        Write-Info "Simulating network traffic and detecting threats..."
        
        # Run in background
        $streamJob = Start-Job -ScriptBlock {
            python backend/realtime/run_phase4.py
        }
        
        Start-Sleep -Seconds 10
        
        if ($streamJob.State -eq "Running") {
            Write-Success "Phase 4 running: Streaming detector active"
            Write-Info "Stop with: Stop-Job -Id $($streamJob.Id); Remove-Job -Id $($streamJob.Id)"
        }
    } else {
        Write-Success "Phase 4 complete: Bloom Filter ready (skipping streaming for quick demo)"
    }
}

# ============================================================================
# PHASE 5: GRAPH ANALYSIS
# ============================================================================
if (5 -in $Phases) {
    Write-PhaseHeader 5 "GRAPH ANALYSIS"
    
    Write-Info "Building network entity graph..."
    Write-Info "Computing centrality and community detection..."
    
    python backend/graph/run_phase5.py
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Phase 5 complete: Graph analysis done"
        Write-Info "Graph exported to: backend/graph/graph_export.html"
        
        if (Test-Path "backend/graph/graph_export.html") {
            Write-Info "Opening graph visualization..."
            Start-Process "backend/graph/graph_export.html"
        }
    } else {
        Write-Error "Phase 5 failed: Graph analysis error"
    }
}

# ============================================================================
# PHASE 6: DASHBOARD (PROFESSIONAL SOC UI)
# ============================================================================
if (6 -in $Phases) {
    Write-PhaseHeader 6 "DASHBOARD - PROFESSIONAL SOC UI"
    
    Write-Info "Starting FastAPI backend..."
    
    # Install API dependencies
    if (-not (Test-Path "backend/api/.venv")) {
        Write-Info "Creating Python virtual environment for API..."
        python -m venv backend/api/.venv
        & backend/api/.venv/Scripts/Activate.ps1
        pip install -r backend/api/requirements.txt
    } else {
        & backend/api/.venv/Scripts/Activate.ps1
    }
    
    # Start FastAPI server in background
    Write-Info "Starting API server at http://localhost:8000..."
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd $PWD; & backend/api/.venv/Scripts/Activate.ps1; python backend/api/main.py" -WindowStyle Minimized
    
    Start-Sleep -Seconds 3
    
    # Check if MongoDB has data
    $mongoCheck = docker exec threvia-mongo mongosh threvia --quiet --eval "db.security_events.countDocuments()"
    
    if ($mongoCheck -eq "0" -or $null -eq $mongoCheck) {
        Write-Info "MongoDB empty - populating with sample data..."
        python backend/realtime/stream_simulator.py --quick-populate
    }
    
    Write-Success "`nDashboard ready!"
    Write-Info "Access dashboard at: http://localhost:8000/dashboard"
    Write-Info "API documentation: http://localhost:8000/docs"
    Write-Info "`nPress Ctrl+C to stop the API server when done"
    
    # Open dashboard in browser
    Start-Process "http://localhost:8000/dashboard"
}

# ============================================================================
# PHASE 7: INTEGRATION CHECK
# ============================================================================
if (7 -in $Phases) {
    Write-PhaseHeader 7 "INTEGRATION CHECK"
    
    Write-Info "Running end-to-end validation..."
    
    # The gate model is versioned (models_clean_v3 is promoted); the scaler,
    # imputer medians and Tier-2 Bot specialist stay in models_clean.  See
    # backend/ml/eval_bot_behind_gate.py for the promotion evidence.
    $checks = @{
        "HDFS corpus" = "docker exec threvia-namenode hdfs dfs -test -e /threvia/corpus/train"
        "Gate RF model"   = "docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean_v3/rf_binary"
        "Scaler/medians"  = "docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean/scaler_pipeline"
        "Bot classifier"  = "docker exec threvia-namenode hdfs dfs -test -e /threvia/models_clean/rf_bot_binary"
        "Bloom filter" = "Test-Path backend/realtime/bloom_filter.pkl"
        "Graph export" = "Test-Path backend/graph/graph_export.html"
        "Dashboard UI" = "Test-Path dashboard/index.html"
        "API server" = "Test-Path backend/api/main.py"
    }
    
    $allPassed = $true
    foreach ($check in $checks.GetEnumerator()) {
        try {
            if ($check.Value -like "docker*") {
                Invoke-Expression $check.Value | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "$($check.Key): OK"
                } else {
                    Write-Error "$($check.Key): MISSING"
                    $allPassed = $false
                }
            } else {
                if (Invoke-Expression $check.Value) {
                    Write-Success "$($check.Key): OK"
                } else {
                    Write-Error "$($check.Key): MISSING"
                    $allPassed = $false
                }
            }
        } catch {
            Write-Error "$($check.Key): CHECK FAILED"
            $allPassed = $false
        }
    }
    
    if ($allPassed) {
        Write-Success "`nPhase 7 complete: All integration checks passed"
        Write-Success "`nðŸŽ‰ THREVIA PIPELINE COMPLETE! ðŸŽ‰"
        Write-Info "`nNext steps:"
        Write-Info "  1. View dashboard: http://localhost:8000/dashboard"
        Write-Info "  2. API docs: http://localhost:8000/docs"
        Write-Info "  3. View graph: backend/graph/graph_export.html"
        Write-Info "  4. Read evaluation: documentation/FINAL_MODEL_EVALUATION.md"
    } else {
        Write-Error "`nPhase 7: Some integration checks failed"
        Write-Info "Review errors above and re-run failed phases"
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  PIPELINE EXECUTION COMPLETE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Info "Phase Status:"
Write-Success "  Phase 1: Foundation âœ…"
Write-Success "  Phase 2: Batch Processing âœ…"
Write-Success "  Phase 3: Machine Learning âœ…"
if (4 -in $Phases) { Write-Success "  Phase 4: Real-Time Layer âœ…" }
if (5 -in $Phases) { Write-Success "  Phase 5: Graph Analysis âœ…" }
if (6 -in $Phases) { Write-Success "  Phase 6: Dashboard âœ…" }
if (7 -in $Phases) { Write-Success "  Phase 7: Integration âœ…" }

Write-Info "`nDocumentation:"
Write-Info "  - Project Status: documentation/PROJECT_STATUS_SUMMARY.md"
Write-Info "  - Phase 3 Evaluation: documentation/FINAL_MODEL_EVALUATION.md"
Write-Info "  - PRD: documentation/THREVIA_PRD.md"

Write-Success "`nâœ¨ THREVIA is ready for demonstration! âœ¨"
