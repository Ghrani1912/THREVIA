# THREVIA Host Python Environment
# ==============================
# Creates ./.venv and installs the host-side dependencies, so the launchers and
# the phase runners work on a machine that has never run this project.
#
# Usage:
#   .\setup_env.ps1            # create .venv and install/update dependencies
#   .\setup_env.ps1 -Force     # delete .venv first, then recreate it
#
# What runs where:
#   - Containers (docker compose up -d): Spark, HDFS, MongoDB, and optionally
#     the simulator + detector (--profile phase4) and the API (--profile phase6).
#   - This .venv: the host-side Python that runs the launchers, the FastAPI
#     backend (start_dashboard.ps1), the phase runners and the test suites.
#   - backend/api/.venv is created separately by start_dashboard.ps1 and holds
#     only the API requirements; .venv is the superset that Phase 4/5 need.

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
$venv = Join-Path $root ".venv"

Write-Host "`n==========================================" -ForegroundColor Cyan
Write-Host "  THREVIA ENVIRONMENT SETUP" -ForegroundColor Cyan
Write-Host "==========================================`n" -ForegroundColor Cyan

# Python must exist before anything else
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "ERROR: 'python' is not on PATH. Install Python 3.10+ and retry." -ForegroundColor Red
    exit 1
}
Write-Host "Python: $(& python --version)" -ForegroundColor Gray

if ($Force -and (Test-Path $venv)) {
    Write-Host "Removing existing .venv (-Force)..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $venv
}

if (-not (Test-Path $venv)) {
    Write-Host "Creating virtual environment at .venv ..." -ForegroundColor Yellow
    python -m venv $venv
} else {
    Write-Host "Virtual environment already exists - updating it." -ForegroundColor Gray
}

$activate = Join-Path $venv "Scripts/Activate.ps1"
& $activate

Write-Host "`nInstalling host dependencies (a few minutes the first time)..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
python -m pip install --quiet -r (Join-Path $root "requirements-dev.txt")

Write-Host "`nVerifying the imports the launchers depend on..." -ForegroundColor Yellow
python -c "import pymongo, fastapi, pybloom_live, pytest; print('OK: pymongo', pymongo.version, '| fastapi', fastapi.__version__, '| pytest', pytest.__version__)"

Write-Host "`n==========================================" -ForegroundColor Green
Write-Host "  ENVIRONMENT READY" -ForegroundColor Green
Write-Host "==========================================`n" -ForegroundColor Green

Write-Host "Activate it in each new shell before running host-side Python:" -ForegroundColor Cyan
Write-Host "  .\.venv\Scripts\Activate.ps1`n" -ForegroundColor Gray

Write-Host "Then the usual entry points work on this machine:" -ForegroundColor Cyan
Write-Host "  docker compose up -d                    # infra (HDFS + Spark + MongoDB)" -ForegroundColor Gray
Write-Host "  .\run_threvia_pipeline.ps1              # full pipeline" -ForegroundColor Gray
Write-Host "  .\start_dashboard.ps1                   # dashboard + API only" -ForegroundColor Gray
Write-Host "  .\verify_datasets.ps1                   # check the datasets are in place`n" -ForegroundColor Gray

Write-Host "Test suites:" -ForegroundColor Cyan
Write-Host "  python backend/realtime/test_online_learning.py" -ForegroundColor Gray
Write-Host "  python backend/realtime/test_detection_policy.py`n" -ForegroundColor Gray
