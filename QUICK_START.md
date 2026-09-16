# THREVIA Quick Start Guide

## Starting the Dashboard (Fastest Way)

If you've already trained the models and just want to view the dashboard:

```powershell
.\start_dashboard.ps1
```

This script will:
1. ✅ Check if Docker containers are running (starts them if needed)
2. ✅ Create Python virtual environment (only first time)
3. ✅ Check if MongoDB has data (populates sample data if empty)
4. ✅ Start the FastAPI backend server
5. ✅ Open the dashboard in your browser

**Dashboard URL:** http://localhost:8000/dashboard

---

## Understanding the Project Phases

### Why Phases Run Each Time?

The `run_threvia_pipeline.ps1` script is designed to run the **complete ML pipeline** from scratch. This includes:

1. **Phase 1**: HDFS validation
2. **Phase 2**: Merge datasets (15.69M rows) - takes 5-10 minutes
3. **Phase 3**: Train ML models - takes 10-15 minutes
4. **Phase 4**: Build Bloom filter
5. **Phase 5**: Graph analysis
6. **Phase 6**: Start dashboard
7. **Phase 7**: Integration tests

**This is by design** - it demonstrates the full pipeline for academic/showcase purposes.

### What is "Creating Python Virtual Environment"?

A **Python virtual environment** is an isolated Python environment that:
- Keeps project dependencies separate from your system Python
- Prevents version conflicts between projects
- Allows you to have different package versions for different projects

When you see "Creating Python virtual environment...", it means:
- Python is creating a folder (`backend/api/.venv`) with its own Python installation
- Installing only the packages needed for this project
- **This only happens once** - subsequent runs will reuse it

---

## Running Individual Components

### Just the Dashboard (Skip Training)
```powershell
.\start_dashboard.ps1
```

### Full Pipeline (All 7 Phases)
```powershell
.\run_threvia_pipeline.ps1
```

### Run Specific Phases
```powershell
# Run only Phase 3 (ML training)
.\run_threvia_pipeline.ps1 -Phases 3

# Run Phases 4, 5, 6
.\run_threvia_pipeline.ps1 -Phases 4,5,6
```

### Populate MongoDB with Sample Data
```powershell
# Activate the API virtual environment first
& backend/api/.venv/Scripts/Activate.ps1

# Run the simulator
python backend/realtime/stream_simulator.py --quick-populate
```

---

## Common Issues

### 1. "Dashboard is empty / no threats showing"

**Cause:** MongoDB has no security events yet.

**Solution:**
```powershell
& backend/api/.venv/Scripts/Activate.ps1
python backend/realtime/stream_simulator.py --quick-populate
```

Then refresh the dashboard (F5).

### 2. "API Connection Failed"

**Cause:** FastAPI server isn't running on port 8000.

**Solution:**
```powershell
# Check if running
Get-Process python | Where-Object {$_.CommandLine -like "*main.py*"}

# If not running, start it
.\start_dashboard.ps1
```

### 3. "Docker containers not running"

**Solution:**
```powershell
docker compose up -d
```

### 4. Why does everything run again when I restart?

The **full pipeline** (`run_threvia_pipeline.ps1`) is designed to demonstrate the complete ML workflow. 

**To just view the dashboard without retraining:**
Use `start_dashboard.ps1` instead!

---

## Project Structure Quick Reference

```
Threvia/
├── backend/
│   ├── api/
│   │   ├── main.py              ← FastAPI server
│   │   ├── requirements.txt     ← API dependencies
│   │   └── .venv/              ← Virtual environment (auto-created)
│   ├── data/                   ← Datasets (not in git)
│   ├── ml/                     ← Phase 3: Training scripts
│   ├── realtime/              ← Phase 4: Bloom filter & streaming
│   │   └── stream_simulator.py ← Generates sample threats
│   └── graph/                 ← Phase 5: Network graph
├── dashboard/
│   ├── index.html             ← Professional SOC UI
│   └── app.js                 ← Dashboard logic
├── start_dashboard.ps1        ← 🚀 QUICK START (dashboard only)
├── run_threvia_pipeline.ps1   ← Full 7-phase pipeline
└── docker-compose.yml         ← Spark, MongoDB, HDFS containers
```

---

## Key URLs

After starting:

| Component | URL |
|-----------|-----|
| **Dashboard** | http://localhost:8000/dashboard |
| API Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/api/v1/health |
| Spark Master UI | http://localhost:8080 |
| Hadoop NameNode | http://localhost:9870 |

---

## For Deployment/Demo

### Scenario 1: Fresh Demo (Full Pipeline)
```powershell
# Takes 20-30 minutes, shows complete ML workflow
.\run_threvia_pipeline.ps1
```

### Scenario 2: Quick Demo (Dashboard Only)
```powershell
# Takes 30 seconds, assumes models already trained
.\start_dashboard.ps1
```

### Scenario 3: Someone Else Clones Your Project

They will need:
1. ✅ Docker Desktop installed
2. ✅ Python 3.9+ installed
3. ✅ Datasets downloaded (see `DATA_SETUP_GUIDE.md`)
4. ⚠️ **Trained models** - either:
   - Run full pipeline once (`run_threvia_pipeline.ps1`)
   - OR receive your pre-trained model files

**Note:** Models are NOT in git (too large). For distribution:
- Option A: Run training once (15-20 mins)
- Option B: Share model files via Google Drive/OneDrive
- Option C: Use MLflow model registry (enterprise approach)

---

## Next Steps

1. **First time?** → Run `.\start_dashboard.ps1`
2. **Dashboard empty?** → Populate data (see "Common Issues #1")
3. **Need to retrain models?** → Run `.\run_threvia_pipeline.ps1`
4. **Ready for deployment?** → See `DISTRIBUTION_CHECKLIST.md`

---

**Questions?** Check:
- `documentation/PROJECT_STATUS_SUMMARY.md` - Overall project status
- `documentation/FINAL_MODEL_EVALUATION.md` - ML performance metrics
- `DATA_SETUP_GUIDE.md` - Dataset download instructions
