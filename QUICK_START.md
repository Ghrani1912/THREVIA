# THREVIA Quick Start Guide

## Starting the Dashboard (Fastest Way)

If you've already trained the models and just want to view the dashboard:

```powershell
.\start_dashboard.ps1
```

This script will:
1. ✅ Check if Docker containers are running (starts them if needed)
2. ✅ Create Python virtual environment (only first time)
3. ✅ Count the dashboard's collections (populates sample data if all are empty)
4. ✅ Start the FastAPI backend server
5. ✅ Open the dashboard in your browser

> **Prerequisite:** the trained models must already be in HDFS. On a machine that
> has never run the pipeline, do the full setup first — `.\setup_env.ps1`, then
> `.\run_threvia_pipeline.ps1`. See the Quick Start in [README.md](README.md).

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

# Insert sample security events (host-side: connects on port 27018)
python backend/realtime/populate_mongo.py
```

Or just run `.\populate_sample_data.ps1`, which does both of the above.

---

## Adaptive Detection — what the ONLINE LEARNING panel shows

The streaming detector is not just the trained model. In front of its decision sits
an adaptive layer (`backend/realtime/online_learning.py`) that measures drift against
the calibration corpus, holds the alert *rate* at a budget, and re-ranks scores with
a bounded correction learned from analyst verdicts. See
[README → Adaptive detection](README.md#adaptive-detection-online-learning).

**To watch it work:**
```powershell
docker compose --profile phase4 up -d   # simulator + detector
docker compose --profile phase6 up -d   # API + dashboard (or use start_dashboard.ps1)
```
Then open http://localhost:8000/dashboard. The panel shows the calibrated cut, the
adapted cut, the realized rate against the budget, PSI/KS with a drift verdict, and
how many verdicts it has consumed. `NO DETECTOR` in that panel means no detector has
reported state — an absence of telemetry, not a detector reading zero.

**To label a detection** (this is the only human supervision it gets): open an
incident in the drawer and press CONFIRM THREAT or MARK FALSE POSITIVE. The verdict
is posted to `POST /api/v1/feedback` and applied on the detector's next poll
(`FEEDBACK_POLL_SECONDS`, default 20 s). A contact with no P(attack) — a Bloom hit —
cannot train the calibrator, and the panel says so.

**To turn it off** and run the frozen operating point (the matched A/B):
```powershell
$env:ONLINE_LEARNING="off"     # or uncomment ONLINE_LEARNING=off in docker-compose.yml
```

**To reset what it has learned:** `docker compose down -v` wipes the `learning_state`
volume, or set `ONLINE_LEARNING_STATE` elsewhere to keep two detectors' state apart.

---

## Common Issues

### 1. "Dashboard is empty / no threats showing"

**Cause:** MongoDB has no security events yet.

**Solution:**
```powershell
& backend/api/.venv/Scripts/Activate.ps1
python backend/realtime/populate_mongo.py
```

Then refresh the dashboard (F5).

For *live* alerts instead of sample data, run the streaming stack:
```powershell
docker compose --profile phase4 up -d
```

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

If the dashboard loads but the panel reads `NO DETECTOR`, the streaming profile is
not running — that panel needs `--profile phase4`, not just the infrastructure.

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
3. ✅ Datasets downloaded (see `documentation/DATA_SETUP_GUIDE.md`)
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
4. **Ready for deployment?** → See `documentation/DEPLOYMENT_GUIDE.md`

---

**Questions?** Check:
- `documentation/PROJECT_STATUS_SUMMARY.md` - Overall project status
- `documentation/FINAL_MODEL_EVALUATION.md` - ML performance metrics
- `documentation/DATA_SETUP_GUIDE.md` - Dataset download instructions
