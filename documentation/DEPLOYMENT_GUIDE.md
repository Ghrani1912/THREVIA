# THREVIA Deployment Guide

**Project:** THREVIA — Threat Recognition, Evaluation & Visualization using Intelligent Analytics  
**Version:** 1.0 (All 7 Phases Complete)  
**Date:** September 12, 2026  
**Status:** ✅ Production-Ready

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Manual Deployment](#manual-deployment)
5. [Architecture](#architecture)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)
8. [Future Enhancements](#future-enhancements)

---

## System Overview

THREVIA is a complete big data cybersecurity intelligence platform with:

- **Batch ML:** Random Forest classifier (14 attack types, Macro-F1 74.21%)
- **Unsupervised:** K-Means clustering (91.31% purity, zero-day detection)
- **Real-Time:** Spark Streaming + Bloom Filter (malicious IP lookup)
- **Graph Analytics:** Entity relationships, centrality, community detection
- **Dashboard:** Interactive Streamlit visualization

**Training Corpus:** 15.69M network flows (LycoS + CICIDS2018 + CIC-2017)  
**Infrastructure:** Hadoop 3.2.1, Spark 3.3.0, MongoDB 6.0

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| CPU | 4 cores | 8 cores |
| Disk | 50 GB free | 100 GB SSD |

### Software Requirements

- **Docker Desktop** (Windows/Mac) or Docker Engine (Linux)
- **WSL2** enabled (Windows only)
- **PowerShell** 5.1+ (Windows) or PowerShell Core 7+ (Linux/Mac)
- **Python** 3.9+ (for dashboard development)

### Dataset Requirements ⚠️

**IMPORTANT:** Datasets are NOT included in the repository (15 GB total).

**You must download them separately:** See **[DATA_SETUP_GUIDE.md](DATA_SETUP_GUIDE.md)** for:
- Required datasets (LycoS, CIC-IDS-2017, CICIDS2018)
- Download links (free, registration required)
- Installation instructions
- Directory structure

**Quick checklist:**
- [ ] LycoS-IDS2018 downloaded (5 GB)
- [ ] CIC-IDS-2017 downloaded (8 GB, 8 files)
- [ ] CICIDS2018 downloaded (2 GB, 2 files)
- [ ] Files placed in `backend/data/` subdirectories

### Network Ports

| Port | Service | Purpose |
|------|---------|---------|
| 9870 | HDFS NameNode | Web UI |
| 8020 | HDFS RPC | Filesystem |
| 8080 | Spark Master | Web UI |
| 7077 | Spark master RPC | Cluster |
| 27018 | MongoDB | Database (host port; container 27017) |
| 8000 | FastAPI + SOC dashboard | http://localhost:8000/dashboard |

> The simulator/detector (`--profile phase4`) add 9999. The Streamlit app
> (`dashboard/app.py`, not started by any launcher) would use 8501; the served
> dashboard is the FastAPI one on 8000.

---

## Quick Start

### 1. Clone Repository

```powershell
git clone <repository-url>
cd Threvia
```

### 2. Start Infrastructure

```powershell
docker compose up -d
```

Wait 30-60 seconds for services to initialize.

### 3. Run Complete Pipeline

```powershell
.\run_threvia_pipeline.ps1
```

This executes all 7 phases:
1. Foundation validation
2. Corpus building (10-15 min)
3. Model training (15-20 min)
4. Bloom Filter + streaming
5. Graph analytics
6. Dashboard launch
7. Integration checks

**Total time:** ~30-40 minutes on recommended hardware

### 4. Access Dashboard

Dashboard automatically opens at: http://localhost:8000/dashboard

If not, run manually:
```powershell
streamlit run dashboard/app.py
```

---

## Manual Deployment

### Phase-by-Phase Execution

#### Phase 1: Foundation

```powershell
# Validate HDFS datasets
docker exec threvia-spark-master python3 /workspace/backend/ingestion/validate_hdfs.py
```

**Expected output:**
```
✅ /threvia/raw exists
✅ /threvia/corpus/train exists (15,692,084 rows)
✅ All datasets validated
```

#### Phase 2: Batch Processing

```powershell
# Build unified training corpus
docker exec threvia-spark-master /opt/spark/bin/spark-submit `
    --master spark://spark-master:7077 `
    --driver-memory 4g `
    --executor-memory 4g `
    /workspace/backend/processing/merge_corpus.py
```

**Output:** `/threvia/corpus/train` (15.69M rows, Parquet format)

#### Phase 3: Machine Learning

```powershell
# Train Random Forest + K-Means
docker exec threvia-spark-master /opt/spark/bin/spark-submit `
    --master spark://spark-master:7077 `
    --driver-memory 3g `
    --executor-memory 3g `
    /workspace/backend/ml/train_clean_corpus.py
```

**Output:**
- `/threvia/models_clean/rf_binary` (Binary classifier)
- `/threvia/models_clean/rf_multiclass` (14-class classifier)
- `/threvia/models_clean/kmeans` (Clustering model)
- `/threvia/models_clean/scaler_pipeline` (StandardScaler)

**Performance:**
- Binary: 99.86% accuracy
- Multiclass: Macro-F1 74.21%, Weighted F1 99.38%
- K-Means: 91.31% cluster purity

#### Phase 4: Real-Time Layer

```powershell
# Build Bloom Filter
python backend/realtime/bloom_filter.py

# Start streaming detector (background)
python backend/realtime/run_phase4.py
```

**Output:**
- `backend/realtime/bloom_filter.pkl` (Malicious IP lookup)
- Real-time alerts written to MongoDB `threvia.security_events`

#### Phase 5: Graph Analysis

```powershell
# Build entity graph + analytics
python backend/graph/run_phase5.py
```

**Output:**
- `backend/graph/graph_export.html` (Interactive visualization)
- Graph metrics written to MongoDB `threvia.graph_metrics`

Open visualization:
```powershell
Start-Process backend/graph/graph_export.html
```

#### Phase 6: Dashboard

```powershell
# Start Streamlit dashboard
streamlit run dashboard/app.py
```

**Features:**
- Real-time threat trends
- Attack type distribution
- Severity metrics
- Interactive graph visualization
- Historical analytics

#### Phase 7: Integration Check

```powershell
.\run_threvia_pipeline.ps1 -Phases 7
```

Validates:
- ✅ HDFS corpus exists
- ✅ Trained models exist
- ✅ Bloom filter built
- ✅ Graph export created
- ✅ Dashboard operational

---

## Architecture

### Data Flow

```
Network Traffic → HDFS → Spark Batch Processing
                           ↓
                    Feature Extraction (78 features)
                           ↓
                    ┌──────┴──────┐
                    ↓             ↓
              Random Forest   K-Means
              (Supervised)   (Unsupervised)
                    ↓             ↓
                Predictions   Anomalies
                    ↓             ↓
              MongoDB ← Spark Streaming ← Real-time Traffic
                    ↓             ↓
              Graph Builder   Bloom Filter
                    ↓
              Streamlit Dashboard
```

### Component Responsibilities

| Component | Responsibility | Technology |
|-----------|----------------|------------|
| **HDFS** | Distributed storage | Hadoop 3.2.1 |
| **Spark Batch** | Corpus building, training | PySpark 3.3.0 |
| **Spark Streaming** | Real-time detection | Structured Streaming |
| **MongoDB** | Alert storage | MongoDB 6.0 |
| **Bloom Filter** | Fast IP lookup | Python + hashlib |
| **Graph Builder** | Entity relationships | NetworkX + pyvis |
| **Dashboard** | Visualization | Streamlit 1.28+ |

---

## Monitoring

### Health Checks

#### HDFS Health
```powershell
docker exec threvia-namenode hdfs dfsadmin -report
```

#### Spark Jobs
```powershell
# Web UI
Start-Process http://localhost:8080

# CLI
docker exec threvia-spark-master /opt/spark/bin/spark-submit --master spark://spark-master:7077 --status
```

#### MongoDB Connection
```powershell
docker exec threvia-mongodb mongosh threvia --eval "db.getCollectionNames()"
```

### Log Access

```powershell
# HDFS logs
docker logs threvia-namenode

# Spark logs
docker logs threvia-spark-master

# MongoDB logs
docker logs threvia-mongodb

# Dashboard logs
# (stdout when running streamlit)
```

---

## Troubleshooting

### Common Issues

#### 1. Out of Memory Error (Spark)

**Symptom:**
```
java.lang.OutOfMemoryError: Java heap space
```

**Solution:**
```powershell
# Reduce driver/executor memory
docker exec threvia-spark-master /opt/spark/bin/spark-submit `
    --driver-memory 2g `
    --executor-memory 2g `
    /workspace/backend/ml/train_clean_corpus.py
```

#### 2. HDFS SafeMode

**Symptom:**
```
Name node is in safe mode
```

**Solution:**
```powershell
docker exec threvia-namenode hdfs dfsadmin -safemode leave
```

#### 3. MongoDB Connection Failed

**Symptom:**
```
pymongo.errors.ServerSelectionTimeoutError
```

**Solution:**
```powershell
# Restart MongoDB
docker restart threvia-mongodb

# Check status
docker exec threvia-mongodb mongosh --eval "db.adminCommand('ping')"
```

#### 4. Dashboard Empty

**Symptom:** Dashboard shows no data

**Solution:**
```powershell
# Populate sample data (host-side: MongoDB is published on 27018)
python backend/realtime/populate_mongo.py

# Reload the page. The FastAPI backend serves the UI, so there is nothing to
# restart — if it is not running at all, use:
.\start_dashboard.ps1
```

For live alerts instead of synthetic sample data:
```powershell
docker compose --profile phase4 up -d
```

#### 4b. ONLINE LEARNING panel reads `NO DETECTOR`

**Symptom:** The adaptive-detection panel shows dashes and `NO DETECTOR`.

**Cause:** Nothing has written `learning_state` — the detector is not running, or
it is running with `ONLINE_LEARNING=off`. This is an absence of telemetry, not a
layer operating at zero.

**Solution:**
```powershell
# Start simulator + detector (profile phase4)
docker compose --profile phase4 up -d

# Confirm the detector is reporting
docker exec threvia-mongodb mongosh threvia --quiet --eval "db.learning_state.countDocuments()"
```

If it stays empty, check the detector's log for the per-batch learning line, and
confirm `ONLINE_LEARNING_STATE` is writable (the `learning_state` volume).

#### 5. Port Conflicts

**Symptom:**
```
Bind for 0.0.0.0:9870 failed: port is already allocated
```

**Solution:**
```powershell
# Stop conflicting containers
docker ps -a
docker stop <container-id>

# Or change ports in docker-compose.yml
```

### Performance Tuning

#### Spark Memory Configuration

Edit `docker-compose.yml`:
```yaml
spark-master:
  environment:
    - SPARK_DRIVER_MEMORY=6g
    - SPARK_EXECUTOR_MEMORY=6g
```

#### MongoDB Indexing

```javascript
// Connect to MongoDB
docker exec -it threvia-mongodb mongosh threvia

// Create indexes
db.security_events.createIndex({ timestamp: -1 })
db.security_events.createIndex({ severity: 1 })
db.security_events.createIndex({ predicted_label: 1 })
```

---

## Future Enhancements (v2.0)

### Tier 1 (High Impact)
- [ ] DoS Slowhttptest: HTTP-specific features (slow header detection)
- [ ] Real-time alerting: Email/Slack notifications
- [ ] Model retraining: Scheduled weekly updates

### Tier 2 (Medium Impact)
- [ ] Bot detection: Balanced classifier with SMOTE
- [ ] Cross-dataset validation: UNSW-NB15 integration
- [ ] Dashboard improvements: Drill-down views, export reports

### Tier 3 (Low Impact)
- [ ] Infiltration detection: Rule-based heuristics
- [ ] TEST-A causal verification: Run `test_lycos_leakage_simple.py`
- [ ] Multi-node Spark cluster: Scale to 5+ workers

### Implementation Timeline

| Quarter | Focus | Deliverables |
|---------|-------|--------------|
| Q4 2026 | Tier 1 | Slowhttptest fix, alerting |
| Q1 2027 | Tier 2 | Bot SMOTE, UNSW-NB15 |
| Q2 2027 | Tier 3 | Infiltration rules, scaling |

---

## Support

### Documentation

- [Project Status](PROJECT_STATUS_SUMMARY.md)
- [Model Evaluation](FINAL_MODEL_EVALUATION.md)
- [Honest Eval Report](HONEST_EVAL_REPORT.md)
- [Leakage analysis + honest metrics](HONEST_EVAL_REPORT.md)
- [Full model evaluation](FINAL_MODEL_EVALUATION.md)
- [THREVIA PRD](THREVIA_PRD.md)

### Key Scripts

| Script | Purpose |
|--------|---------|
| `run_threvia_pipeline.ps1` | End-to-end execution |
| `backend/ml/train_clean_corpus.py` | Phase 3 training |
| `backend/realtime/run_phase4.py` | Phase 4 streaming |
| `backend/graph/run_phase5.py` | Phase 5 graph |
| `dashboard/app.py` | Phase 6 dashboard |

---

## Deployment Checklist

### Pre-Deployment
- [ ] Docker containers running (`docker ps`)
- [ ] HDFS datasets uploaded (`validate_hdfs.py`)
- [ ] 16 GB RAM available
- [ ] Ports 9870, 8020, 8080, 7077, 8000, 27018 free

### Deployment
- [ ] Phase 1: Foundation validated
- [ ] Phase 2: Corpus built (15.69M rows)
- [ ] Phase 3: Models trained (Macro-F1 74.21%)
- [ ] Phase 4: Streaming running
- [ ] Phase 5: Graph exported
- [ ] Phase 6: Dashboard accessible
- [ ] Phase 7: Integration checks passed

### Post-Deployment
- [ ] Dashboard verified (http://localhost:8000/dashboard)
- [ ] Real-time alerts flowing to MongoDB
- [ ] Graph visualization renders
- [ ] No error logs in containers
- [ ] Documentation distributed to team

---

## Conclusion

THREVIA v1.0 is a complete, production-ready big data cybersecurity platform with:

- **90% threat coverage** (DDoS, PortScan, BENIGN, Patator attacks)
- **Real-time detection** (Spark Streaming + Bloom Filter)
- **Graph analytics** (Entity relationships, centrality)
- **Interactive dashboard** (Streamlit visualization)

**Known limitations:**
- Bot: 0.31% recall (class imbalance, defer to v2.0)
- Infiltration: 0% recall (cross-dataset mismatch, defer to v2.0)
- DoS Slowhttptest: 44.75% recall (needs HTTP features, Tier 1 fix)

**Deployment time:** ~30-40 minutes  
**System status:** ✅ **READY FOR DEMONSTRATION AND PRODUCTION USE**

---

**Last Updated:** September 12, 2026  
**Version:** 1.0  
**Contact:** See `THREVIA_PRD.md` for team information
