# THREVIA

**Threat Recognition, Evaluation & Visualization using Intelligent Analytics**

A scalable Big Data cybersecurity intelligence platform for detecting, analyzing, and predicting malicious network behavior.

**Current Status:** ✅ **ALL 7 PHASES COMPLETE — READY FOR DEPLOYMENT**  
**See:** [Project Status Summary](documentation/PROJECT_STATUS_SUMMARY.md) | [Final Evaluation](documentation/FINAL_MODEL_EVALUATION.md)

---

## ⚡ Quick Start

**⚠️ FIRST TIME SETUP:** Datasets are NOT included in this repository. **[Download datasets first →](DATA_SETUP_GUIDE.md)**

```powershell
# Start infrastructure
docker compose up -d

# Run complete pipeline (30-40 minutes)
.\run_threvia_pipeline.ps1

# Access dashboard at http://localhost:8501
```

**See [QUICKSTART.md](QUICKSTART.md) for detailed instructions**

---

## 📚 Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| **[Project Status Summary](documentation/PROJECT_STATUS_SUMMARY.md)** | High-level status, timeline, next actions | Stakeholders, Project Managers |
| **[THREVIA PRD](documentation/THREVIA_PRD.md)** | Product requirements, goals, architecture | All team members |
| **[Phase 3 Model Evaluation](documentation/FINAL_MODEL_EVALUATION.md)** | Comprehensive ML model evaluation | ML Engineers, Data Scientists |
| **[Honest Eval Report](documentation/HONEST_EVAL_REPORT.md)** | Detailed metrics with honest macro-F1 | Technical reviewers |
| **[LycoS Leakage Analysis](documentation/LYCOS_LEAKAGE_ANALYSIS.md)** | TEST-A causal leakage investigation | ML Engineers |
| **[Implementation Plan](documentation/implementation_plan.md)** | TEST-C1/C2 split technical details | Developers |

---

## Project Structure

```
Threvia/
├── docker-compose.yml       # All services (Hadoop, Spark, MongoDB)
├── hadoop.env               # Hadoop config shared by containers
├── .gitignore
├── THREVIA_PRD.md
│
├── backend/                 # All data processing, ML, analytics
│   ├── data/                # Raw datasets (NOT committed to git)
│   │   ├── CIC-IDS- 2017/   # Original CICIDS2017 (8 CSVs)
│   │   ├── LYCSOS/          # LycoS-IDS2018 (5.2 GB, primary training source)
│   │   ├── CICIDS2018/      # CICIDS2018 Thursday + Wednesday (Infiltration)
│   │   ├── UNSW-NB15/       # UNSW-NB15 (future cross-dataset experiment)
│   │   ├── IDS2025 .../     # IDS2025 XLSX (held-out validation)
│   │   ├── portscan_clean/  # Deduped + port-grouped PortScan splits
│   │   └── ids2025_clean/   # IDS2025 converted to CSV
│   ├── ingestion/           # Phase 1: data loading & validation
│   ├── processing/          # Phase 2 + 3a: PySpark cleaning, corpus merge
│   │   ├── schema_maps.py          # Column rename maps (LycoS, CIC18, IDS25)
│   │   ├── merge_corpus.py         # Unified training corpus builder
│   │   ├── convert_ids2025.py      # XLSX → CSV + HDFS upload
│   │   ├── portscan_split.py       # Dedup + grouped split
│   │   ├── zerovar_diagnostic.py   # Data quality diagnostic
│   │   └── upload_corpus_sources.ps1
│   ├── ml/                  # Phase 3: MLlib classification & clustering
│   ├── realtime/            # Phase 4: Bloom filter & streaming
│   │   ├── bloom_filter.py         # Threat intelligence Bloom Filter
│   │   ├── streaming_detector.py   # Spark Streaming detection
│   │   ├── stream_simulator.py     # Network traffic simulator
│   │   └── run_phase4.py           # Phase 4 runner
│   ├── graph/               # Phase 5: Graph analytics
│   │   ├── graph_builder.py        # Entity graph construction
│   │   ├── graph_analytics.py      # Centrality + communities
│   │   └── run_phase5.py           # Phase 5 runner
│   └── utils/               # Shared helpers
│
├── dashboard/               # Phase 6: Streamlit frontend
│   ├── app.py                      # Main dashboard
│   └── requirements.txt
│
└── run_threvia_pipeline.ps1 # END-TO-END PIPELINE RUNNER (All 7 phases)
```

---

**See:** [Full Phase 3 Evaluation](documentation/FINAL_MODEL_EVALUATION.md) for comprehensive analysis

---

## Quick Start — Full Pipeline

### Run Complete THREVIA System (All 7 Phases)

```powershell
# Start Docker environment
docker compose up -d

# Run end-to-end pipeline
.\run_threvia_pipeline.ps1
```

The pipeline will execute:
1. **Phase 1:** Validate HDFS datasets
2. **Phase 2:** Build unified corpus (15.69M rows)
3. **Phase 3:** Train RF classifiers + K-Means
4. **Phase 4:** Build Bloom Filter + start streaming detector
5. **Phase 5:** Build entity graph + compute analytics
6. **Phase 6:** Launch interactive dashboard
7. **Phase 7:** Run integration checks

**Quick demo mode** (skips long-running processes):
```powershell
.\run_threvia_pipeline.ps1 -QuickDemo
```

**Run specific phases:**
```powershell
.\run_threvia_pipeline.ps1 -Phases 4,5,6  # Run phases 4-6 only
```

---

## Manual Setup (Development)

### Prerequisites
- Docker Desktop running
- WSL2 enabled (Windows)
- ~4 GB RAM available for containers

### Step 1 — Start all services
```bash
docker compose up -d
```

This starts:
| Service | URL |
|---|---|
| HDFS NameNode Web UI | http://localhost:9870 |
| Spark Master Web UI | http://localhost:8080 |
| MongoDB | localhost:27017 |

The `hdfs-init` container will automatically:
1. Wait for HDFS to be ready
2. Create `/threvia/raw`, `/threvia/processed`, `/threvia/output`
3. Upload all 8 CICIDS2017 CSVs into `/threvia/raw/`

### Step 2 — Validate the upload
```bash
docker exec threvia-namenode python3 /workspace/backend/ingestion/validate_hdfs.py
```

Or manually inspect HDFS:
```bash
docker exec threvia-namenode hdfs dfs -ls /threvia/raw
```

### Step 3 — Inspect the dataset locally (optional)
```bash
python backend/ingestion/inspect_dataset.py
```

### Stop everything
```bash
docker compose down
```

To also wipe volumes (HDFS data):
```bash
docker compose down -v
```

---

## Implementation Phases

### 🎉 THREVIA Pipeline Flow — ALL PHASES COMPLETE

```
Phase 1: FOUNDATION (✅ Complete)
    Raw Data (CICIDS2017, CICIDS2018, LycoS) → HDFS Storage
                              ↓
Phase 2: BATCH PROCESSING (✅ Complete)
    PySpark cleaning → Feature extraction (78 features) → 15.69M clean rows
                              ↓
Phase 3: MACHINE LEARNING (✅ Complete)
    ├─ Random Forest (Binary: 99.86%, Multiclass: Macro-F1 74.21%)
    ├─ K-Means (91.31% cluster purity)
    └─ Evaluation (TEST-A/B/C1, CROSS-DATASET)
                              ↓
Phase 4: REAL-TIME LAYER (✅ Complete)
    Bloom Filter + Spark Streaming → Real-time alerts → MongoDB
                              ↓
Phase 5: GRAPH ANALYSIS (✅ Complete)
    Entity graph → Centrality → Community detection → Visualization
                              ↓
Phase 6: DASHBOARD (✅ Complete)
    Interactive Streamlit dashboard → Trends, graphs, metrics
                              ↓
Phase 7: INTEGRATION (✅ Complete)
    End-to-end testing + Documentation + Polish

🚀 SYSTEM READY FOR DEPLOYMENT
```

### Phase Status Table

| Phase | Description | Status | Progress |
|---|---|---|---|
| 1 | Foundation — Environment, HDFS, dataset ingestion | ✅ Complete | 100% |
| 2 | Batch Processing — PySpark cleaning, MapReduce | ✅ Complete | 100% |
| 3 | Machine Learning — Classification + clustering | ✅ Complete | 100% |
| 4 | Real-Time — Bloom Filter + spike detection | ✅ Complete | 100% |
| 5 | Graph Analysis — Entity relationships | ✅ Complete | 100% |
| 6 | Dashboard — Interactive visualization | ✅ Complete | 100% |
| 7 | Integration & Polish | ✅ Complete | 100% |

**Overall Project Progress:** 100% (All 7 phases complete)

**Status:** ✅ **Production-ready system, fully operational**

---

## Phase 3 — ML Model Performance

### Supervised Model (Random Forest)
**Grade: B** — Excellent for common attacks, needs fixes for rare attacks

| Attack Type | Recall | Status | Test Set |
|-------------|--------|--------|----------|
| **DDoS** | 99.81% | ✅ Production-ready | TEST-C1 (Friday) |
| **PortScan** | 99.27% | ✅ Verified (0% leakage) | TEST-B (port-grouped) |
| **BENIGN** | 99.99% | ✅ Perfect | TEST-C1 (Friday) |
| **SSH/FTP-Patator** | 89-99% | ⚠️ Unverified | TEST-A (LycoS) |
| **DoS Hulk** | 100.00% | ⚠️ Unverified | TEST-A (LycoS) |
| **Bot** | **0.31%** | ❌ Unusable | TEST-C1 (Friday) |
| **Infiltration** | **0.00%** | ❌ Unusable | CROSS-DATASET |
| **DoS Slowhttptest** | **44.75%** | ⚠️ Unreliable | TEST-A (LycoS) |

**Key Metrics:**
- **Macro-F1: 74.21%** (honest metric — exposes minority failures)
- **Weighted F1: 99.38%** (misleading — hides Bot/Infiltration failures)
- **Accuracy: 99.51%** (dominated by BENIGN)

### Unsupervised Model (K-Means)
**Grade: A-** — Strong zero-day detection

- **Cluster Purity:** 91.31% (2.58M flows correctly grouped)
- **Use Case:** Zero-day detection, anomaly baseline
- **Status:** ✅ Production-ready (Tier 4 fallback)

**See:** [Full Phase 3 Evaluation](documentation/FINAL_MODEL_EVALUATION.md) for comprehensive analysis

---

## Implementation Phases (Deprecated - Old Table)

| Model | Task | Accuracy | F1 | AUC-ROC |
|---|---|---|---|---|
| Random Forest | Binary | 0.9958 | 0.9958 | 0.9996 |
| Random Forest | Multi-class | 0.9962 | 0.9955 | — |
| Logistic Regression | Binary | 0.8945 | 0.8843 | 0.9672 |
| Logistic Regression | Multi-class | 0.9229 | 0.9143 | — |

> ⚠️ The 99.6% accuracy is inflated — root causes confirmed: 14.3% duplicate rows,
> 13.4% cross-boundary vector leakage, 214+ zero-variance deterministic signatures,
> and session-correlated flows split randomly. The **temporal evaluation**
> (Mon–Thu train / Friday test) is the honest benchmark.
> See `backend/ml/leakage_check.py` for the full audit.

### Phase 3a — Data Quality & Clean Corpus

Key scripts in `backend/processing/`:

| Script | What it does |
|---|---|
| `schema_maps.py` | Canonical column rename maps for LycoS, CICIDS2018, IDS2025 |
| `zerovar_diagnostic.py` | Zero-variance diagnostic on CICIDS2018 Infiltration rows |
| `portscan_split.py` | Dedup + port-grouped split of CIC-2017 PortScan |
| `merge_corpus.py` | Spark job — merges all sources into unified training Parquet |
| `convert_ids2025.py` | Converts IDS2025 XLSX → CSV, uploads to HDFS validation path |
| `upload_corpus_sources.ps1` | Uploads all raw source CSVs to HDFS before merge |

---

## Dataset

### Original — CIC-IDS-2017
**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection System 2017

| File | Content |
|---|---|
| Monday-WorkingHours | Benign traffic only |
| Tuesday-WorkingHours | FTP-Patator, SSH-Patator |
| Wednesday-WorkingHours | DoS Hulk, DoS GoldenEye, DoS Slowloris, Heartbleed |
| Thursday Morning | Web Attacks (Brute Force, XSS, SQL Injection) |
| Thursday Afternoon | Infiltration |
| Friday Morning | Botnet ARES |
| Friday Afternoon (DDoS) | DDoS |
| Friday Afternoon (PortScan) | Port Scan |

> **Note:** CIC-IDS-2017 was used for the initial Phase 3 evaluation but was found to have
> significant data quality issues (42.9% duplicate rows in PortScan, 14.3% cross-boundary
> leakage in random splits, 214+ zero-variance deterministic feature signatures). See
> `backend/processing/leakage_check.py` and `backend/ml/advanced_eval.py` for full diagnostics.

---

### Unified Training Corpus (Phase 3 — Clean)

The clean training corpus merges three sources to address the CIC-IDS-2017 quality problems.
See `backend/processing/merge_corpus.py` for the full pipeline.

**Sources:**

| Dataset | Role | Rows | Key property |
|---|---|---|---|
| LycoS-IDS2018 | Primary training data | 13,691,268 | Re-extracted from raw pcaps; fixes zero-variance signatures |
| CICIDS2018 Thu + Wed | Infiltration supplement | 161,934 | Only Infiltration rows; verified cautiously usable (8 shared tool-artifact zero-var cols, <11% dups) |
| CIC-IDS-2017 PortScan (train split) | PortScan class | 72,706 | Deduped (42.9% removed); port-grouped split (port overlap=0, vec leakage=0) |

**Training corpus label distribution:**

| Class | Rows | % |
|---|---|---|
| BENIGN | 10,000,000 | 71.8% |
| DoS Hulk | 1,802,966 | 12.9% |
| DDoS | 1,366,089 | 9.8% |
| FTP-Patator | 190,300 | 1.4% |
| Infiltration | 161,934 | 1.2% |
| DoS Slowhttptest | 105,550 | 0.8% |
| Bot | 96,154 | 0.7% |
| SSH-Patator | 92,648 | 0.7% |
| PortScan | 72,706 | 0.5% |
| DoS GoldenEye | 26,861 | 0.2% |
| DoS slowloris | 10,274 | 0.07% |
| Web Attack – Brute Force | 260 | <0.01% |
| Web Attack – XSS | 116 | <0.01% |
| Web Attack – Sql Injection | 50 | <0.01% |
| **TOTAL** | **13,925,908** | |

> Imbalance ratio: **2.55x** (benign:attack) — down from ~5x in CIC-IDS-2017.
> Infiltration class grew from **36 → 161,934 rows**.
> StandardScaler fit on **training data only** (no test leakage).

**HDFS layout after corpus build:**
```
/threvia/corpus/train          — 13,925,908 rows, Parquet (training corpus)
/threvia/corpus/portscan_test  — 18,113 rows, Parquet (held-out PortScan test)
/threvia/validation/           — ids2025_validation.csv (91,830 rows, held-out)
```

---

### Additional Datasets

| Dataset | Location | Use |
|---|---|---|
| LycoS-IDS2018 | `backend/data/LYCSOS/` | Primary training source (5.2 GB) |
| CICIDS2018 Thu + Wed | `backend/data/CICIDS2018/` | Infiltration supplement |
| IDS2025 | `backend/data/ids2025_clean/` | **Held-out validation only** — balanced, re-engineered; do not mix into training |
| UNSW-NB15 | `backend/data/UNSW-NB15/` | Future cross-dataset generalisation experiment (different schema — not pipeline-compatible) |

**Column rename maps** (source → canonical CIC-IDS-2017 schema):
`backend/processing/schema_maps.py`
