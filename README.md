# THREVIA

**Threat Recognition, Evaluation & Visualization using Intelligent Analytics**

A scalable Big Data cybersecurity intelligence platform for detecting, analyzing, and predicting malicious network behavior.

**Current Status:** ✅ **ALL 7 PHASES COMPLETE — READY FOR DEPLOYMENT**  
**See:** [Project Status Summary](documentation/PROJECT_STATUS_SUMMARY.md) | [Final Evaluation](documentation/FINAL_MODEL_EVALUATION.md)

---

## ⚡ Quick Start

**⚠️ FIRST TIME SETUP:** Datasets are NOT included in this repository —
**[download them first →](documentation/DATA_SETUP_GUIDE.md)**, then confirm with
`.\verify_datasets.ps1`.

```powershell
# 1. Host Python environment — creates ./.venv and installs the requirements
.\setup_env.ps1

# 2. Infrastructure: HDFS + Spark + MongoDB
docker compose up -d

# 3. Upload the raw datasets, then run all 7 phases (30-40 minutes)
.\run_threvia_pipeline.ps1

# 4. Dashboard (served by the FastAPI backend)
#    http://localhost:8000/dashboard
```

Already trained and just want the dashboard up?
```powershell
docker compose up -d      # MongoDB must be running
.\start_dashboard.ps1     # makes backend/api/.venv, populates sample data, serves the UI
```

Want live streaming alerts (simulator + detector as containers)?
```powershell
docker compose --profile phase4 up -d
```

**Step-by-step walkthrough:** [QUICK_START.md](QUICK_START.md). Full prerequisite
list: [Running this on another machine](#running-this-on-another-machine).

---

## 📚 Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| **[Project Status Summary](documentation/PROJECT_STATUS_SUMMARY.md)** | High-level status, timeline, next actions | Stakeholders, Project Managers |
| **[THREVIA PRD](documentation/THREVIA_PRD.md)** | Product requirements, goals, architecture | All team members |
| **[Phase 3 Model Evaluation](documentation/FINAL_MODEL_EVALUATION.md)** | Comprehensive ML model evaluation | ML Engineers, Data Scientists |
| **[Honest Eval Report](documentation/HONEST_EVAL_REPORT.md)** | Detailed metrics with honest macro-F1 | Technical reviewers |
| **[Leakage & test design](documentation/FINAL_MODEL_EVALUATION.md)** | TEST-A causal leakage, TEST-C1/C2 split details | ML Engineers |
| **[Deployment guide](documentation/DEPLOYMENT_GUIDE.md)** | Ports, health checks, troubleshooting | Operators |
| **[Dataset setup](documentation/DATA_SETUP_GUIDE.md)** | Where to download every dataset | Everyone |
| **[Dashboard explained](documentation/DASHBOARD_EXPLAINED.md)** | What the SOC UI shows and why | Reviewers |

> There are no separate `LYCOS_LEAKAGE_ANALYSIS.md` / `implementation_plan.md`
> documents — the leakage investigation and the split design live inside
> `FINAL_MODEL_EVALUATION.md` and `HONEST_EVAL_REPORT.md`.

---

## Project Structure

```
Threvia/
├── docker-compose.yml          # Infra + profiled jobs (HDFS, Spark, MongoDB,
│                               #   simulator, detector, API)
├── requirements.txt            # Host dependencies (composes the 3 phase manifests)
├── requirements-dev.txt        # The above + pytest
├── setup_env.ps1               # Creates ./.venv and installs them
├── .gitignore
│
├── backend/                    # All data processing, ML, analytics
│   ├── data/                   # Raw datasets (NOT committed — see the setup guide)
│   │   ├── CIC-IDS- 2017/      # Original CICIDS2017 (8 CSVs)
│   │   ├── LYCSOS/             # LycoS-IDS2018 (5.2 GB, primary training source)
│   │   ├── CICIDS2018/         # CICIDS2018 Thursday + Wednesday (Infiltration)
│   │   ├── UNSW-NB15/          # UNSW-NB15 (future cross-dataset experiment)
│   │   ├── IDS2025 .../        # IDS2025 XLSX (held-out validation)
│   │   ├── portscan_clean/     # Deduped + port-grouped PortScan splits
│   │   └── ids2025_clean/      # IDS2025 converted to CSV
│   ├── api/                    # Phase 6: FastAPI backend — serves the UI + /api/v1
│   ├── ingestion/              # Phase 1: data loading & validation
│   ├── processing/             # Phase 2 + 3a: PySpark cleaning, corpus merge
│   │   ├── schema_maps.py          # Column rename maps (LycoS, CIC18, IDS25)
│   │   ├── merge_corpus.py         # Unified training corpus builder
│   │   ├── convert_ids2025.py      # XLSX → CSV + HDFS upload
│   │   ├── portscan_split.py       # Dedup + grouped split
│   │   ├── zerovar_diagnostic.py   # Data quality diagnostic
│   │   └── upload_corpus_sources.ps1   # LycoS / CIC18 / PortScan → HDFS
│   ├── ml/                     # Phase 3: MLlib classification & clustering
│   ├── realtime/               # Phase 4: Bloom filter & streaming
│   │   ├── bloom_filter.py         # Threat intelligence Bloom Filter
│   │   ├── streaming_detector.py   # Spark Streaming detection
│   │   ├── stream_simulator.py     # Network traffic simulator
│   │   ├── online_learning.py      # Adaptive cut + bounded residual layer
│   │   ├── thresholds.json         # Deployed operating point (read, not restated)
│   │   └── run_phase4.py           # Phase 4 runner
│   └── graph/                  # Phase 5: Graph analytics
│       ├── graph_builder.py        # Entity graph construction
│       ├── graph_analytics.py      # Centrality + communities
│       └── run_phase5.py           # Phase 5 runner
│
├── dashboard/                  # Phase 6: the SOC UI served at /dashboard
│   ├── index.html              #   + app.js / graph.js  (what the API serves)
│   ├── app.py                  # legacy Streamlit variant — no launcher starts it
│   └── requirements.txt
│
├── documentation/              # Reports, PRD, dataset + deployment guides
└── *.ps1                       # Launchers: setup_env, verify_datasets,
                                #   upload_datasets, run_threvia_pipeline,
                                #   start_dashboard, start_threvia,
                                #   populate_sample_data, run_phase4_docker,
                                #   run_detector_only
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
- Docker Desktop running (with WSL2 on Windows)
- Python 3.10+ on PATH
- PowerShell (the launchers are `.ps1`)
- ~4 GB RAM free for containers, ~10 GB disk for the datasets

### Step 1 — Host Python environment
```powershell
.\setup_env.ps1
```
Creates `./.venv` and installs `requirements-dev.txt`. Activate it in each new
shell before running anything host-side:
```powershell
.\.venv\Scripts\Activate.ps1
```
(`backend/api/.venv` is a separate, smaller environment that `start_dashboard.ps1`
creates for the API from `backend/api/requirements.txt`.)

### Step 2 — Start the infrastructure
```powershell
docker compose up -d
```

This starts five services — the two optional job profiles stay off until asked:

| Service | Container | Host address |
|---|---|---|
| HDFS NameNode Web UI | `threvia-namenode` | http://localhost:9870 |
| HDFS RPC | `threvia-namenode` | `hdfs://localhost:8020` |
| Spark Master Web UI | `threvia-spark-master` | http://localhost:8080 |
| Spark master RPC | `threvia-spark-master` | `spark://localhost:7077` |
| MongoDB | `threvia-mongodb` | `mongodb://localhost:27018` |
| Stream simulator | `threvia-stream-simulator` | profile `phase4` |
| Streaming detector | `threvia-streaming-detector` | profile `phase4` |
| Dashboard API | `threvia-api` | http://localhost:8000/dashboard — profile `phase6` |

Note MongoDB is published on **27018**, not 27017, because 27017 is commonly
taken by a MongoDB installed on the host. Containers still reach it at
`mongodb:27017` (that is what `MONGO_URI` is set to in compose); host-side Python
(the API, the populator, the graph exporter) defaults to 27018 to match.

### Step 3 — Upload the datasets to HDFS
```powershell
.\verify_datasets.ps1        # are the CSVs on disk?
.\upload_datasets.ps1 -All   # raw CIC-IDS-2017 + the Phase 2 corpus sources
```
`upload_datasets.ps1` is idempotent: files already in HDFS are skipped, so it is
cheap to re-run. Phase 1 validates `/threvia/raw`, so this has to happen before
the pipeline (Step 4).

### Step 4 — Validate the upload
```powershell
docker exec threvia-namenode python3 /workspace/backend/ingestion/validate_hdfs.py
```

Or inspect HDFS directly:
```powershell
docker exec threvia-namenode hdfs dfs -ls /threvia/raw
```

### Step 5 — Inspect a dataset locally (optional)
```powershell
python backend/ingestion/inspect_dataset.py
```

### Stop everything
```powershell
docker compose down
```

To also wipe volumes (HDFS data, MongoDB, learned state):
```powershell
docker compose down -v
```

---

## Running this on another machine

Everything needed to reproduce a run is in git **except the datasets and the
trained models** — both are too large. The complete checklist:

| # | Requirement | How |
|---|---|---|
| 1 | Docker Desktop | https://www.docker.com/products/docker-desktop |
| 2 | Python 3.10+ on PATH | `python --version` |
| 3 | Host Python deps | `.\setup_env.ps1` → `./.venv` from `requirements-dev.txt` |
| 4 | Datasets (~8.7 GB) | [documentation/DATA_SETUP_GUIDE.md](documentation/DATA_SETUP_GUIDE.md), then `.\verify_datasets.ps1` |
| 5 | HDFS upload | `.\upload_datasets.ps1 -All` (after `docker compose up -d`) |
| 6 | Trained models | produced by Phase 3, stored in HDFS — a fresh clone must run `.\run_threvia_pipeline.ps1` at least once, or receive the HDFS volumes |
| 7 | MongoDB contents | the detector fills it live; for a demo `.\start_dashboard.ps1` populates sample data |

What is deliberately **not** in git: `backend/data/**` (datasets, ignored),
trained models (they live in HDFS under `/threvia/models_clean_v3`), the Bloom
filter pickle and the PyVis export (both regenerated), every venv, and the
per-machine `.env`/`hadoop.env` files.

Common failure modes on a new machine:
- **`MongoServerSelectionError` from a host script** → Mongo is on 27018; sets
  `MONGO_URI` or fix the port. Inside containers it is `mongodb:27017`.
- **Phase 1 reports missing files** → you skipped `upload_datasets.ps1`.
- **The dashboard loads but is empty** → MongoDB has no documents yet. Run
  `.\populate_sample_data.ps1` (sample data) or `docker compose --profile phase4
  up -d` (live stream).
- **`docker compose up -d` starts no detector** → that is the profiles working:
  add `--profile phase4` (simulator + detector) and/or `--profile phase6` (API).

---

## Adaptive detection (online learning)

Phase 4 ships a second layer that sits between the frozen Random Forest's score and
the alert decision. **The model is not retrained.**
`backend/realtime/online_learning.py` changes *where the line falls* and re-ranks
scores, and every change it makes is bounded, reversible and visible in the UI. It
exists because the deployed operating point was calibrated on the lab corpus, and
live traffic is not that corpus.

Three parts, in increasing order of what they are allowed to change:

| Part | What it does | Bound |
|---|---|---|
| **Drift monitor** | PSI + KS of a 20-bin score histogram against a frozen baseline. A *persistent* shift re-anchors the baseline and increments a counter, so "re-anchors ≥ 1" is a durable statement that live traffic differs from the calibration corpus. | Decides nothing |
| **Rate control** | Label-free. Holds the fraction of scored flows that alert at `target_alert_rate` by tracking the `1−budget` quantile of recent adapted scores. | Cut clamped to `0.5× … min(4×, ceiling)` around the calibrated anchor |
| **Residual calibrator** | Supervised logistic correction over `[bias, logit p, bot evidence, novelty, drift]`, AdaGrad with L2 + forgetting. | `|w·φ| ≤ 1.5` logits; at `w = 0` it is the exact identity |

Supervision is **analyst verdicts** (the drawer's CONFIRM THREAT / MARK FALSE
POSITIVE buttons, or `POST /api/v1/feedback`) plus the stream's benign majority —
accepted only below `0.10 × cut`, down-weighted to 0.25, and **switched off while
drift is severe**, because in a severe shift "scored low" is evidence of novelty,
not of benignity. It never trains on its own predictions: that is confirmation bias
with a drift-driven amplifier.

Controls (all read by `OnlineLearningConfig.from_env()`; the commented-out block is
already in `docker-compose.yml` under `streaming-detector`):

| Variable | Default | Effect |
|---|---|---|
| `ONLINE_LEARNING` | `on` | `off` runs the frozen operating point — the matched A/B baseline |
| `ONLINE_LEARNING_TARGET_RATE` | `0.025` | alert-rate budget, as a fraction of scored flows |
| `ONLINE_LEARNING_STEP` | `0.25` | EMA pull toward the budget-quantile cut, per batch |
| `ONLINE_LEARNING_MAX_SHIFT` | `1.5` | cap on the residual, in log-odds |
| `ONLINE_LEARNING_CEILING` | *unset* | absolute cap on the adapted cut (e.g. the severity ladder's top rung) |
| `ONLINE_LEARNING_STATE` | `/tmp/threvia_learning_state.json` | checkpoint path; compose points it at the `learning_state` volume |
| `ONLINE_LEARNING_PRIME` | *unset* | JSON file of known-benign scores, to seed the drift reference instead of bootstrapping from the first batch |
| `FEEDBACK_POLL_SECONDS` | `20` | how often the detector reads new verdicts |

**Where to see it.** The dashboard's *ADAPTIVE DETECTION · ONLINE LEARNING* panel
shows anchor → adapted cut, realized rate vs budget, PSI/KS/verdict/re-anchors, the
residual's norm and update count, verdicts consumed vs recorded, and a rate
sparkline against the budget. The same data is at `GET /api/v1/learning/status`.
State is checkpointed to disk *and* mirrored into MongoDB (`learning_state`,
`learning_telemetry`, `feedback`) because the API runs in a different process from
the detector; delete the `learning_state` volume to start learning from scratch.

**What it deliberately does not do**, so this does not read as more than it is:
- It cannot recover an attack the frozen model scores below the gate. A bounded
  post-hoc correction does not move a novel attack family the corpus never
  contained — that needs the offline retrain loop, and the verdicts and telemetry
  this layer accumulates are exactly that loop's input.
- The rate target is subordinate to the band. On an attack-dense stream the
  requested rate is unreachable, so the controller saturates at its ceiling and
  reports `budget_saturated` rather than silently muting real detections.
- Its defaults are slow on purpose: adapting a *measured* operating point quickly
  is how you lose the ability to explain a decision afterwards.

Verified directly (no Docker needed) by driving the policy: 20 attack-dense batches
push the cut to its ceiling with `budget_saturated` set, 20 quiet batches relax it
back to the anchor, re-anchoring fires with a logged warning, duplicate and unusable
verdicts are skipped, and save/reload round-trips the cut, label count and weights.
Unit suite: `python backend/realtime/test_online_learning.py` (24 tests).

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
    FastAPI backend + SOC UI (index.html/app.js) → radar, spectral, topology,
    telemetry stream, online-learning panel
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
> `backend/ml/leakage_check.py` and `backend/ml/advanced_eval.py` for full diagnostics.

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
