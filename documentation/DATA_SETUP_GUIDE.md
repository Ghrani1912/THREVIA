# THREVIA — Data Setup Guide

**For new users cloning the repository**

This guide explains how to obtain and set up the datasets required to run THREVIA.

---

## ⚠️ Important: Datasets Are NOT Included

The THREVIA repository **does not include datasets** because:
- They are very large (15+ GB total)
- Licensing restrictions (some datasets require registration)
- Git is not designed for large binary files

**You must download the datasets separately** before running the pipeline.

---

## Required Datasets

### 1. **LycoS-IDS2018** (Primary Training Dataset) ⭐ **REQUIRED**

**Size:** ~5.2 GB  
**Purpose:** Main training corpus (13.69M rows)  
**Download:** [LycoS Kaggle Dataset](https://www.kaggle.com/datasets/mryanm/lycos-ids2018)

**Steps:**
1. Go to Kaggle link (requires free Kaggle account)
2. Download `LycoS-Unicas-IDS2018.csv`
3. Place in: `backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv`

```powershell
# Create directory
New-Item -ItemType Directory -Force -Path backend/data/LYCSOS

# Place downloaded file here:
# backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv
```

---

### 2. **CIC-IDS-2017** (PortScan Supplement) ⭐ **REQUIRED**

**Size:** ~8 GB (8 CSV files)  
**Purpose:** PortScan class training (72K rows)  
**Download:** [CIC-IDS-2017 Official](https://www.unb.ca/cic/datasets/ids-2017.html)

**Steps:**
1. Register at UNB CIC website (free)
2. Download all 8 CSV files (Monday-Friday)
3. Place in: `backend/data/CIC-IDS- 2017/` (note the space!)

**Required files:**
```
backend/data/CIC-IDS- 2017/
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
```

```powershell
# Create directory (note the space in folder name!)
New-Item -ItemType Directory -Force -Path "backend/data/CIC-IDS- 2017"

# Place downloaded CSVs here
```

---

### 3. **CICIDS2018** (Infiltration Supplement) ⭐ **REQUIRED**

**Size:** ~2 GB  
**Purpose:** Infiltration class (161K rows)  
**Download:** [CICIDS2018 Official](https://www.unb.ca/cic/datasets/ids-2018.html)

**Steps:**
1. Register at UNB CIC website (free)
2. Download Thursday and Wednesday CSV files
3. Place in: `backend/data/CICIDS2018/`

**Required files:**
```
backend/data/CICIDS2018/
├── CICIDS2018_Thursday.csv
└── CICIDS2018_Wednesday.csv
```

```powershell
# Create directory
New-Item -ItemType Directory -Force -Path backend/data/CICIDS2018
```

---

### 4. **IDS2025** (Held-Out Validation) 📊 **OPTIONAL**

**Size:** ~100 MB  
**Purpose:** Validation set only (NOT used in training)  
**Download:** [IDS2025 Kaggle](https://www.kaggle.com/datasets/kittipongkrai/ids2025-balanced-intrusion-detection-evaluation-d)

**Steps:**
1. Go to Kaggle link
2. Download `IDS2025.xlsx`
3. Place in: `backend/data/IDS2025 (Balanced Intrusion Detection Evaluation D)/IDS2025.xlsx`

```powershell
# Create directory
New-Item -ItemType Directory -Force -Path "backend/data/IDS2025 (Balanced Intrusion Detection Evaluation D)"

# The pipeline will convert XLSX → CSV automatically
```

**Note:** Optional because LycoS TEST-A already provides held-out validation.

---

### 5. **UNSW-NB15** (Future Cross-Dataset) 🔮 **NOT USED**

**Purpose:** Future v2.0 cross-dataset validation (different schema)  
**Status:** Not currently integrated into pipeline

If you want to add it for future experiments:
- [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- Place in: `backend/data/UNSW-NB15/`

**Skip this for now** unless doing custom research.

---

## Directory Structure (After Download)

```
backend/data/
├── CIC-IDS- 2017/              # 8 CSV files (~8 GB)
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   └── ... (6 more files)
│
├── CICIDS2018/                 # 2 CSV files (~2 GB)
│   ├── CICIDS2018_Thursday.csv
│   └── CICIDS2018_Wednesday.csv
│
├── LYCSOS/                     # 1 CSV file (~5 GB)
│   └── LycoS-Unicas-IDS2018.csv
│
└── IDS2025 (Balanced...)/      # 1 XLSX file (~100 MB) [OPTIONAL]
    └── IDS2025.xlsx
```

**Total required space:** ~15 GB (excluding optional datasets)

---

## Verification

After downloading datasets, verify they exist:

```powershell
# Check LycoS
Test-Path "backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv"

# Check CIC-IDS-2017 (Friday PortScan specifically)
Test-Path "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

# Check CICIDS2018
Test-Path "backend/data/CICIDS2018/CICIDS2018_Thursday.csv"
```

All should return `True`.

---

## What About HDFS Data?

### HDFS Will Be Populated Automatically

When you run `.\run_threvia_pipeline.ps1`, the pipeline will:

1. **Phase 1:** Upload raw CSVs to HDFS `/threvia/raw`
2. **Phase 2:** Build unified corpus → HDFS `/threvia/corpus/train` (15.69M rows)
3. **Phase 3:** Train models → HDFS `/threvia/models_clean/`

**You don't need to manually populate HDFS.** The pipeline does it.

### Sharing Your Trained Models (For Project Owner)

If you want to help other users **skip the 30-minute training**, you can export and share your trained models:

**Step 1: Export from HDFS**

```powershell
# Create export directory
New-Item -ItemType Directory -Force -Path hdfs_export

# Export trained corpus (15.69M rows)
docker exec threvia-namenode hdfs dfs -get /threvia/corpus/train ./hdfs_export/corpus_train

# Export trained models
docker exec threvia-namenode hdfs dfs -get /threvia/models_clean ./hdfs_export/models_clean

# Compress for sharing (will create ~2-3 GB zip file)
Compress-Archive -Path hdfs_export -DestinationPath threvia_pretrained_models.zip
```

**Step 2: Upload to File Sharing**

Upload `threvia_pretrained_models.zip` to:
- Google Drive (shareable link)
- AWS S3 (public bucket)
- GitHub Releases (if < 2 GB)
- Kaggle Datasets
- University file server

**Step 3: Share Download Link**

Add to `DATA_SETUP_GUIDE.md`:
```markdown
### Optional: Pre-Trained Models

Download pre-trained models to skip 30 minutes of training:
- [Download threvia_pretrained_models.zip](YOUR_LINK_HERE) (2.5 GB)

After downloading:
```powershell
# Extract
Expand-Archive -Path threvia_pretrained_models.zip -DestinationPath .

# Upload to HDFS
docker exec threvia-namenode hdfs dfs -put hdfs_export/corpus_train /threvia/corpus/train
docker exec threvia-namenode hdfs dfs -put hdfs_export/models_clean /threvia/models_clean
```

Then skip to Phase 4:
```powershell
.\run_threvia_pipeline.ps1 -Phases 4,5,6,7
```
```

### If You Want Pre-Trained Models (As New User)

**Option 1: Just Run the Pipeline (Recommended)**

Most users should just run the full pipeline — it's automated and takes 30-40 minutes total:
```powershell
.\run_threvia_pipeline.ps1
```

**Option 2: Download Pre-Trained Models (If Available)**

If the project owner has shared pre-trained models:

```powershell
# Download from shared link (replace with actual URL)
# Example: Google Drive, S3, etc.
Invoke-WebRequest -Uri "SHARED_LINK_HERE" -OutFile threvia_pretrained_models.zip

# Extract
Expand-Archive -Path threvia_pretrained_models.zip -DestinationPath .

# Start Docker
docker compose up -d

# Wait for HDFS to initialize (30 seconds)
Start-Sleep -Seconds 30

# Upload to HDFS
docker exec threvia-namenode hdfs dfs -mkdir -p /threvia/corpus
docker exec threvia-namenode hdfs dfs -mkdir -p /threvia/models_clean
docker exec threvia-namenode hdfs dfs -put hdfs_export/corpus_train /threvia/corpus/train
docker exec threvia-namenode hdfs dfs -put hdfs_export/models_clean/* /threvia/models_clean/

# Run remaining phases (skip 1-3)
.\run_threvia_pipeline.ps1 -Phases 4,5,6,7
```

**Benefits:**
- Saves 30 minutes (no corpus building or training)
- Guarantees exact reproduction of published results
- Useful for demos or testing phases 4-7

**Limitations:**
- Large download (2-3 GB)
- Requires trusting pre-trained models
- Doesn't teach you the full pipeline

---

## Alternative: Use Sample Data (Quick Demo)

If you **only want to test the pipeline** without full datasets:

### Create Tiny Sample CSVs

```powershell
# Run sample data generator (creates small test files)
python backend/ingestion/create_sample_data.py
```

This creates:
- `backend/data/sample/sample_train.csv` (10K rows)
- `backend/data/sample/sample_test.csv` (1K rows)

**Limitations:**
- Won't achieve published accuracy (too small)
- Good for testing code, not for real evaluation
- Models will be undertrained

**Use this only for development/testing, not production.**

---

## Dataset Licensing & Citations

### LycoS-IDS2018
- **License:** CC BY 4.0 (free to use with attribution)
- **Citation:**
  ```
  Ryan, M. (2023). LycoS-IDS2018. Kaggle.
  https://www.kaggle.com/datasets/mryanm/lycos-ids2018
  ```

### CIC-IDS-2017
- **License:** Free for research/educational use
- **Citation:**
  ```
  Sharafaldin, I., Lashkari, A.H., Ghorbani, A.A. (2018).
  "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization."
  Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP).
  ```

### CICIDS2018
- **License:** Free for research/educational use
- **Citation:**
  ```
  Sharafaldin, I., Lashkari, A.H., Hakak, S., Ghorbani, A.A. (2019).
  "Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy."
  International Carnahan Conference on Security Technology (ICCST).
  ```

### IDS2025
- **License:** CC BY 4.0
- **Citation:**
  ```
  Kittipongkrai, K. (2024). IDS2025: Balanced Intrusion Detection Evaluation Dataset. Kaggle.
  https://www.kaggle.com/datasets/kittipongkrai/ids2025-balanced-intrusion-detection-evaluation-d
  ```

**Always cite datasets if publishing research using THREVIA.**

---

## Troubleshooting

### "File not found" error during pipeline

**Problem:** Dataset missing or in wrong location

**Solution:**
```powershell
# Verify all required files exist
Test-Path "backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv"
Test-Path "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
Test-Path "backend/data/CICIDS2018/CICIDS2018_Thursday.csv"
```

### "HDFS path does not exist"

**Problem:** HDFS not initialized

**Solution:**
```powershell
# Check HDFS is running
docker exec threvia-namenode hdfs dfs -ls /

# Re-run Phase 1
.\run_threvia_pipeline.ps1 -Phases 1
```

### "Out of space" during download

**Problem:** Not enough disk space

**Solution:**
- Free up at least 20 GB (15 GB datasets + 5 GB HDFS overhead)
- Or use external drive and symlink:
  ```powershell
  # Download to external drive (e.g., D:\threvia_data)
  # Then create symlink
  New-Item -ItemType SymbolicLink -Path "backend/data" -Target "D:\threvia_data"
  ```

### "Access denied" downloading datasets

**Problem:** Kaggle/UNB requires login

**Solution:**
- Create free Kaggle account: https://www.kaggle.com/account/login
- Register at UNB CIC: https://www.unb.ca/cic/datasets/

---

## Quick Reference Card

| Dataset | Size | Required? | Purpose | Download Link |
|---------|------|-----------|---------|---------------|
| **LycoS-IDS2018** | 5 GB | ⭐ YES | Primary training (13.69M rows) | [Kaggle](https://www.kaggle.com/datasets/mryanm/lycos-ids2018) |
| **CIC-IDS-2017** | 8 GB | ⭐ YES | PortScan class (72K rows) | [UNB CIC](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **CICIDS2018** | 2 GB | ⭐ YES | Infiltration class (161K rows) | [UNB CIC](https://www.unb.ca/cic/datasets/ids-2018.html) |
| **IDS2025** | 100 MB | 📊 Optional | Held-out validation | [Kaggle](https://www.kaggle.com/datasets/kittipongkrai/ids2025-balanced-intrusion-detection-evaluation-d) |
| **UNSW-NB15** | 1 GB | 🔮 Not used | Future v2.0 | [UNSW](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |

---

## Next Steps

After downloading datasets:

1. **Verify files exist** (see Verification section above)
2. **Run pipeline:** `.\run_threvia_pipeline.ps1`
3. **Wait 30-40 minutes** (automatic corpus building + training)
4. **Access dashboard:** http://localhost:8501

**See [QUICKSTART.md](QUICKSTART.md) for deployment instructions.**

---

**Questions?** See [DEPLOYMENT_GUIDE.md](documentation/DEPLOYMENT_GUIDE.md) troubleshooting section.

**Last Updated:** September 12, 2026
