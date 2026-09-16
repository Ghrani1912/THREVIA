# THREVIA Dataset Setup Guide

## Overview
THREVIA requires several public intrusion detection datasets for training. These datasets are **NOT included in the repository** due to size (>20GB total). Download them separately following this guide.

## Required Datasets

### 1. CIC-IDS-2017
**Purpose**: Primary training corpus for DDoS, PortScan, and Botnet detection

**Download**:
- Official: https://www.unb.ca/cic/datasets/ids-2017.html
- Alternative (Kaggle): https://www.kaggle.com/datasets/cicdataset/cicids2017

**Files needed**:
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Monday-WorkingHours.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`

**Location**: Place in `backend/data/CIC-IDS- 2017/`

### 2. UNSW-NB15
**Purpose**: Secondary training corpus for balanced attack types

**Download**:
- Official: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- Alternative: https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15

**Files needed**:
- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

**Location**: Place in `backend/data/UNSW-NB15/CSV Files/Training and Testing Sets/`

### 3. CTU-13 Botnet (Optional)
**Purpose**: Additional botnet traffic for bot classifier

**Download**: https://www.stratosphereips.org/datasets-ctu13

**Location**: Place parquet files in `backend/data/botnet/`

## Dataset Structure

After downloading, your directory structure should look like:

```
backend/data/
├── CIC-IDS- 2017/
│   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
│   └── ... (other CSV files)
├── UNSW-NB15/
│   └── CSV Files/
│       └── Training and Testing Sets/
│           ├── UNSW_NB15_training-set.csv
│           └── UNSW_NB15_testing-set.csv
└── botnet/ (optional)
    ├── 1-Neris-20110810.binetflow.parquet
    └── ... (other parquet files)
```

## Verification

Run the verification script to check if datasets are correctly placed:

```powershell
.\verify_datasets.ps1
```

Or manually check with Python:

```python
import os

required_files = [
    "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "backend/data/UNSW-NB15/CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv"
]

for path in required_files:
    exists = "✓" if os.path.exists(path) else "✗"
    print(f"{exists} {path}")
```

## Alternative: Pre-processed Datasets

If you have issues downloading the original datasets, contact the repository maintainer for access to pre-processed Parquet files stored on HDFS.

## Storage Requirements

- **Raw datasets**: ~20 GB
- **Processed corpus** (after Phase 2): ~5 GB
- **Trained models** (after Phase 3): ~500 MB
- **Total recommended**: 30+ GB free space

## License & Attribution

All datasets are publicly available research datasets. Please cite the original authors:

- **CIC-IDS-2017**: Sharafaldin et al., Canadian Institute for Cybersecurity
- **UNSW-NB15**: Moustafa & Slay, UNSW Canberra
- **CTU-13**: Stratosphere IPS, Czech Technical University

Refer to each dataset's official page for specific citation requirements.
