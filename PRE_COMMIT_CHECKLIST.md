# Pre-Commit Checklist for GitHub Push

## ✅ Files to INCLUDE (commit these)

### Core Code
- [x] `backend/ml/*.py` - Training scripts
- [x] `backend/processing/*.py` - Data processing
- [x] `backend/realtime/*.py` - Streaming detector & simulator
- [x] `backend/api/main.py` - FastAPI backend
- [x] `backend/api/requirements.txt` - API dependencies

### Dashboard
- [x] `dashboard/index.html` - Main dashboard UI
- [x] `dashboard/app.js` - Frontend JavaScript
- [x] `dashboard/README.md` - Dashboard documentation

### Configuration
- [x] `docker-compose.yml` - Docker orchestration
- [x] `requirements.txt` - Python dependencies
- [x] `.gitignore` - Git exclusions

### Scripts
- [x] `run_threvia_pipeline.ps1` - Main pipeline runner
- [x] `start_dashboard.ps1` - Dashboard launcher
- [x] `verify_datasets.ps1` - Dataset verification

### Documentation
- [x] `README.md` - Project overview
- [x] `QUICK_START.md` - Quick start guide
- [x] `DASHBOARD_EXPLAINED.md` - Dashboard docs
- [x] `DATA_SETUP.md` - Dataset download guide
- [x] `documentation/*.md` - All docs

## ❌ Files to EXCLUDE (already in .gitignore)

### Large Datasets (>10MB each)
- [ ] `backend/data/**/*.csv` - Raw dataset CSVs
- [ ] `backend/data/**/*.parquet` - Parquet files
- [ ] `backend/data/**/*.xlsx` - Excel files

### Virtual Environments
- [ ] `.venv/` - Root Python venv
- [ ] `backend/api/.venv/` - API Python venv

### Generated Artifacts
- [ ] `backend/realtime/bloom_filter.pkl` - Bloom filter (regenerated)
- [ ] `backend/graph/graph_export.html` - Graph viz (regenerated)
- [ ] `lib/` - PyVis vendor libs

### Python Cache
- [ ] `__pycache__/` - Python bytecode
- [ ] `*.pyc`, `*.pyo` - Compiled Python

### IDE & OS
- [ ] `.vscode/`, `.idea/` - IDE configs
- [ ] `.freebuff/` - FreeBuff project files
- [ ] `.DS_Store`, `Thumbs.db` - OS metadata

### Debug/Test Scripts (optional to exclude)
- [ ] `backend/realtime/debug_*.py`
- [ ] `backend/realtime/check_*.py`
- [ ] `backend/realtime/test_*.py`
- [ ] `backend/ml/diagnose_*.py`

## 🔍 Pre-Push Verification

Run these checks before pushing:

```powershell
# 1. Check git status
git status

# 2. Verify no large files are staged (>100MB will fail GitHub push)
git ls-files -s | ForEach-Object { $_.Split()[3] } | ForEach-Object { if ((Get-Item $_).Length -gt 100MB) { Write-Host "WARNING: Large file: $_" } }

# 3. Check for sensitive data
git diff --cached | Select-String -Pattern "(password|secret|token|key|api_key)" -CaseSensitive

# 4. Verify .gitignore is working
git check-ignore backend/data/**/*.csv

# 5. Test build (optional but recommended)
docker-compose build --no-cache
```

## 📋 Recommended Commit Strategy

```powershell
# Stage all modified and new files
git add .

# Check what will be committed
git status

# Create descriptive commit
git commit -m "feat: Complete Phase 4 streaming detector with ML classification

- Added real-time ML pipeline with DDoS/Bot detection
- Implemented dashboard with radar visualization
- Fixed MongoDB connection for live telemetry
- Added severity levels based on confidence scores
- Updated documentation with setup guides"

# Push to GitHub
git push origin main
```

## 🚨 Common Issues

### Issue: "File too large" error
**Solution**: File >100MB detected. Check if dataset accidentally staged:
```powershell
git rm --cached backend/data/CIC-IDS-*/
git commit --amend -m "Remove accidentally staged datasets"
```

### Issue: Sensitive data in commit
**Solution**: Use BFG Repo Cleaner or git-filter-branch to remove:
```powershell
# Install BFG
choco install bfg-repo-cleaner

# Remove sensitive file from history
bfg --delete-files sensitive_file.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### Issue: .gitignore not working
**Solution**: Untrack already-committed files:
```powershell
git rm -r --cached .
git add .
git commit -m "chore: Fix .gitignore patterns"
```

## ✨ After Successful Push

Update README.md with:
- [ ] GitHub repository URL
- [ ] Clone instructions
- [ ] Dataset download links
- [ ] Quick start guide reference

Example:
```markdown
## Clone & Setup

git clone https://github.com/yourusername/threvia.git
cd threvia

# Download datasets (see DATA_SETUP.md)
# Then run pipeline
.\run_threvia_pipeline.ps1 -Phases 2,3,4
```
