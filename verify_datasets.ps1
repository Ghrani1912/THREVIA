# THREVIA Dataset Verification Script
# ====================================
# Checks if all required datasets are downloaded and in the correct locations

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  THREVIA Dataset Verification" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$allPresent = $true
$totalSize = 0

# Define required datasets
$requiredDatasets = @(
    @{
        Name = "LycoS-IDS2018"
        Path = "backend/data/LYCSOS/LycoS-Unicas-IDS2018.csv"
        Required = $true
        ExpectedSize = 5.2
    },
    @{
        Name = "CIC-IDS-2017 (Friday PortScan)"
        Path = "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 1.0
    },
    @{
        Name = "CIC-IDS-2017 (Friday DDoS)"
        Path = "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 1.5
    },
    @{
        Name = "CIC-IDS-2017 (Monday)"
        Path = "backend/data/CIC-IDS- 2017/Monday-WorkingHours.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.5
    },
    @{
        Name = "CIC-IDS-2017 (Tuesday)"
        Path = "backend/data/CIC-IDS- 2017/Tuesday-WorkingHours.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.4
    },
    @{
        Name = "CIC-IDS-2017 (Wednesday)"
        Path = "backend/data/CIC-IDS- 2017/Wednesday-workingHours.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.6
    },
    @{
        Name = "CIC-IDS-2017 (Thursday Morning)"
        Path = "backend/data/CIC-IDS- 2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.2
    },
    @{
        Name = "CIC-IDS-2017 (Thursday Afternoon)"
        Path = "backend/data/CIC-IDS- 2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.3
    },
    @{
        Name = "CIC-IDS-2017 (Friday Morning)"
        Path = "backend/data/CIC-IDS- 2017/Friday-WorkingHours-Morning.pcap_ISCX.csv"
        Required = $true
        ExpectedSize = 0.5
    },
    @{
        Name = "CICIDS2018 (Thursday)"
        Path = "backend/data/CICIDS2018/CICIDS2018_Thursday.csv"
        Required = $true
        ExpectedSize = 1.5
    },
    @{
        Name = "CICIDS2018 (Wednesday)"
        Path = "backend/data/CICIDS2018/CICIDS2018_Wednesday.csv"
        Required = $true
        ExpectedSize = 0.5
    },
    @{
        Name = "IDS2025 (Validation)"
        Path = "backend/data/IDS2025 (Balanced Intrusion Detection Evaluation D)/IDS2025.xlsx"
        Required = $false
        ExpectedSize = 0.1
    }
)

Write-Host "Checking required datasets...`n" -ForegroundColor Yellow

foreach ($dataset in $requiredDatasets) {
    $exists = Test-Path $dataset.Path
    
    if ($exists) {
        $file = Get-Item $dataset.Path
        $sizeGB = [math]::Round($file.Length / 1GB, 2)
        $totalSize += $sizeGB
        
        Write-Host "✅ " -ForegroundColor Green -NoNewline
        Write-Host "$($dataset.Name): " -NoNewline
        Write-Host "$sizeGB GB" -ForegroundColor Gray
    }
    else {
        if ($dataset.Required) {
            Write-Host "❌ " -ForegroundColor Red -NoNewline
            Write-Host "$($dataset.Name): " -NoNewline
            Write-Host "MISSING (required)" -ForegroundColor Red
            $allPresent = $false
        }
        else {
            Write-Host "⚠️  " -ForegroundColor Yellow -NoNewline
            Write-Host "$($dataset.Name): " -NoNewline
            Write-Host "Missing (optional)" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Total dataset size: $([math]::Round($totalSize, 2)) GB" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if ($allPresent) {
    Write-Host "✅ All required datasets present!" -ForegroundColor Green
    Write-Host "`nYou can now run the pipeline:" -ForegroundColor Yellow
    Write-Host "  docker compose up -d" -ForegroundColor Gray
    Write-Host "  .\run_threvia_pipeline.ps1" -ForegroundColor Gray
    exit 0
}
else {
    Write-Host "❌ Some required datasets are missing!" -ForegroundColor Red
    Write-Host "`nPlease download missing datasets:" -ForegroundColor Yellow
    Write-Host "  See documentation/DATA_SETUP_GUIDE.md for instructions" -ForegroundColor Gray
    Write-Host "`nDataset sources:" -ForegroundColor Yellow
    Write-Host "  • LycoS: https://www.kaggle.com/datasets/mryanm/lycos-ids2018" -ForegroundColor Gray
    Write-Host "  • CIC-IDS-2017: https://www.unb.ca/cic/datasets/ids-2017.html" -ForegroundColor Gray
    Write-Host "  • CICIDS2018: https://www.unb.ca/cic/datasets/ids-2018.html" -ForegroundColor Gray
    exit 1
}
