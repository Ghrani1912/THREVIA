"""
Phase 1 — HDFS Validation Script
Run this AFTER docker compose up to confirm:
  1. All 8 CICIDS2017 CSVs are in HDFS at /threvia/raw/
  2. File sizes look correct
  3. HDFS directory structure is ready for Phase 2

Usage (from host, after containers are up):
  docker exec threvia-namenode python3 /workspace/backend/ingestion/validate_hdfs.py

Or run directly inside the namenode container bash:
  hdfs dfs -ls /threvia/raw
"""

import subprocess
import sys

EXPECTED_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

HDFS_RAW_PATH = "/threvia/raw"

def run_hdfs(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def main():
    print("=" * 60)
    print("THREVIA Phase 1 — HDFS Validation")
    print("=" * 60)

    # Check HDFS directories exist
    for path in ["/threvia/raw", "/threvia/processed", "/threvia/output"]:
        stdout, stderr, code = run_hdfs(f"hdfs dfs -test -d {path}")
        if code == 0:
            print(f"[OK]  Directory exists: {path}")
        else:
            print(f"[FAIL] Directory missing: {path}")
            sys.exit(1)

    # List files in /threvia/raw
    stdout, stderr, code = run_hdfs(f"hdfs dfs -ls {HDFS_RAW_PATH}")
    if code != 0:
        print(f"[FAIL] Cannot list {HDFS_RAW_PATH}: {stderr}")
        sys.exit(1)

    print(f"\nFiles found in {HDFS_RAW_PATH}:")
    print(stdout)

    # Check each expected file exists
    all_ok = True
    for fname in EXPECTED_FILES:
        hdfs_path = f"{HDFS_RAW_PATH}/{fname}"
        stdout, stderr, code = run_hdfs(f"hdfs dfs -test -e {hdfs_path}")
        if code == 0:
            # Get file size
            size_out, _, _ = run_hdfs(f"hdfs dfs -du -h {hdfs_path}")
            size = size_out.split()[0] if size_out else "?"
            print(f"  [OK]  {fname}  ({size})")
        else:
            print(f"  [MISSING]  {fname}")
            all_ok = False

    print("\n" + "=" * 60)
    if all_ok:
        print("Phase 1 PASSED — All datasets loaded into HDFS successfully.")
        print("Ready for Phase 2: Batch Processing & Feature Extraction.")
    else:
        print("Phase 1 FAILED — Some files are missing. Re-run hdfs-init.")
    print("=" * 60)


if __name__ == "__main__":
    main()
