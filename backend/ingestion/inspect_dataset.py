"""
Phase 1 — Dataset Quick Inspector
Run this locally (on host, no Docker needed) to verify CSV files
before uploading to HDFS.

Usage:
    python backend/ingestion/inspect_dataset.py
"""

import os
import csv

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

def inspect_csv(filepath):
    filename = os.path.basename(filepath)
    size_mb = os.path.getsize(filepath) / (1024 * 1024)

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        # Count rows efficiently
        row_count = sum(1 for _ in reader)

    labels = set()
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        label_col = " Label" if " Label" in reader.fieldnames else "Label"
        for row in reader:
            labels.add(row.get(label_col, "UNKNOWN").strip())

    return {
        "file": filename,
        "size_mb": round(size_mb, 1),
        "columns": len(header),
        "rows": row_count,
        "labels": sorted(labels),
    }


def main():
    print("=" * 70)
    print("THREVIA — CICIDS2017 Dataset Inspection")
    print("=" * 70)

    csv_files = [
        os.path.join(DATA_DIR, f)
        for f in os.listdir(DATA_DIR)
        if f.endswith(".csv")
    ]

    if not csv_files:
        print(f"No CSV files found in {DATA_DIR}")
        return

    total_rows = 0
    all_labels = set()

    for fpath in sorted(csv_files):
        print(f"\nInspecting: {os.path.basename(fpath)} ...")
        info = inspect_csv(fpath)
        total_rows += info["rows"]
        all_labels.update(info["labels"])

        print(f"  Size     : {info['size_mb']} MB")
        print(f"  Columns  : {info['columns']}")
        print(f"  Rows     : {info['rows']:,}")
        print(f"  Labels   : {info['labels']}")

    print("\n" + "=" * 70)
    print(f"TOTAL ROWS across all files : {total_rows:,}")
    print(f"ALL UNIQUE LABELS           : {sorted(all_labels)}")
    print("=" * 70)


if __name__ == "__main__":
    main()
