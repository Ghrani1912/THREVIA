"""
Task 5 — Convert IDS2025 XLSX → CSV + upload to HDFS as held-out validation set.

Steps:
  1. Read IDS2025.xlsx (single sheet, 91,830 rows)
  2. Apply IDS25_RENAME column map + drop IDS25_EXTRA_DROP cols
  3. Apply LABEL_NORMALISE to the newLabel column
  4. Write to backend/data/ids2025_clean/ids2025_validation.csv
  5. Upload to HDFS /threvia/validation/ids2025

Usage (local, no Docker needed):
    python backend/processing/convert_ids2025.py

Usage (upload step only, run inside namenode container):
    hdfs dfs -put /workspace/backend/data/ids2025_clean/ids2025_validation.csv \
              /threvia/validation/ids2025_validation.csv
"""

import csv
import os
import sys
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from processing.schema_maps import (
    IDS25_RENAME, IDS25_EXTRA_DROP,
    CANONICAL_FEATURE_COLS, CANONICAL_LABEL_COL,
    normalise_label,
)

try:
    import openpyxl
except ImportError:
    print("ERROR: openpyxl not installed. Run: pip install openpyxl")
    sys.exit(1)

DATA_DIR   = os.path.join(os.path.dirname(__file__), '..', 'data')
XLSX_PATH  = os.path.join(DATA_DIR,
    'IDS2025 (Balanced Intrusion Detection Evaluation D', 'IDS2025.xlsx')
OUT_DIR    = os.path.join(DATA_DIR, 'ids2025_clean')
OUT_CSV    = os.path.join(OUT_DIR, 'ids2025_validation.csv')
HDFS_DEST  = 'hdfs://namenode:8020/threvia/validation/ids2025_validation.csv'


def sep(title):
    print('\n' + '=' * 60)
    print(f'  {title}')
    print('=' * 60)


def main():
    sep('THREVIA — IDS2025 XLSX → CSV Conversion')
    os.makedirs(OUT_DIR, exist_ok=True)

    # ── 1. Open workbook ──────────────────────────────────────────
    print(f'\n[1/5] Opening {XLSX_PATH} ...')
    wb = openpyxl.load_workbook(XLSX_PATH, read_only=True, data_only=True)
    ws = wb.active
    print(f'  Sheet   : {ws.title}')
    print(f'  Max row : {ws.max_row}')
    print(f'  Max col : {ws.max_column}')

    # ── 2. Read headers ───────────────────────────────────────────
    print('\n[2/5] Reading headers and building rename map ...')
    raw_headers = [cell.value for cell in next(ws.iter_rows(min_row=1, max_row=1))]
    print(f'  Raw header count : {len(raw_headers)}')

    # Build final column order: apply renames, drop extra cols
    # Output cols = canonical feature cols in order + Label
    # Any IDS2025 col not in rename map keeps its name if it maps to canonical
    rename_map = IDS25_RENAME.copy()
    drop_set   = set(IDS25_EXTRA_DROP)

    # Map: raw xlsx col → output canonical col (or None if dropped)
    col_map = {}
    for raw in raw_headers:
        if raw is None:
            col_map[raw] = None
            continue
        if raw in drop_set:
            col_map[raw] = None
        elif raw in rename_map:
            col_map[raw] = rename_map[raw]
        else:
            # Keep as-is if it matches a canonical col directly
            col_map[raw] = raw

    # Canonical output order
    output_cols = CANONICAL_FEATURE_COLS  # includes 'Label' at end

    print(f'  Dropped cols : {[c for c in raw_headers if col_map.get(c) is None]}')
    print(f'  Output cols  : {len(output_cols)}')

    # Check which canonical cols are present vs missing in IDS2025
    ids25_targets = set(col_map.values()) - {None}
    missing_in_ids25 = [c for c in output_cols if c not in ids25_targets]
    print(f'  Canonical cols NOT in IDS2025 (will be empty): {missing_in_ids25}')

    # ── 3. Read rows, apply rename + label normalisation ──────────
    print('\n[3/5] Converting rows ...')
    import collections
    label_dist = collections.Counter()
    rows_written = 0
    rows_skipped = 0

    with open(OUT_CSV, 'w', newline='', encoding='utf-8') as out_f:
        writer = csv.DictWriter(out_f, fieldnames=output_cols,
                                extrasaction='ignore')
        writer.writeheader()

        for xlsx_row in ws.iter_rows(min_row=2, values_only=True):
            # Map xlsx values to canonical col names
            row_dict = {}
            for raw_col, cell_val in zip(raw_headers, xlsx_row):
                canon_col = col_map.get(raw_col)
                if canon_col is None:
                    continue
                # Convert to string, handle None
                row_dict[canon_col] = '' if cell_val is None else str(cell_val)

            # Normalise label
            raw_label = row_dict.get('Label', '').strip()
            if not raw_label:
                rows_skipped += 1
                continue
            row_dict['Label'] = normalise_label(raw_label)
            label_dist[row_dict['Label']] += 1

            # Fill missing canonical cols with empty string
            for col in output_cols:
                if col not in row_dict:
                    row_dict[col] = ''

            writer.writerow(row_dict)
            rows_written += 1

            if rows_written % 20000 == 0:
                print(f'  ...{rows_written:,} rows written')

    wb.close()

    print(f'\n  Rows written  : {rows_written:,}')
    print(f'  Rows skipped  : {rows_skipped:,}')
    print(f'\n  Label distribution:')
    for label, count in sorted(label_dist.items(), key=lambda x: -x[1]):
        pct = count / rows_written * 100
        print(f'    {label:<40} {count:>8,}  ({pct:5.1f}%)')

    # ── 4. Validate output CSV ────────────────────────────────────
    print('\n[4/5] Validating output CSV ...')
    with open(OUT_CSV, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        check_cols = reader.fieldnames
        val_rows = sum(1 for _ in reader)

    print(f'  Output file   : {OUT_CSV}')
    print(f'  Output cols   : {len(check_cols)}  (expected {len(output_cols)})')
    print(f'  Output rows   : {val_rows:,}  (expected {rows_written:,})')
    size_mb = os.path.getsize(OUT_CSV) / 1024 / 1024
    print(f'  File size     : {size_mb:.2f} MB')
    assert len(check_cols) == len(output_cols), 'Column count mismatch!'
    assert val_rows == rows_written, 'Row count mismatch!'
    print('  Validation    : PASS')

    # ── 5. HDFS upload ────────────────────────────────────────────
    print('\n[5/5] Uploading to HDFS ...')
    print(f'  Source : {OUT_CSV}')
    print(f'  Dest   : {HDFS_DEST}')

    # Create HDFS dir
    mkdir_cmd = ['docker', 'exec', 'threvia-namenode',
                 'hdfs', 'dfs', '-mkdir', '-p', '/threvia/validation']
    ret = subprocess.run(mkdir_cmd, capture_output=True, text=True)
    if ret.returncode != 0:
        print(f'  mkdir stderr: {ret.stderr.strip()}')

    # Put file — path inside container is via the mounted /workspace volume
    container_path = '/workspace/backend/data/ids2025_clean/ids2025_validation.csv'
    put_cmd = ['docker', 'exec', 'threvia-namenode',
               'hdfs', 'dfs', '-put', '-f', container_path,
               '/threvia/validation/ids2025_validation.csv']
    ret = subprocess.run(put_cmd, capture_output=True, text=True)
    if ret.returncode == 0:
        # Verify
        ls_cmd = ['docker', 'exec', 'threvia-namenode',
                  'hdfs', 'dfs', '-ls', '/threvia/validation/']
        ls = subprocess.run(ls_cmd, capture_output=True, text=True)
        print(f'  Upload: SUCCESS')
        print(f'  HDFS listing:\n{ls.stdout.strip()}')
    else:
        print(f'  Upload: FAILED')
        print(f'  stderr: {ret.stderr.strip()}')
        print(f'  You can upload manually with:')
        print(f'    docker exec threvia-namenode hdfs dfs -put -f \\')
        print(f'      {container_path} /threvia/validation/ids2025_validation.csv')

    sep('COMPLETE')
    print(f'  CSV    : {OUT_CSV}')
    print(f'  Rows   : {rows_written:,}')
    print(f'  HDFS   : {HDFS_DEST}')


if __name__ == '__main__':
    main()
