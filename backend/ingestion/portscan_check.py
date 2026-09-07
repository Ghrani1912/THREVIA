"""Quick PortScan coverage check across all available datasets."""
import csv, collections, os, openpyxl

DATA_ROOT = os.path.join(os.path.dirname(__file__), '..', 'data')

def scan_labels_csv(path, label_col=None):
    labels = collections.Counter()
    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        if label_col is None:
            label_col = next(
                (c for c in reader.fieldnames if c.strip().lower() == 'label'), None
            )
        for row in reader:
            val = row.get(label_col, '').strip()
            labels[val] += 1
    return labels

def sep(title):
    print('\n' + '='*60)
    print(f'  {title}')
    print('='*60)

# ── CIC-IDS-2017 ──────────────────────────────────────────────
sep('CIC-IDS-2017 (8 files)')
labels_17 = collections.Counter()
for fname in sorted(os.listdir(os.path.join(DATA_ROOT, 'CIC-IDS- 2017'))):
    fpath = os.path.join(DATA_ROOT, 'CIC-IDS- 2017', fname)
    with open(fpath, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        label_col = next((c for c in reader.fieldnames if c.strip() == 'Label'), None)
        for row in reader:
            labels_17[row[label_col].strip()] += 1
for k, v in sorted(labels_17.items(), key=lambda x: -x[1]):
    marker = '  <<< PORTSCAN' if 'port' in k.lower() or 'scan' in k.lower() else ''
    print(f'  {k:<42} {v:>10,}{marker}')
print(f'  TOTAL: {sum(labels_17.values()):,}')

# ── LycoS ─────────────────────────────────────────────────────
sep('LycoS-IDS2018 (full scan - may take ~2 min)')
lycos_labels = collections.Counter()
with open(os.path.join(DATA_ROOT, 'LYCSOS', 'LycoS-Unicas-IDS2018.csv'),
          encoding='utf-8', errors='replace') as f:
    for i, line in enumerate(f):
        if i == 0:
            continue
        val = line.rstrip('\n').rsplit(',', 1)[-1].strip()
        lycos_labels[val] += 1
        if i % 3_000_000 == 0:
            print(f'  ...{i:,} rows processed')
for k, v in sorted(lycos_labels.items(), key=lambda x: -x[1]):
    marker = '  <<< PORTSCAN' if 'port' in k.lower() or 'scan' in k.lower() else ''
    print(f'  {k:<42} {v:>10,}{marker}')
print(f'  TOTAL: {sum(lycos_labels.values()):,}')

# ── CICIDS2018 ─────────────────────────────────────────────────
sep('CICIDS2018 (all files in folder)')
for fname in sorted(os.listdir(os.path.join(DATA_ROOT, 'CICIDS2018'))):
    fpath = os.path.join(DATA_ROOT, 'CICIDS2018', fname)
    labels = scan_labels_csv(fpath)
    print(f'  [{fname}]')
    for k, v in sorted(labels.items(), key=lambda x: -x[1]):
        marker = '  <<< PORTSCAN' if 'port' in k.lower() or 'scan' in k.lower() else ''
        print(f'    {k:<40} {v:>10,}{marker}')

# ── IDS2025 ───────────────────────────────────────────────────
sep('IDS2025 (xlsx)')
wb = openpyxl.load_workbook(
    os.path.join(DATA_ROOT,
                 'IDS2025 (Balanced Intrusion Detection Evaluation D',
                 'IDS2025.xlsx'),
    read_only=True, data_only=True
)
ws = wb.active
ids25_labels = collections.Counter()
for row in ws.iter_rows(min_row=2, values_only=True):
    if row and row[-1] is not None:
        ids25_labels[str(row[-1]).strip()] += 1
for k, v in sorted(ids25_labels.items(), key=lambda x: -x[1]):
    marker = '  <<< PORTSCAN' if 'port' in k.lower() or 'scan' in k.lower() else ''
    print(f'  {k:<42} {v:>10,}{marker}')
print(f'  TOTAL: {sum(ids25_labels.values()):,}')

# ── UNSW-NB15 ─────────────────────────────────────────────────
sep('UNSW-NB15 (training + testing)')
for fname in ['UNSW_NB15_training-set.csv', 'UNSW_NB15_testing-set.csv']:
    fpath = os.path.join(DATA_ROOT, 'UNSW-NB15', 'CSV Files',
                         'Training and Testing Sets', fname)
    labels = scan_labels_csv(fpath, label_col='attack_cat')
    print(f'  [{fname}]')
    for k, v in sorted(labels.items(), key=lambda x: -x[1]):
        marker = '  <<< RECON/SCAN' if 'recon' in k.lower() or 'scan' in k.lower() or 'port' in k.lower() else ''
        print(f'    {k:<40} {v:>10,}{marker}')

# ── SUMMARY ───────────────────────────────────────────────────
sep('SUMMARY — PortScan coverage')
print(f'  CIC-IDS-2017  : PortScan = {labels_17.get("PortScan", 0):>10,} rows')
ps_lycos = sum(v for k,v in lycos_labels.items() if 'port' in k.lower() or 'scan' in k.lower())
print(f'  LycoS         : PortScan = {ps_lycos:>10,} rows  (label names: {[k for k in lycos_labels if "port" in k.lower() or "scan" in k.lower()]})')
ps_18 = 0  # we already know it's 0 from scan above
print(f'  CICIDS2018    : PortScan = {ps_18:>10,} rows  (not in Thu/Wed files)')
ps_ids25 = sum(v for k,v in ids25_labels.items() if 'port' in k.lower() or 'scan' in k.lower())
print(f'  IDS2025       : PortScan = {ps_ids25:>10,} rows')
print()
print('  UNSW-NB15 uses "Reconnaissance" for scan-type attacks, not a drop-in.')
