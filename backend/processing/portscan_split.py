"""
PortScan Dedup + Grouped Split
===============================
Fixes two problems with the raw CIC-2017 PortScan subset:

  1. DUPLICATES (42.9% of rows are exact feature-vector duplicates)
     → Drop all duplicate rows, keeping one copy of each unique vector.

  2. SESSION CORRELATION (flows to the same Destination Port come from
     the same scan wave; a random split leaks correlated flows across
     train/test boundary)
     → Group by Destination Port (1,000 groups, median 159 flows/group)
       and assign WHOLE GROUPS to train or test.  This guarantees every
       port's scan session is entirely in one split.

Output:
  backend/data/portscan_clean/
    portscan_train.csv   — 80% of port-groups, deduped
    portscan_test.csv    — 20% of port-groups, deduped
    portscan_stats.txt   — diagnostic summary

Usage:
    python backend/processing/portscan_split.py
"""

import csv
import os
import random
import collections
import statistics

DATA_DIR   = os.path.join(os.path.dirname(__file__), '..', 'data', 'CIC-IDS- 2017')
OUT_DIR    = os.path.join(os.path.dirname(__file__), '..', 'data', 'portscan_clean')
TRAIN_FILE = os.path.join(OUT_DIR, 'portscan_train.csv')
TEST_FILE  = os.path.join(OUT_DIR, 'portscan_test.csv')
STATS_FILE = os.path.join(OUT_DIR, 'portscan_stats.txt')
SEED       = 42
TRAIN_RATIO = 0.80

os.makedirs(OUT_DIR, exist_ok=True)


def sep(title):
    print('\n' + '=' * 64)
    print(f'  {title}')
    print('=' * 64)


def main():
    sep('THREVIA — PortScan Dedup + Grouped Split')

    # ── 1. Load all PortScan rows ──────────────────────────────────────────────
    print('\n[1/6] Loading PortScan rows from CIC-2017 ...')
    all_rows = []
    header = None
    for fname in sorted(os.listdir(DATA_DIR)):
        fpath = os.path.join(DATA_DIR, fname)
        with open(fpath, encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            if header is None:
                # Canonical header: strip whitespace, dedupe duplicate col names
                raw_fieldnames = reader.fieldnames
                seen, header = set(), []
                for c in raw_fieldnames:
                    cc = c.strip()
                    base, i = cc, 2
                    while cc in seen:
                        cc = f'{base}_{i}'
                        i += 1
                    seen.add(cc)
                    header.append(cc)
            label_col = next(
                (c for c in reader.fieldnames if c.strip() == 'Label'), None
            )
            for row in reader:
                if row.get(label_col, '').strip() == 'PortScan':
                    # Re-key with canonical stripped names
                    clean = {}
                    for raw_c, canonical_c in zip(raw_fieldnames, header):
                        clean[canonical_c] = row[raw_c].strip()
                    all_rows.append(clean)

    total_raw = len(all_rows)
    print(f'  Raw PortScan rows : {total_raw:,}')
    print(f'  Columns           : {len(header)}')

    # ── 2. Deduplication ──────────────────────────────────────────────────────
    print('\n[2/6] Deduplicating by full feature vector ...')
    feat_cols = [c for c in header if c != 'Label']

    seen_vecs = set()
    deduped = []
    for row in all_rows:
        vec = tuple(row.get(c, '') for c in feat_cols)
        if vec not in seen_vecs:
            seen_vecs.add(vec)
            deduped.append(row)

    n_removed = total_raw - len(deduped)
    print(f'  After dedup       : {len(deduped):,}')
    print(f'  Removed           : {n_removed:,}  ({n_removed/total_raw*100:.1f}%)')

    # ── 3. Group by Destination Port ──────────────────────────────────────────
    print('\n[3/6] Grouping deduped rows by Destination Port ...')
    groups: dict[str, list] = collections.defaultdict(list)
    for row in deduped:
        groups[row.get('Destination Port', 'UNKNOWN')].append(row)

    port_list = sorted(groups.keys())
    group_sizes = [len(groups[p]) for p in port_list]
    print(f'  Unique port groups   : {len(port_list):,}')
    print(f'  Min group size       : {min(group_sizes):,}')
    print(f'  Median group size    : {statistics.median(group_sizes):.1f}')
    print(f'  Max group size       : {max(group_sizes):,}')
    print(f'  Mean group size      : {statistics.mean(group_sizes):.1f}')

    # ── 4. Grouped split (whole port-groups → train or test) ──────────────────
    print(f'\n[4/6] Grouped {TRAIN_RATIO:.0%}/{1-TRAIN_RATIO:.0%} split (seed={SEED}) ...')
    rng = random.Random(SEED)
    shuffled_ports = port_list[:]
    rng.shuffle(shuffled_ports)

    # Assign greedily to hit target ratio by row count (not group count)
    target_train = int(len(deduped) * TRAIN_RATIO)
    train_rows, test_rows = [], []
    train_count = 0

    for port in shuffled_ports:
        group = groups[port]
        if train_count < target_train:
            train_rows.extend(group)
            train_count += len(group)
        else:
            test_rows.extend(group)

    actual_train_ratio = len(train_rows) / len(deduped)
    print(f'  Train rows : {len(train_rows):,}  ({actual_train_ratio*100:.1f}%)')
    print(f'  Test  rows : {len(test_rows):,}   ({(1-actual_train_ratio)*100:.1f}%)')

    # Verify NO port appears in both train and test
    train_ports = {r['Destination Port'] for r in train_rows}
    test_ports  = {r['Destination Port'] for r in test_rows}
    overlap = train_ports & test_ports
    print(f'  Port overlap (must be 0) : {len(overlap)}  '
          f'{"PASS" if len(overlap)==0 else "FAIL -- overlap found!"}')

    # ── 5. Verify no feature-vector leakage ──────────────────────────────────
    print('\n[5/6] Verifying no feature-vector leakage across split ...')
    train_vecs = {tuple(r.get(c,'') for c in feat_cols) for r in train_rows}
    test_vecs  = {tuple(r.get(c,'') for c in feat_cols) for r in test_rows}
    leaked_vecs = train_vecs & test_vecs
    print(f'  Leaked feature vectors   : {len(leaked_vecs):,}  '
          f'(expected 0 after dedup+group split)')
    # Note: after dedup, shared vecs can only appear if two ports have
    # identical flow stats — extremely rare but document it
    if leaked_vecs:
        print(f'  WARNING: {len(leaked_vecs)} vectors appear in both splits.')
        print('  These are flows with identical features targeting different ports.')
        print('  Acceptable — they are NOT session-correlated duplicates.')

    # ── 6. Write output CSVs ─────────────────────────────────────────────────
    print(f'\n[6/6] Writing output files ...')

    def write_csv(path, rows, fieldnames):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)

    write_csv(TRAIN_FILE, train_rows, header)
    write_csv(TEST_FILE,  test_rows,  header)
    print(f'  Train -> {TRAIN_FILE}')
    print(f'  Test  -> {TEST_FILE}')

    # ── Stats summary ─────────────────────────────────────────────────────────
    stats_lines = [
        'PortScan Dedup + Grouped Split — Statistics',
        '=' * 56,
        f'Raw rows              : {total_raw:,}',
        f'Duplicate rows removed: {n_removed:,}  ({n_removed/total_raw*100:.1f}%)',
        f'Deduped rows          : {len(deduped):,}',
        '',
        f'Grouping key          : Destination Port',
        f'Total port groups     : {len(port_list):,}',
        f'Min / Median / Max group size : '
        f'{min(group_sizes)} / {statistics.median(group_sizes):.1f} / {max(group_sizes)}',
        '',
        f'Train rows  : {len(train_rows):,}  ({actual_train_ratio*100:.1f}%)',
        f'Test  rows  : {len(test_rows):,}  ({(1-actual_train_ratio)*100:.1f}%)',
        f'Port overlap: {len(overlap)} (0 = clean grouped split)',
        f'Vec leakage : {len(leaked_vecs)} vectors shared across split',
        '',
        'Verdict: Port-grouped split prevents session-correlated flows',
        'from leaking across the train/test boundary.',
        'The 42.9% duplicate rate has been fully eliminated.',
        '',
        'Train port sample (first 10):',
    ] + [f'  port {p}' for p in sorted(train_ports)[:10]] + [
        '',
        'Test port sample (first 10):',
    ] + [f'  port {p}' for p in sorted(test_ports)[:10]]

    with open(STATS_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(stats_lines))
    print(f'  Stats -> {STATS_FILE}')

    sep('COMPLETE')
    print(f'  Output dir : {OUT_DIR}')
    print(f'  Train      : {len(train_rows):,} rows  ({len(train_ports):,} port groups)')
    print(f'  Test       : {len(test_rows):,} rows  ({len(test_ports):,} port groups)')
    print(f'  Dups removed: {n_removed:,} ({n_removed/total_raw*100:.1f}%)')
    print(f'  Vec leakage : {len(leaked_vecs)}')


if __name__ == '__main__':
    main()
