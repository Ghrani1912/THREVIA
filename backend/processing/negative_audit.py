"""
Steps 1 + 2 — Negative-Value Audit
=====================================
For each CIC-2017 source subset, counts rows where these three columns
are negative (physically impossible — CICFlowMeter timestamp overflow bug):
  - Flow Duration
  - Flow Bytes/s
  - Flow Packets/s

Subsets audited:
  A) Friday BENIGN rows only  (the ceiling analysis — how many rows does fixing
     the bug potentially recover from the 8% BENIGN recall?)
  B) Friday ALL rows          (full picture)
  C) PortScan training subset (from portscan_clean/portscan_train.csv)
  D) PortScan test subset     (portscan_clean/portscan_test.csv)

Also checks: which other columns have negative values (broader contamination scan).

Usage:
    python backend/processing/negative_audit.py
"""

import csv
import math
import os
import sys

DATA = os.path.join(os.path.dirname(__file__), '..', 'data')

FRIDAY_FILES = [
    os.path.join(DATA, 'CIC-IDS- 2017',
                 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'),
    os.path.join(DATA, 'CIC-IDS- 2017',
                 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'),
    os.path.join(DATA, 'CIC-IDS- 2017',
                 'Friday-WorkingHours-Morning.pcap_ISCX.csv'),
]

PORTSCAN_TRAIN = os.path.join(DATA, 'portscan_clean', 'portscan_train.csv')
PORTSCAN_TEST  = os.path.join(DATA, 'portscan_clean', 'portscan_test.csv')

# CIC-2017 canonical column names (after strip) for the three key bug features
BUG_COLS = ['Flow Duration', 'Flow Bytes/s', 'Flow Packets/s']

# Columns where negative values are used as a sentinel (-1 = no TCP window)
SENTINEL_COLS = {'Init_Win_bytes_forward', 'Init_Win_bytes_backward'}

# Rate features that depend on duration (need recomputation after duration fix)
RATE_COLS = ['Flow Bytes/s', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s']

# Raw count columns available to recompute rates
BYTE_COLS  = ['Total Length of Fwd Packets', 'Total Length of Bwd Packets']
PKT_COLS   = ['Total Fwd Packets', 'Total Backward Packets']


def safe_float(v):
    if not v or v.strip() in ('', 'nan', 'NaN', 'inf', '-inf', 'Infinity', '-Infinity'):
        return None
    try:
        f = float(v)
        return None if (math.isnan(f) or math.isinf(f)) else f
    except ValueError:
        return None


def audit_file(path, label_filter=None):
    """
    Scan a CSV file. Return a dict with:
      total_rows, label_counts,
      neg_counts: {col: count_negative},
      neg_benign: {col: count_negative_in_BENIGN},
      any_neg_rows: rows where ANY bug col is negative,
      all_neg_rows: rows where ALL bug cols are negative,
      col_neg_scan: {col: count} for all numeric cols (broader scan),
      recomputable: count of rows where duration negative but byte/pkt counts ok
    """
    if not os.path.exists(path):
        print(f'  MISSING: {path}')
        return None

    total = 0
    label_counts   = {}
    neg_counts     = {c: 0 for c in BUG_COLS}
    neg_benign     = {c: 0 for c in BUG_COLS}
    any_neg        = 0
    all_neg        = 0
    recomputable   = 0
    col_neg_scan   = {}   # broader scan over all numeric cols

    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        # Normalise field names (strip whitespace)
        raw_fields = reader.fieldnames
        norm_map   = {c: c.strip() for c in raw_fields}   # raw → stripped

        # Check which bug cols are present
        stripped_fields = [c.strip() for c in raw_fields]
        present_bug = {c for c in BUG_COLS if c in stripped_fields}
        present_byte = {c for c in BYTE_COLS if c in stripped_fields}
        present_pkt  = {c for c in PKT_COLS  if c in stripped_fields}

        # Initialise broader scan (all numeric cols except sentinel)
        for c in stripped_fields:
            if c not in SENTINEL_COLS:
                col_neg_scan[c] = 0

        for row in reader:
            # Re-key with stripped names
            r = {norm_map[k]: v for k, v in row.items()}
            total += 1

            label = r.get('Label', '').strip().upper()
            label_counts[label] = label_counts.get(label, 0) + 1
            is_benign = (label == 'BENIGN')

            if label_filter and label != label_filter.upper():
                continue

            # Check bug columns
            bug_vals = {}
            for c in present_bug:
                v = safe_float(r.get(c, ''))
                bug_vals[c] = v

            row_any_neg = any(v is not None and v < 0
                              for v in bug_vals.values())
            row_all_neg = (len(bug_vals) == len(present_bug) and
                           all(v is not None and v < 0
                               for v in bug_vals.values()))

            for c, v in bug_vals.items():
                if v is not None and v < 0:
                    neg_counts[c] += 1
                    if is_benign:
                        neg_benign[c] += 1

            if row_any_neg:
                any_neg += 1
            if row_all_neg:
                all_neg += 1

            # Check recomputability: if duration negative but byte/pkt counts
            # are non-negative and total pkt count > 0
            dur_val = safe_float(r.get('Flow Duration', ''))
            if dur_val is not None and dur_val < 0:
                bytes_ok = all(
                    safe_float(r.get(c, '')) is not None and
                    safe_float(r.get(c, '')) >= 0
                    for c in present_byte
                )
                pkts_ok = all(
                    safe_float(r.get(c, '')) is not None and
                    safe_float(r.get(c, '')) > 0
                    for c in present_pkt
                )
                if bytes_ok and pkts_ok:
                    recomputable += 1

            # Broader scan
            for c in col_neg_scan:
                if c in SENTINEL_COLS:
                    continue
                v = safe_float(r.get(c, ''))
                if v is not None and v < 0:
                    col_neg_scan[c] += 1

    # Only report cols with at least 1 negative in broader scan
    col_neg_scan = {c: n for c, n in col_neg_scan.items() if n > 0}

    return dict(
        total=total,
        label_counts=label_counts,
        neg_counts=neg_counts,
        neg_benign=neg_benign,
        any_neg=any_neg,
        all_neg=all_neg,
        recomputable=recomputable,
        col_neg_scan=col_neg_scan,
        present_bug=present_bug,
    )


def sep(title=''):
    print('\n' + '=' * 72)
    if title:
        print(f'  {title}')
        print('=' * 72)


def report(name, res, show_col_scan=True):
    if res is None:
        return
    t = res['total']
    lc = res['label_counts']
    benign_n = lc.get('BENIGN', 0)
    print(f'\n  Total rows    : {t:,}')
    print(f'  Label counts  : '
          + ', '.join(f'{k}={v:,}' for k, v in sorted(lc.items(), key=lambda x: -x[1])[:8]))

    print(f'\n  {"Column":<25} {"neg total":>10}  {"neg BENIGN":>12}  '
          f'{"% of total":>10}  {"% of BENIGN":>12}')
    print('  ' + '-' * 72)
    for c in BUG_COLS:
        n_tot  = res['neg_counts'].get(c, 0)
        n_ben  = res['neg_benign'].get(c, 0)
        pct_t  = n_tot / t * 100  if t else 0
        pct_b  = n_ben / benign_n * 100 if benign_n else 0
        flag   = '  <<< BUG' if n_tot > 0 else ''
        print(f'  {c:<25} {n_tot:>10,}  {n_ben:>12,}  '
              f'{pct_t:>9.2f}%  {pct_b:>11.2f}%{flag}')

    print(f'\n  Rows with ANY  bug-col negative : {res["any_neg"]:,}  '
          f'({res["any_neg"]/t*100:.2f}% of all rows)')
    print(f'  Rows with ALL  bug-col negative : {res["all_neg"]:,}  '
          f'({res["all_neg"]/t*100:.2f}% of all rows)')
    if res['recomputable']:
        print(f'  Duration-neg but recomputable   : {res["recomputable"]:,}  '
              f'(byte+pkt counts OK)')

    if show_col_scan and res['col_neg_scan']:
        print(f'\n  All columns with any negatives ({len(res["col_neg_scan"])} cols):')
        for c, n in sorted(res['col_neg_scan'].items(), key=lambda x: -x[1])[:20]:
            print(f'    {c:<40} {n:>10,}  ({n/t*100:.2f}%)')


def main():
    sep('CIC-2017 Negative-Value Audit — Steps 1 + 2')

    # ── A) Friday ALL rows ────────────────────────────────────────────────────
    sep('A. CIC-2017 Friday — ALL rows (3 files combined)')
    friday_combined = {c: 0 for c in BUG_COLS}
    friday_benign   = {c: 0 for c in BUG_COLS}
    friday_any = friday_all = friday_total = friday_recomp = 0
    friday_labels = {}
    friday_col_neg = {}

    for fpath in FRIDAY_FILES:
        fn = os.path.basename(fpath)
        print(f'\n  Scanning {fn} ...')
        res = audit_file(fpath)
        if res is None:
            continue
        friday_total += res['total']
        friday_any   += res['any_neg']
        friday_all   += res['all_neg']
        friday_recomp+= res['recomputable']
        for c in BUG_COLS:
            friday_combined[c] += res['neg_counts'].get(c, 0)
            friday_benign[c]   += res['neg_benign'].get(c, 0)
        for k, v in res['label_counts'].items():
            friday_labels[k] = friday_labels.get(k, 0) + v
        for c, n in res['col_neg_scan'].items():
            friday_col_neg[c] = friday_col_neg.get(c, 0) + n

    benign_friday = friday_labels.get('BENIGN', 0)
    print(f'\n  === Friday combined summary ===')
    print(f'  Total rows    : {friday_total:,}')
    print(f'  BENIGN rows   : {benign_friday:,}')
    print(f'\n  {"Column":<25} {"neg total":>10}  {"neg BENIGN":>12}  '
          f'{"% total":>8}  {"% BENIGN":>10}  {"BENIGN recall ceiling":>22}')
    print('  ' + '-' * 95)
    for c in BUG_COLS:
        n_t = friday_combined[c]
        n_b = friday_benign[c]
        pt  = n_t / friday_total   * 100 if friday_total   else 0
        pb  = n_b / benign_friday  * 100 if benign_friday  else 0
        # Ceiling: if we fix these rows, BENIGN recall could recover by this %
        ceiling = n_b / benign_friday * 100 if benign_friday else 0
        print(f'  {c:<25} {n_t:>10,}  {n_b:>12,}  '
              f'{pt:>7.2f}%  {pb:>9.2f}%  {ceiling:>21.2f}%')

    print(f'\n  Rows with ANY  bug-col negative : {friday_any:,}  '
          f'({friday_any/friday_total*100:.2f}%)')
    print(f'  Rows with ALL  bug-col negative : {friday_all:,}  '
          f'({friday_all/friday_total*100:.2f}%)')
    print(f'  Duration-neg but recomputable   : {friday_recomp:,}')

    print(f'\n  All cols with negatives across Friday:')
    for c, n in sorted(friday_col_neg.items(), key=lambda x: -x[1])[:20]:
        print(f'    {c:<40} {n:>8,}  ({n/friday_total*100:.2f}%)')

    # ── B) PortScan training subset ───────────────────────────────────────────
    sep('B. PortScan Training Subset (portscan_clean/portscan_train.csv)')
    ps_train_res = audit_file(PORTSCAN_TRAIN)
    if ps_train_res:
        report('PortScan Train', ps_train_res)

    # ── C) PortScan test subset ───────────────────────────────────────────────
    sep('C. PortScan Test Subset (portscan_clean/portscan_test.csv)')
    ps_test_res = audit_file(PORTSCAN_TEST)
    if ps_test_res:
        report('PortScan Test', ps_test_res)

    # ── Summary verdict ───────────────────────────────────────────────────────
    sep('VERDICT')
    benign_recall_current = 0.0801   # from eval_clean_corpus.py output
    if benign_friday:
        max_recovery = friday_benign.get('Flow Duration', 0) / benign_friday
        combined_neg = max(
            friday_benign.get(c, 0) for c in BUG_COLS
        )
        ceiling_pct = combined_neg / benign_friday * 100

        ps_train_any = ps_train_res['any_neg'] if ps_train_res else 0
        ps_train_tot = ps_train_res['total']   if ps_train_res else 1

        print(f"""
  Friday BENIGN recall (current model) : {benign_recall_current:.1%}
  Friday BENIGN rows total             : {benign_friday:,}
  Friday BENIGN rows with any neg bug  : {combined_neg:,}  ({ceiling_pct:.1f}%)

  CEILING: fixing the bug can recover AT MOST {ceiling_pct:.1f}% of BENIGN rows
  from being corrupted inputs.  Whether that translates directly to recall
  improvement depends on whether those rows are currently misclassified.

  PortScan training contamination:
    Rows with any negative bug col : {ps_train_any:,} / {ps_train_tot:,}
    ({ps_train_any/ps_train_tot*100:.2f}%)
  {'*** CONTAMINATED — must clean before trusting PortScan 100% result' if ps_train_any > 0 else 'Clean — no negative bug values in PortScan training subset'}
        """)

    sep('DONE')


if __name__ == '__main__':
    main()
