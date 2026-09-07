"""
Zero-Variance Diagnostic — CICIDS2018 Infiltration rows
Runs on both Thursday and Wednesday files.

For each file:
  1. Isolate Infiltration rows only
  2. Apply CIC18_RENAME to get canonical column names
  3. Compute stddev of every numeric feature within the Infiltration subset
  4. Report features with stddev == 0.0 (deterministic signatures)
  5. Cross-check: compare the same features in CIC-2017 Infiltration rows
     to see if the zero-variance signature is shared (same bug) or independent

Verdict per file:
  CLEAN   — fewer zero-variance features than CIC-2017 Infiltration (<= threshold)
  SUSPECT — same or more zero-variance features; likely same session-correlation bug

Usage:
    python backend/processing/zerovar_diagnostic.py
"""

import csv
import math
import os
import sys
import collections

# Add backend root to path so we can import schema_maps
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from processing.schema_maps import CIC18_RENAME, CIC18_EXTRA_DROP

DATA = os.path.join(os.path.dirname(__file__), '..', 'data')

CIC17_DIR   = os.path.join(DATA, 'CIC-IDS- 2017')
CIC18_DIR   = os.path.join(DATA, 'CICIDS2018')

# ── helpers ───────────────────────────────────────────────────────────────────

def load_infiltration_rows(filepath, label_col, rename_map, drop_cols,
                            valid_labels=None):
    """
    Read a CSV, apply rename_map, return only rows whose label (after
    normalisation) matches valid_labels (default: any Infiltration variant).
    Returns list of dicts with canonical column names.
    """
    if valid_labels is None:
        valid_labels = {'infiltration', 'infilteration'}

    rows = []
    with open(filepath, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        # Build a per-file rename mapping (raw col → canonical)
        # Only rename cols that exist in this file
        active_rename = {k: v for k, v in rename_map.items()
                         if k in reader.fieldnames}
        for row in reader:
            raw_label = row.get(label_col, '').strip()
            if raw_label.lower() in valid_labels:
                renamed = {}
                for col, val in row.items():
                    if col in drop_cols:
                        continue
                    new_col = active_rename.get(col, col)
                    renamed[new_col] = val
                rows.append(renamed)
    return rows


def compute_stats(rows, feature_cols):
    """
    Returns dict: col -> {'mean': float, 'std': float, 'n_valid': int,
                          'n_null': int, 'pct_zero': float}
    """
    stats = {}
    for col in feature_cols:
        vals = []
        n_null = 0
        for row in rows:
            v = row.get(col, '').strip()
            if v in ('', 'inf', '-inf', 'Infinity', '-Infinity', 'NaN', 'nan'):
                n_null += 1
                continue
            try:
                fv = float(v)
                if not (math.isinf(fv) or math.isnan(fv)):
                    vals.append(fv)
                else:
                    n_null += 1
            except ValueError:
                n_null += 1

        if len(vals) < 2:
            stats[col] = {'mean': None, 'std': None,
                          'n_valid': len(vals), 'n_null': n_null,
                          'pct_zero': None}
            continue

        mean = sum(vals) / len(vals)
        variance = sum((x - mean) ** 2 for x in vals) / len(vals)
        std = math.sqrt(variance)
        n_zero = sum(1 for v in vals if v == 0.0)
        pct_zero = n_zero / len(vals) * 100
        stats[col] = {
            'mean': mean, 'std': std,
            'n_valid': len(vals), 'n_null': n_null,
            'pct_zero': pct_zero,
        }
    return stats


def zero_variance_features(stats, threshold=1e-9):
    """Return sorted list of (col, std) where std <= threshold."""
    result = []
    for col, s in stats.items():
        if s['std'] is not None and s['std'] <= threshold:
            result.append((col, s['std'], s['mean'], s['pct_zero']))
    return sorted(result, key=lambda x: x[0])


def sep(title):
    print('\n' + '=' * 68)
    print(f'  {title}')
    print('=' * 68)


def print_zero_var(zv_list, label=''):
    if not zv_list:
        print(f'  {label}: NO zero-variance features ✅')
        return
    print(f'  {label}: {len(zv_list)} zero-variance features')
    print(f'  {"Feature":<40} {"Std":>12} {"Mean":>14} {"PctZero":>8}')
    print('  ' + '-' * 76)
    for col, std, mean, pct in zv_list:
        mean_s = f'{mean:.4f}' if mean is not None else 'N/A'
        pct_s  = f'{pct:.1f}%' if pct is not None else 'N/A'
        print(f'  {col:<40} {std:>12.6f} {mean_s:>14} {pct_s:>8}')


# ── get canonical feature cols from a CIC18 file after rename ─────────────────

def get_feature_cols_from_file(filepath, rename_map, drop_cols):
    with open(filepath, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        cols = []
        for col in reader.fieldnames:
            if col in drop_cols:
                continue
            canonical = rename_map.get(col, col)
            if canonical.lower() not in ('label',):
                cols.append(canonical)
    return cols


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    sep('THREVIA — Zero-Variance Diagnostic: CICIDS2018 Infiltration')

    # ── Step 0: Build reference from CIC-2017 Infiltration ────────────────────
    sep('0. Reference: CIC-2017 Infiltration (known-bad baseline)')

    cic17_infil = []
    cic17_feature_cols = None
    for fname in sorted(os.listdir(CIC17_DIR)):
        fpath = os.path.join(CIC17_DIR, fname)
        with open(fpath, encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            if cic17_feature_cols is None:
                cic17_feature_cols = [
                    c.strip() for c in reader.fieldnames
                    if c.strip().lower() not in ('label', '')
                ]
            label_col = next(
                (c for c in reader.fieldnames if c.strip() == 'Label'), None
            )
            for row in reader:
                if row.get(label_col, '').strip().lower() in \
                        ('infiltration', 'infilteration'):
                    renamed = {k.strip(): v for k, v in row.items()}
                    cic17_infil.append(renamed)

    print(f'  CIC-2017 Infiltration rows: {len(cic17_infil):,}')
    cic17_stats = compute_stats(cic17_infil, cic17_feature_cols)
    cic17_zv    = zero_variance_features(cic17_stats)
    print_zero_var(cic17_zv, 'CIC-2017 Infiltration')
    cic17_zv_cols = {col for col, *_ in cic17_zv}

    # ── Step 1: CICIDS2018 Thursday ────────────────────────────────────────────
    sep('1. CICIDS2018 Thursday')
    thu_path    = os.path.join(CIC18_DIR, 'CICIDS2018_Thursday.csv')
    thu_fcols   = get_feature_cols_from_file(thu_path, CIC18_RENAME, CIC18_EXTRA_DROP)
    thu_infil   = load_infiltration_rows(thu_path, 'Label', CIC18_RENAME, CIC18_EXTRA_DROP)
    print(f'  Infiltration rows: {len(thu_infil):,}')

    # duplicate check within Thursday
    thu_vectors = [tuple(row.get(c, '') for c in thu_fcols) for row in thu_infil]
    thu_dup_pct = (len(thu_vectors) - len(set(thu_vectors))) / max(len(thu_vectors), 1) * 100
    print(f'  Duplicate rows (exact feature match): {(len(thu_vectors)-len(set(thu_vectors))):,}  ({thu_dup_pct:.1f}%)')

    thu_stats   = compute_stats(thu_infil, thu_fcols)
    thu_zv      = zero_variance_features(thu_stats)
    print_zero_var(thu_zv, 'CICIDS2018-Thursday Infiltration')
    thu_zv_cols = {col for col, *_ in thu_zv}

    # Overlap with CIC-2017 zero-var cols
    shared_thu = thu_zv_cols & cic17_zv_cols
    new_thu    = thu_zv_cols - cic17_zv_cols
    print(f'\n  Shared with CIC-2017 zero-var set : {len(shared_thu)} cols')
    print(f'  New zero-var (not in CIC-2017)    : {len(new_thu)} cols  -> {sorted(new_thu)}')

    # ── Step 2: CICIDS2018 Wednesday ───────────────────────────────────────────
    sep('2. CICIDS2018 Wednesday')
    wed_path    = os.path.join(CIC18_DIR, 'CICIDS2018_Wednesday.csv')
    wed_fcols   = get_feature_cols_from_file(wed_path, CIC18_RENAME, CIC18_EXTRA_DROP)
    wed_infil   = load_infiltration_rows(wed_path, 'Label', CIC18_RENAME, CIC18_EXTRA_DROP)
    print(f'  Infiltration rows: {len(wed_infil):,}')

    wed_vectors = [tuple(row.get(c, '') for c in wed_fcols) for row in wed_infil]
    wed_dup_pct = (len(wed_vectors) - len(set(wed_vectors))) / max(len(wed_vectors), 1) * 100
    print(f'  Duplicate rows (exact feature match): {(len(wed_vectors)-len(set(wed_vectors))):,}  ({wed_dup_pct:.1f}%)')

    wed_stats   = compute_stats(wed_infil, wed_fcols)
    wed_zv      = zero_variance_features(wed_stats)
    print_zero_var(wed_zv, 'CICIDS2018-Wednesday Infiltration')
    wed_zv_cols = {col for col, *_ in wed_zv}

    shared_wed = wed_zv_cols & cic17_zv_cols
    new_wed    = wed_zv_cols - cic17_zv_cols
    print(f'\n  Shared with CIC-2017 zero-var set : {len(shared_wed)} cols')
    print(f'  New zero-var (not in CIC-2017)    : {len(new_wed)} cols  -> {sorted(new_wed)}')

    # ── Step 3: Feature value overlap — do CIC18 infil rows share exact values ─
    sep('3. Feature-value overlap: CIC-2017 vs CIC-2018 Infiltration')
    print('  Checking whether zero-var features have the SAME constant value\n'
          '  in both datasets (same constant = same collection artifact):\n')

    all_zv_shared = (thu_zv_cols | wed_zv_cols) & cic17_zv_cols
    print(f'  {"Feature":<40} {"CIC17 mean":>12} {"CIC18-Thu mean":>14} {"CIC18-Wed mean":>14} {"Same?":>6}')
    print('  ' + '-' * 90)
    for col in sorted(all_zv_shared):
        m17 = cic17_stats.get(col, {}).get('mean')
        m_thu = thu_stats.get(col, {}).get('mean')
        m_wed = wed_stats.get(col, {}).get('mean')
        same = (
            m17 is not None and
            (m_thu is None or abs(m_thu - m17) < 1e-6) and
            (m_wed is None or abs(m_wed - m17) < 1e-6)
        )
        m17_s   = f'{m17:.4f}'  if m17  is not None else 'N/A'
        m_thu_s = f'{m_thu:.4f}' if m_thu is not None else 'N/A'
        m_wed_s = f'{m_wed:.4f}' if m_wed is not None else 'N/A'
        print(f'  {col:<40} {m17_s:>12} {m_thu_s:>14} {m_wed_s:>14} {"YES" if same else "NO":>6}')

    # ── Step 4: Verdict ────────────────────────────────────────────────────────
    sep('VERDICT')

    def verdict(name, zv_count, shared_count, dup_pct):
        print(f'\n  [{name}]')
        print(f'    Zero-variance features   : {zv_count}')
        print(f'    Shared with CIC-2017 bug : {shared_count}')
        print(f'    Duplicate row rate       : {dup_pct:.1f}%')
        if zv_count == 0:
            result = 'CLEAN -- no zero-variance signatures; safe to include'
        elif shared_count == zv_count and dup_pct < 20.0:
            result = ('CAUTIOUSLY USABLE -- zero-var cols are same as CIC-2017 '
                      '(shared tool artifact, not new session corruption); '
                      'low duplication; include with documentation')
        elif dup_pct > 30.0:
            result = ('SUSPECT -- high duplicate rate suggests heavy session '
                      'correlation; EXCLUDE from training')
        else:
            result = ('MARGINAL -- some new zero-var cols beyond CIC-2017 baseline; '
                      'include only if no better Infiltration source exists')
        print(f'    Result: {result}')

    verdict('CICIDS2018 Thursday', len(thu_zv), len(shared_thu), thu_dup_pct)
    verdict('CICIDS2018 Wednesday', len(wed_zv), len(shared_wed), wed_dup_pct)

    print('\n' + '=' * 68)
    print('  DIAGNOSTIC COMPLETE')
    print('=' * 68)


if __name__ == '__main__':
    main()
