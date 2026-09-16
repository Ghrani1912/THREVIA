"""
Feature Distribution Comparison
================================
Pulls mean/std/min/max/median/p95 for key features, separately for:
  A) LycoS BENIGN rows
  B) CIC-2017 Friday BENIGN rows

Uses canonical column names (after rename map) so comparisons are apples-to-apples.
Reads locally — no Spark needed.

Key features checked:
  Flow Duration, Fwd/Bwd Packet Length Mean, Packet Length Mean,
  Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std,
  Idle Mean, Active Mean, Init_Win_bytes_forward

Usage:
    python backend/processing/feature_dist_compare.py
"""

import csv
import math
import os
import sys
import statistics
import collections

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from processing.schema_maps import LYCOS_RENAME

DATA = os.path.join(os.path.dirname(__file__), '..', 'data')

LYCOS_PATH   = os.path.join(DATA, 'LYCSOS', 'LycoS-Unicas-IDS2018.csv')
CIC17_FRIDAY = os.path.join(DATA, 'CIC-IDS- 2017',
                             'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv')
# Friday morning also has BENIGN
CIC17_FRIDAY2 = os.path.join(DATA, 'CIC-IDS- 2017',
                              'Friday-WorkingHours-Morning.pcap_ISCX.csv')

# Key features to compare (canonical names)
KEY_FEATURES = [
    'Flow Duration',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Fwd IAT Mean',
    'Idle Mean',
    'Active Mean',
    'Init_Win_bytes_forward',
    'Total Fwd Packets',
    'Total Backward Packets',
]

MAX_ROWS = 300_000   # cap per source to keep runtime reasonable


def safe_float(v):
    if v is None or v.strip() in ('', 'inf', '-inf', 'Infinity', '-Infinity', 'nan', 'NaN'):
        return None
    try:
        f = float(v)
        return None if (math.isinf(f) or math.isnan(f)) else f
    except (ValueError, TypeError):
        return None


def load_benign_features(path, label_col_raw, rename_map, max_rows, label_match='BENIGN'):
    """Stream CSV, keep BENIGN rows, collect values for KEY_FEATURES."""
    buckets = {f: [] for f in KEY_FEATURES}
    n_read = n_benign = 0

    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        raw_fields = reader.fieldnames

        # Build reverse map: canonical → raw column name in this file
        # For LycoS: raw=lycos_name, canonical=LYCOS_RENAME[lycos_name]
        # For CIC-2017: raw=cic_name (after strip), canonical=cic_name.strip()
        canon_to_raw = {}
        for raw_col in raw_fields:
            stripped = raw_col.strip()
            canonical = rename_map.get(raw_col, rename_map.get(stripped, stripped))
            if canonical in KEY_FEATURES:
                canon_to_raw[canonical] = raw_col

        # Find label column
        label_col = next(
            (c for c in raw_fields if c.strip() in (label_col_raw, label_col_raw.strip())),
            None
        )
        if label_col is None:
            print(f'  WARNING: label column "{label_col_raw}" not found in {os.path.basename(path)}')
            print(f'  Available: {raw_fields[:5]}')
            return buckets, 0

        for row in reader:
            n_read += 1
            if n_benign >= max_rows:
                break
            raw_label = row.get(label_col, '').strip().upper()
            if raw_label != label_match.upper():
                continue
            n_benign += 1
            for canon, raw_c in canon_to_raw.items():
                v = safe_float(row.get(raw_c, ''))
                if v is not None:
                    buckets[canon].append(v)

    return buckets, n_benign


def stats(vals):
    if not vals:
        return dict(n=0, mean=None, std=None, min=None, p25=None,
                    median=None, p75=None, p95=None, max=None)
    s = sorted(vals)
    n = len(s)
    mean = sum(s) / n
    std  = math.sqrt(sum((x - mean)**2 for x in s) / n) if n > 1 else 0.0
    def pct(p):
        idx = (p / 100) * (n - 1)
        lo, hi = int(idx), min(int(idx) + 1, n - 1)
        return s[lo] + (s[hi] - s[lo]) * (idx - lo)
    return dict(n=n, mean=mean, std=std, min=s[0],
                p25=pct(25), median=pct(50), p75=pct(75), p95=pct(95), max=s[-1])


def fmt(v, width=14):
    if v is None:
        return ' ' * width
    if abs(v) >= 1e9:
        return f'{v:>{width}.3e}'
    if abs(v) >= 1e6:
        return f'{v:>{width},.0f}'
    if abs(v) >= 1:
        return f'{v:>{width},.2f}'
    return f'{v:>{width}.4f}'


def ratio_tag(a, b):
    """Return a descriptive tag for the scale difference between two means."""
    if a is None or b is None or a == 0 or b == 0:
        return '?'
    r = max(a, b) / min(a, b)
    if r > 1000:  return f'*** {r:,.0f}x HUGE'
    if r > 100:   return f'**  {r:,.0f}x LARGE'
    if r > 10:    return f'*   {r:,.1f}x moderate'
    return f'    {r:,.1f}x similar'


def sep(title=''):
    print('\n' + '=' * 90)
    if title:
        print(f'  {title}')
        print('=' * 90)


def main():
    sep('THREVIA — Feature Distribution: LycoS-BENIGN vs CIC-2017-Friday-BENIGN')

    # ── LycoS BENIGN ──────────────────────────────────────────────────────────
    print(f'\n[1/2] Loading LycoS BENIGN (cap {MAX_ROWS:,} rows) ...')
    lycos_buckets, lycos_n = load_benign_features(
        LYCOS_PATH, 'label', LYCOS_RENAME, MAX_ROWS, label_match='Benign'
    )
    print(f'  Loaded {lycos_n:,} BENIGN rows from LycoS')
    print(f'  Feature coverage: '
          f'{sum(1 for v in lycos_buckets.values() if v)} / {len(KEY_FEATURES)} features found')

    # ── CIC-2017 Friday BENIGN — combine both Friday files ────────────────────
    print(f'\n[2/2] Loading CIC-2017 Friday BENIGN (cap {MAX_ROWS:,} rows total) ...')
    cic_buckets = {f: [] for f in KEY_FEATURES}
    cic_n = 0

    # CIC-2017 columns are already canonical after stripping — pass empty rename
    cic_rename = {}  # identity map
    for fpath in [CIC17_FRIDAY, CIC17_FRIDAY2]:
        if not os.path.exists(fpath):
            print(f'  Skipping (not found): {os.path.basename(fpath)}')
            continue
        remaining = MAX_ROWS - cic_n
        if remaining <= 0:
            break
        b, n = load_benign_features(
            fpath, ' Label', cic_rename, remaining, label_match='BENIGN'
        )
        for feat in KEY_FEATURES:
            cic_buckets[feat].extend(b.get(feat, []))
        cic_n += n
        print(f'  {os.path.basename(fpath)}: {n:,} BENIGN rows')

    print(f'  Total CIC-2017 Friday BENIGN rows: {cic_n:,}')
    print(f'  Feature coverage: '
          f'{sum(1 for v in cic_buckets.values() if v)} / {len(KEY_FEATURES)} features found')

    # ── Compute stats ─────────────────────────────────────────────────────────
    sep('SUMMARY STATISTICS')
    print(f'  LycoS rows   : {lycos_n:,}   (capped at {MAX_ROWS:,})')
    print(f'  CIC-17 rows  : {cic_n:,}')

    lycos_stats = {f: stats(lycos_buckets[f]) for f in KEY_FEATURES}
    cic_stats   = {f: stats(cic_buckets[f])   for f in KEY_FEATURES}

    col_w = 28
    num_w = 13

    header = (f'  {"Feature":<{col_w}} '
              f'{"Source":>8}  '
              f'{"n":>8}  '
              f'{"mean":>{num_w}}  '
              f'{"std":>{num_w}}  '
              f'{"min":>{num_w}}  '
              f'{"median":>{num_w}}  '
              f'{"p95":>{num_w}}  '
              f'{"max":>{num_w}}  '
              f'Scale diff')
    print()
    print(header)
    print('  ' + '-' * (len(header) + 10))

    smoking_guns = []

    for feat in KEY_FEATURES:
        ls = lycos_stats[feat]
        cs = cic_stats[feat]

        for src, s in [('LycoS', ls), ('CIC-Fri', cs)]:
            line = (f'  {feat:<{col_w}} '
                    f'{src:>8}  '
                    f'{s["n"]:>8,}  '
                    f'{fmt(s["mean"], num_w)}  '
                    f'{fmt(s["std"],  num_w)}  '
                    f'{fmt(s["min"],  num_w)}  '
                    f'{fmt(s["median"], num_w)}  '
                    f'{fmt(s["p95"],  num_w)}  '
                    f'{fmt(s["max"],  num_w)}')
            if src == 'CIC-Fri':
                tag = ratio_tag(ls['mean'], cs['mean'])
                line += f'  {tag}'
                if '***' in tag or '**' in tag:
                    smoking_guns.append((feat, ls['mean'], cs['mean'], tag))
            print(line)
        print()

    # ── Smoking guns summary ──────────────────────────────────────────────────
    sep('SMOKING GUNS (scale difference > 10x between sources)')
    if smoking_guns:
        print(f'\n  {"Feature":<{col_w}}  {"LycoS mean":>{num_w}}  '
              f'{"CIC-Fri mean":>{num_w}}  Tag')
        print('  ' + '-' * 80)
        for feat, lm, cm, tag in smoking_guns:
            print(f'  {feat:<{col_w}}  {fmt(lm, num_w)}  {fmt(cm, num_w)}  {tag}')
    else:
        print('  No extreme scale differences found (all < 10x).')

    # ── Fix recommendation ────────────────────────────────────────────────────
    sep('DIAGNOSIS & FIX')
    if smoking_guns:
        n_huge  = sum(1 for _, _, _, t in smoking_guns if '***' in t)
        n_large = sum(1 for _, _, _, t in smoking_guns if '**' in t and '***' not in t)
        print(f"""
  Found {len(smoking_guns)} features with >10x scale difference:
    {n_huge} features with >1000x difference  (HUGE)
    {n_large} features with >100x difference   (LARGE)

  ROOT CAUSE:
    The StandardScaler was fit ONLY on LycoS training data.
    LycoS and CIC-2017 use different traffic generators and capture
    environments, so the same feature has a very different natural range.
    The scaler normalises LycoS flows correctly but maps CIC-2017 flows
    to extreme values (very large positive or very negative z-scores),
    which the RF then misclassifies.

  FIXES (in order of recommended priority):

  1. ROBUST SCALER (best for mixed-source corpora)
     Replace StandardScaler with RobustScaler (IQR-based).
     RobustScaler is less sensitive to outliers and different-scale sources.
     In PySpark this requires computing per-column Q1/Q3 manually, then
     applying (x - Q1) / (Q3 - Q1) transform.
     --> Add a robust_scaler step to merge_corpus.py

  2. REFIT SCALER ON BOTH SOURCES
     Compute scaler statistics on a representative mix of LycoS + a sample
     of CIC-2017 flows, so z-scores are calibrated to the combined space.
     --> Pass both to Pipeline.fit() in merge_corpus.py

  3. SCALE-INVARIANT FEATURES ONLY
     Keep only ratio/flag/count features that are naturally scale-invariant
     (e.g., Down/Up Ratio, flag counts, subflow counts).
     Drop absolute-magnitude features (Flow Bytes/s, Flow Duration, etc.)
     that are environment-dependent.
     --> Add a feature_selection step to the pipeline

  4. LOG-TRANSFORM BEFORE SCALING
     Log-transform right-skewed magnitude features (Flow Duration,
     Flow Bytes/s, Packet Length Mean) before scaling.
     log1p(x) handles zeros and compresses multi-order-of-magnitude ranges.
     --> Apply F.log1p() to selected cols in merge_corpus.py

  RECOMMENDED IMMEDIATE FIX:
    Apply log1p to skewed features + refit StandardScaler on the combined
    source (LycoS + a 10% sample of CIC-2017 Friday BENIGN).
    This is the lowest-effort fix that addresses the core issue.
        """)
    else:
        print("""
  No extreme scale differences found.
  The domain shift issue is likely due to class distribution mismatch
  rather than feature scaling. Check label normalisation and training
  class weights.
        """)

    sep('DONE')


if __name__ == '__main__':
    main()
