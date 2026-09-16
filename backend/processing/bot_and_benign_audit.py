"""
Steps 1+2+3a — Bot investigation + CIC-2017 BENIGN negative-value audit
=========================================================================

PART A — Bot label verification
  Scans exact label strings for "Bot" rows in:
    - LycoS-IDS2018
    - CIC-2017 Friday Morning (source of Bot in Friday test set)
    - CIC-2017 all files (full picture)
  Rules out silent normalisation mismatch before spending effort on fix.

PART B — Bot feature distribution comparison
  LycoS-Bot vs CIC-2017-Friday-Bot, same method as feature_dist_compare.py.
  Key features: Flow Duration, Fwd/Bwd Packet Length Mean, Flow Bytes/s,
  Flow Packets/s, Flow IAT Mean, SYN/FIN/RST flag counts, Total Fwd/Bwd Packets.
  If distributions are wildly different => signature mismatch (same story as DDoS).

PART C — CIC-2017 BENIGN negative-value audit
  Same check as negative_audit.py but restricted to BENIGN rows across ALL
  CIC-2017 files (not just Friday). Reports:
    - How many BENIGN rows have negative Flow Duration / Bytes/s / Packets/s
    - Duplicate rate in BENIGN rows (needed for Step 3b planning)
    - Distribution of Destination Port (for grouped-split key planning)

Usage:
    python backend/processing/bot_and_benign_audit.py
"""

import csv
import math
import os
import sys
import statistics
import collections

DATA = os.path.join(os.path.dirname(__file__), '..', 'data')
CIC17_DIR   = os.path.join(DATA, 'CIC-IDS- 2017')
LYCOS_PATH  = os.path.join(DATA, 'LYCSOS', 'LycoS-Unicas-IDS2018.csv')

# CIC-2017 Friday files (where Bot rows come from in the test set)
FRIDAY_FILES = [
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',        # Botnet ARES
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

KEY_FEATURES = [
    'Flow Duration',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Packet Length Mean',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Total Fwd Packets',
    'Total Backward Packets',
    'SYN Flag Count',
    'FIN Flag Count',
    'RST Flag Count',
    'ACK Flag Count',
    'Init_Win_bytes_forward',
    'Fwd Avg Bytes/Bulk',
]

BUG_COLS = ['Flow Duration', 'Flow Bytes/s', 'Flow Packets/s']
MAX_BOT  = 100_000   # cap for Bot feature scan (LycoS has 96k rows)
MAX_BENIGN = 500_000  # cap for BENIGN scan per audit

# ── helpers ───────────────────────────────────────────────────────────────────

def safe_float(v):
    if not v or v.strip() in ('', 'nan', 'NaN', 'inf', '-inf', 'Infinity', '-Infinity'):
        return None
    try:
        f = float(v)
        return None if (math.isnan(f) or math.isinf(f)) else f
    except ValueError:
        return None


def get_label_col(fieldnames):
    return next((c for c in fieldnames if c.strip() == 'Label'), None)


def sep(title=''):
    print('\n' + '=' * 72)
    if title:
        print(f'  {title}')
        print('=' * 72)


def stats(vals):
    if not vals:
        return dict(n=0, mean=None, std=None, min=None, median=None, p95=None, max=None)
    s = sorted(vals)
    n = len(s)
    mean = sum(s) / n
    std  = math.sqrt(sum((x - mean) ** 2 for x in s) / n) if n > 1 else 0.0
    def pct(p):
        idx = (p / 100) * (n - 1)
        lo, hi = int(idx), min(int(idx) + 1, n - 1)
        return s[lo] + (s[hi] - s[lo]) * (idx - lo)
    return dict(n=n, mean=mean, std=std, min=s[0],
                median=pct(50), p95=pct(95), max=s[-1])


def fmt(v, w=13):
    if v is None:
        return ' ' * w
    if abs(v) >= 1e9: return f'{v:>{w}.3e}'
    if abs(v) >= 1e6: return f'{v:>{w},.0f}'
    if abs(v) >= 1:   return f'{v:>{w},.2f}'
    return f'{v:>{w}.4f}'


def ratio_tag(a, b):
    if a is None or b is None or a == 0 or b == 0: return '?'
    r = max(abs(a), abs(b)) / max(min(abs(a), abs(b)), 1e-9)
    if r > 1000: return f'*** {r:,.0f}x HUGE'
    if r > 100:  return f'**  {r:,.0f}x LARGE'
    if r > 10:   return f'*   {r:,.1f}x moderate'
    return f'    {r:,.1f}x similar'


# ═══════════════════════════════════════════════════════════════════════════════
# PART A — Bot label verification
# ═══════════════════════════════════════════════════════════════════════════════

def part_a():
    sep('PART A — Bot Label Verification')

    # LycoS
    print('\n  LycoS-IDS2018 Bot labels:')
    lycos_bot_labels = collections.Counter()
    with open(LYCOS_PATH, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw = row.get('label', '').strip()
            if 'bot' in raw.lower():
                lycos_bot_labels[repr(raw)] += 1
    print(f'    {dict(lycos_bot_labels)}')

    # CIC-2017 all files
    print('\n  CIC-2017 all files Bot labels:')
    cic17_bot_labels = collections.Counter()
    cic17_all_labels = collections.Counter()
    for fname in sorted(os.listdir(CIC17_DIR)):
        fpath = os.path.join(CIC17_DIR, fname)
        with open(fpath, encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            lc = get_label_col(reader.fieldnames)
            if not lc:
                continue
            for row in reader:
                raw = row.get(lc, '').strip()
                cic17_all_labels[raw] += 1
                if 'bot' in raw.lower():
                    cic17_bot_labels[repr(raw)] += 1

    print(f'    Bot labels     : {dict(cic17_bot_labels)}')
    print(f'    All CIC labels : {dict(sorted(cic17_all_labels.items(), key=lambda x:-x[1]))}')

    # After LABEL_NORMALISE: "Bot" -> "Bot" for both sources
    from processing.schema_maps import LABEL_NORMALISE, normalise_label
    lycos_normalised = set(
        normalise_label(k.strip("'")) for k in lycos_bot_labels
    )
    cic17_normalised = set(
        normalise_label(k.strip("'")) for k in cic17_bot_labels
    )
    print(f'\n  After normalise_label():')
    print(f'    LycoS  -> {lycos_normalised}')
    print(f'    CIC-17 -> {cic17_normalised}')
    match = lycos_normalised == cic17_normalised == {'Bot'}
    print(f'\n  Labels match exactly: {"YES — no silent bug" if match else "NO — MISMATCH, check normalisation"}')
    return match


# ═══════════════════════════════════════════════════════════════════════════════
# PART B — Bot feature distribution comparison
# ═══════════════════════════════════════════════════════════════════════════════

def load_rows(path, label_match, rename_map, max_rows,
              label_col_raw='Label', strip_label=True):
    """Stream CSV, return list of {canonical_col: value} for matching rows."""
    rows = []
    with open(path, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        raw_fields = reader.fieldnames
        norm_map   = {c: c.strip() for c in raw_fields}
        lc = next(
            (c for c in raw_fields
             if c.strip() == label_col_raw.strip()),
            None
        )
        if lc is None:
            return rows

        # Build canonical → raw mapping
        canon_to_raw = {}
        for raw_c in raw_fields:
            stripped = raw_c.strip()
            canon = rename_map.get(raw_c, rename_map.get(stripped, stripped))
            if canon in KEY_FEATURES:
                canon_to_raw[canon] = raw_c

        for row in reader:
            if len(rows) >= max_rows:
                break
            raw_label = row.get(lc, '').strip()
            if strip_label:
                raw_label = raw_label.upper()
                target    = label_match.upper()
            else:
                target = label_match
            if raw_label != target:
                continue
            renamed = {}
            for canon, raw_c in canon_to_raw.items():
                v = safe_float(row.get(raw_c, ''))
                renamed[canon] = v
            rows.append(renamed)
    return rows


def part_b():
    sep('PART B — Bot Feature Distribution: LycoS vs CIC-2017-Friday')

    from processing.schema_maps import LYCOS_RENAME

    # LycoS Bot rows
    print(f'\n  Loading LycoS Bot rows (cap {MAX_BOT:,}) ...')
    lycos_bot = load_rows(LYCOS_PATH, 'Bot', LYCOS_RENAME,
                          MAX_BOT, label_col_raw='label', strip_label=True)
    print(f'  Loaded {len(lycos_bot):,} LycoS Bot rows')

    # CIC-2017 Friday Bot rows (mainly Friday Morning — Botnet ARES)
    print(f'\n  Loading CIC-2017 Friday Bot rows ...')
    cic_bot = []
    for fname in FRIDAY_FILES:
        fpath = os.path.join(CIC17_DIR, fname)
        if not os.path.exists(fpath):
            continue
        rows = load_rows(fpath, 'Bot', {}, MAX_BOT,
                         label_col_raw=' Label', strip_label=True)
        cic_bot.extend(rows)
        if rows:
            print(f'    {fname}: {len(rows):,} Bot rows')
    print(f'  Total CIC-2017 Friday Bot rows: {len(cic_bot):,}')

    if not lycos_bot or not cic_bot:
        print('  SKIPPING comparison — one or both sources have 0 Bot rows')
        return

    # Compute stats per feature
    col_w, num_w = 28, 12
    header = (f'  {"Feature":<{col_w}} {"Source":>9}  '
              f'{"n":>7}  {"mean":>{num_w}}  {"std":>{num_w}}  '
              f'{"min":>{num_w}}  {"median":>{num_w}}  '
              f'{"p95":>{num_w}}  {"max":>{num_w}}  Scale diff')
    print()
    print(header)
    print('  ' + '-' * (len(header) + 5))

    smoking_guns = []
    for feat in KEY_FEATURES:
        lycos_vals = [r[feat] for r in lycos_bot if r.get(feat) is not None]
        cic_vals   = [r[feat] for r in cic_bot   if r.get(feat) is not None]

        ls = stats(lycos_vals)
        cs = stats(cic_vals)

        for src, s in [('LycoS', ls), ('CIC-Fri', cs)]:
            line = (f'  {feat:<{col_w}} {src:>9}  '
                    f'{s["n"]:>7,}  {fmt(s["mean"], num_w)}  '
                    f'{fmt(s["std"],  num_w)}  {fmt(s["min"],  num_w)}  '
                    f'{fmt(s["median"], num_w)}  {fmt(s["p95"],  num_w)}  '
                    f'{fmt(s["max"],  num_w)}')
            if src == 'CIC-Fri':
                tag = ratio_tag(ls['mean'], cs['mean'])
                line += f'  {tag}'
                if any(x in tag for x in ('***', '**', '*')):
                    smoking_guns.append((feat, ls['mean'], cs['mean'], tag))
            print(line)
        print()

    sep('Bot smoking guns')
    if smoking_guns:
        print(f'\n  Features with >10x scale difference (Bot):')
        for feat, lm, cm, tag in smoking_guns:
            print(f'    {feat:<30}  LycoS={fmt(lm,12)}  CIC={fmt(cm,12)}  {tag}')
    else:
        print('  No >10x differences found.')

    print(f'\n  INTERPRETATION:')
    if len(smoking_guns) >= 3:
        print('  Large-scale Bot feature differences confirm SIGNATURE MISMATCH:')
        print('  LycoS Bot (re-extracted) and CIC-2017 Botnet ARES have structurally')
        print('  different traffic patterns. This is the same category as DDoS.')
        print('  Adding CIC-2017 BENIGN to training will NOT fix Bot recall —')
        print('  Bot recall requires Bot training examples from the same environment.')
    else:
        print('  Bot distributions are similar — low-signal structural similarity.')
        print('  Zero Bot recall is more likely a class-size or threshold issue.')


# ═══════════════════════════════════════════════════════════════════════════════
# PART C — CIC-2017 BENIGN negative-value audit + dedup + port distribution
# ═══════════════════════════════════════════════════════════════════════════════

def part_c():
    sep('PART C — CIC-2017 BENIGN Audit (all files): negatives + dups + ports')

    total_benign = 0
    neg_counts   = {c: 0 for c in BUG_COLS}
    any_neg      = 0
    dup_vecs     = collections.Counter()
    port_dist    = collections.Counter()
    feat_sample  = {f: [] for f in KEY_FEATURES}   # for quick stats

    for fname in sorted(os.listdir(CIC17_DIR)):
        fpath = os.path.join(CIC17_DIR, fname)
        file_benign = 0
        with open(fpath, encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            raw_fields = reader.fieldnames
            lc = get_label_col(raw_fields)
            if not lc:
                continue
            norm_map = {c: c.strip() for c in raw_fields}

            # Build canonical → raw
            canon_to_raw = {}
            for raw_c in raw_fields:
                stripped = raw_c.strip()
                if stripped in BUG_COLS or stripped in KEY_FEATURES or \
                   stripped == 'Destination Port':
                    canon_to_raw[stripped] = raw_c

            for row in reader:
                if row.get(lc, '').strip().upper() != 'BENIGN':
                    continue
                if total_benign >= MAX_BENIGN:
                    break
                total_benign += 1
                file_benign  += 1

                # Negative check
                row_any_neg = False
                for c in BUG_COLS:
                    raw_c = canon_to_raw.get(c)
                    if raw_c:
                        v = safe_float(row.get(raw_c, ''))
                        if v is not None and v < 0:
                            neg_counts[c] += 1
                            row_any_neg = True
                if row_any_neg:
                    any_neg += 1

                # Destination Port distribution
                dp_raw = canon_to_raw.get('Destination Port')
                if dp_raw:
                    dp = row.get(dp_raw, '').strip()
                    if dp:
                        port_dist[dp] += 1

                # Feature sample (first 50k for stats)
                if total_benign <= 50_000:
                    for feat in KEY_FEATURES:
                        raw_c = canon_to_raw.get(feat)
                        if raw_c:
                            v = safe_float(row.get(raw_c, ''))
                            if v is not None:
                                feat_sample[feat].append(v)

                # Dedup vector (using 5 key features for speed)
                vec_key = tuple(
                    row.get(canon_to_raw.get(c, ''), '').strip()
                    for c in ['Flow Duration', 'Flow Bytes/s',
                              'Total Fwd Packets', 'Total Backward Packets',
                              'Destination Port']
                )
                dup_vecs[vec_key] += 1

        print(f'  {fname:<60} {file_benign:>8,} BENIGN rows')
        if total_benign >= MAX_BENIGN:
            print(f'  (cap of {MAX_BENIGN:,} reached)')
            break

    n_dup  = sum(n - 1 for n in dup_vecs.values() if n > 1)
    n_uniq = sum(1 for n in dup_vecs.values())

    print(f'\n  Total BENIGN rows scanned : {total_benign:,}  (cap={MAX_BENIGN:,})')
    print(f'\n  --- Negative-value bug ---')
    print(f'  {"Column":<25} {"neg count":>10}  {"% of BENIGN":>12}')
    print('  ' + '-' * 50)
    for c in BUG_COLS:
        n = neg_counts[c]
        pct = n / total_benign * 100 if total_benign else 0
        flag = '  <<< BUG' if n > 0 else ''
        print(f'  {c:<25} {n:>10,}  {pct:>11.3f}%{flag}')
    print(f'  Any-bug rows : {any_neg:,}  ({any_neg/total_benign*100:.3f}%)')

    print(f'\n  --- Duplicate rate (5-key fingerprint) ---')
    print(f'  Unique vectors : {n_uniq:,}')
    print(f'  Duplicate rows : {n_dup:,}  ({n_dup/total_benign*100:.1f}% of BENIGN rows)')

    print(f'\n  --- Destination Port distribution (top 20) ---')
    print(f'  Total unique dst ports : {len(port_dist):,}')
    top_ports = port_dist.most_common(20)
    for port, cnt in top_ports:
        print(f'    port {port:<10} {cnt:>8,}  ({cnt/total_benign*100:.2f}%)')

    # Group sizes for planning grouped split
    group_sizes = sorted(port_dist.values(), reverse=True)
    if group_sizes:
        print(f'\n  Port-group size stats:')
        print(f'    Max group   : {group_sizes[0]:,}')
        print(f'    Median group: {statistics.median(group_sizes):.0f}')
        print(f'    Mean group  : {sum(group_sizes)/len(group_sizes):.0f}')
        print(f'    Groups >=100: {sum(1 for s in group_sizes if s>=100):,}')
        print(f'    Groups ==1  : {sum(1 for s in group_sizes if s==1):,}')

    print(f'\n  --- Key feature quick stats (first 50k BENIGN rows) ---')
    for feat in ['Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
                 'Fwd Packet Length Mean']:
        s = stats(feat_sample[feat])
        print(f'  {feat:<30} n={s["n"]:>7,}  mean={fmt(s["mean"])}  '
              f'min={fmt(s["min"])}  max={fmt(s["max"])}')

    sep('PART C VERDICT')
    print(f"""
  Negative-value bug in BENIGN:
    Any-bug rows : {any_neg:,} / {total_benign:,}  ({any_neg/total_benign*100:.3f}%)
    {'NEGLIGIBLE — safe to mix without separate cleaning step'
     if any_neg/total_benign < 0.001
     else 'PRESENT — clip negatives before mixing (same DURATION_FLOOR approach)'}

  Duplicate rate in BENIGN : {n_dup/total_benign*100:.1f}%
    {'HIGH — dedup before mixing, same as PortScan'
     if n_dup/total_benign > 0.10
     else 'LOW — dedup still recommended but less critical than PortScan (42.9%)'}

  Grouped-split feasibility:
    {len(port_dist):,} unique Destination Ports available as group key
    {'Good coverage for grouped split — similar to PortScan (1000 groups)'
     if len(port_dist) >= 100
     else 'Fewer groups than PortScan — may need finer grouping key'}
    """)


def main():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

    label_ok = part_a()
    part_b()
    part_c()

    sep('SUMMARY')
    print("""
  After running all three parts:
  - If Bot label strings match AND distributions are wildly different:
    => Bot is a signature-mismatch failure (same category as DDoS).
       Document it, no fix needed — mixing BENIGN won't help Bot.
  - CIC-2017 BENIGN negative-value status will determine whether
    cleaning is needed before the mix.
  - Port-group distribution will guide portscan_split-style discipline
    for the BENIGN mix in Step 3b.
    """)


if __name__ == '__main__':
    main()
