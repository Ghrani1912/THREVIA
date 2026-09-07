"""Quick structural inspection of CIC-2017 PortScan rows."""
import csv, os, collections, statistics

DATA = os.path.join(os.path.dirname(__file__), '..', 'data', 'CIC-IDS- 2017')

portscan_rows = []
portscan_file = None
for fname in sorted(os.listdir(DATA)):
    fpath = os.path.join(DATA, fname)
    with open(fpath, encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        label_col = next((c for c in reader.fieldnames if c.strip() == 'Label'), None)
        for row in reader:
            if row.get(label_col, '').strip() == 'PortScan':
                portscan_rows.append({k.strip(): v.strip() for k, v in row.items()})
                if not portscan_file:
                    portscan_file = fname

print(f'PortScan rows : {len(portscan_rows):,}  from file: {portscan_file}')
print(f'Columns       : {len(portscan_rows[0])}')

# Destination Port distribution
dst_ports = collections.Counter(r['Destination Port'] for r in portscan_rows)
print(f'\nUnique Destination Ports : {len(dst_ports):,}')
print(f'Top 20 dst ports         : {dst_ports.most_common(20)}')

# Flow Duration
durations = []
for r in portscan_rows:
    try:
        durations.append(float(r.get('Flow Duration', 0)))
    except ValueError:
        pass
print(f'\nFlow Duration  min={min(durations):.0f}  median={statistics.median(durations):.0f}  '
      f'max={max(durations):.0f}  mean={statistics.mean(durations):.0f}')

# Fwd/Bwd packet count distribution — probe flows are often 1-pkt
fwd_cnts = collections.Counter(r.get('Total Fwd Packets','') for r in portscan_rows)
bwd_cnts = collections.Counter(r.get('Total Backward Packets','') for r in portscan_rows)
print(f'\nTop Fwd Packet counts : {fwd_cnts.most_common(8)}')
print(f'Top Bwd Packet counts : {bwd_cnts.most_common(8)}')

# SYN / RST flag distribution
syn_vals = collections.Counter(r.get('SYN Flag Count','') for r in portscan_rows)
rst_vals = collections.Counter(r.get('RST Flag Count','') for r in portscan_rows)
print(f'\nSYN Flag Count dist   : {dict(syn_vals.most_common(5))}')
print(f'RST Flag Count dist   : {dict(rst_vals.most_common(5))}')

# Duplicate analysis
feat_cols = [k for k in portscan_rows[0] if k != 'Label']
vectors = [tuple(r.get(c, '') for c in feat_cols) for r in portscan_rows]
n_unique = len(set(vectors))
n_dups = len(vectors) - n_unique
print(f'\nTotal rows  : {len(portscan_rows):,}')
print(f'Unique vecs : {n_unique:,}')
print(f'Dup rows    : {n_dups:,}  ({n_dups/len(portscan_rows)*100:.1f}%)')

# How many unique Dst Ports — scanning sweeps a port range
# Group by Dst Port → that's our natural flow-group boundary
# (scan sessions target one port at a time across many hosts;
#  flows to the same port are part of the same scan wave)
port_groups = collections.defaultdict(list)
for i, r in enumerate(portscan_rows):
    port_groups[r['Destination Port']].append(i)

group_sizes = sorted([len(v) for v in port_groups.values()], reverse=True)
print(f'\nFlow-group by Destination Port:')
print(f'  Total groups (unique dst ports) : {len(port_groups):,}')
print(f'  Largest group size              : {group_sizes[0]:,}')
print(f'  Median group size               : {statistics.median(group_sizes):.1f}')
print(f'  Groups with size >= 100         : {sum(1 for s in group_sizes if s>=100):,}')
print(f'  Groups with size == 1           : {sum(1 for s in group_sizes if s==1):,}')
print(f'\n  Top 15 ports by flow count:')
for port, idxs in sorted(port_groups.items(), key=lambda x: -len(x[1]))[:15]:
    print(f'    port {port:<8} -> {len(idxs):,} flows')
