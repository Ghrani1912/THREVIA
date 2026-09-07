"""
schema_maps.py — Canonical column rename maps for all datasets.

CANONICAL schema = CIC-IDS-2017 column names (stripped of leading/trailing
whitespace), which is the feature set our existing PySpark pipeline was built on.

Each map is { source_column_name : canonical_column_name }.
Columns that exist only in the source (not in canonical) are listed separately
as EXTRA_* so callers can decide to drop or keep them.

Label normalisation maps are at the bottom — they map each dataset's raw label
strings to a unified label namespace used across the merged corpus.

Usage in PySpark:
    from processing.schema_maps import LYCOS_RENAME, CIC18_RENAME, IDS25_RENAME
    for src, tgt in LYCOS_RENAME.items():
        df = df.withColumnRenamed(src, tgt)
"""

# ─────────────────────────────────────────────────────────────────────────────
# CANONICAL FEATURE COLUMNS  (CIC-IDS-2017, whitespace-stripped)
# ─────────────────────────────────────────────────────────────────────────────
# NOTE: CIC-2017 has a duplicate "Fwd Header Length" column (indices 34 and 55).
# After strip+dedup in preprocess.py the second occurrence becomes
# "Fwd Header Length_2". We treat "Fwd Header Length" as the canonical name
# and drop the duplicate during corpus build.

CANONICAL_FEATURE_COLS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",            # raw label — kept as string
]

CANONICAL_LABEL_COL = "Label"

# ─────────────────────────────────────────────────────────────────────────────
# LycoS-IDS2018  →  Canonical
# ─────────────────────────────────────────────────────────────────────────────
# LycoS has 78 cols (same count as CIC-2017).
# Column concepts map 1-to-1 but naming convention differs:
#   snake_case  vs  "Title Case with /s slashes"
# Extra LycoS-only cols that have no CIC-2017 equivalent are listed below.

LYCOS_RENAME: dict[str, str] = {
    # ── identity / port ──────────────────────────────────────────
    "dst_port":                 "Destination Port",
    # ip_prot has no CIC-2017 equivalent → kept as-is (see LYCOS_EXTRA)

    # ── flow-level ───────────────────────────────────────────────
    "flow_duration":            "Flow Duration",
    "down_up_ratio":            "Down/Up Ratio",
    "bytes_per_s":              "Flow Bytes/s",
    "pkt_per_s":                "Flow Packets/s",

    # ── packet length (overall) ───────────────────────────────────
    "pkt_len_max":              "Max Packet Length",
    "pkt_len_min":              "Min Packet Length",
    "pkt_len_mean":             "Packet Length Mean",
    "pkt_len_var":              "Packet Length Variance",
    "pkt_len_std":              "Packet Length Std",

    # ── forward packet stats ──────────────────────────────────────
    "fwd_pkt_cnt":              "Total Fwd Packets",
    "fwd_pkt_len_tot":          "Total Length of Fwd Packets",
    "fwd_pkt_len_max":          "Fwd Packet Length Max",
    "fwd_pkt_len_min":          "Fwd Packet Length Min",
    "fwd_pkt_len_mean":         "Fwd Packet Length Mean",
    "fwd_pkt_len_std":          "Fwd Packet Length Std",
    "fwd_pkt_hdr_len_tot":      "Fwd Header Length",
    # fwd_pkt_hdr_len_min → no CIC-2017 equivalent (see LYCOS_EXTRA)
    # fwd_non_empty_pkt_cnt → no CIC-2017 equivalent
    "fwd_pkt_per_s":            "Fwd Packets/s",

    # ── backward packet stats ─────────────────────────────────────
    "bwd_pkt_cnt":              "Total Backward Packets",
    "bwd_pkt_len_tot":          "Total Length of Bwd Packets",
    "bwd_pkt_len_max":          "Bwd Packet Length Max",
    "bwd_pkt_len_min":          "Bwd Packet Length Min",
    "bwd_pkt_len_mean":         "Bwd Packet Length Mean",
    "bwd_pkt_len_std":          "Bwd Packet Length Std",
    "bwd_pkt_hdr_len_tot":      "Bwd Header Length",
    # bwd_pkt_hdr_len_min → no CIC-2017 equivalent
    # bwd_non_empty_pkt_cnt → no CIC-2017 equivalent
    "bwd_pkt_per_s":            "Bwd Packets/s",

    # ── inter-arrival times (flow) ────────────────────────────────
    "iat_max":                  "Flow IAT Max",
    "iat_min":                  "Flow IAT Min",
    "iat_mean":                 "Flow IAT Mean",
    "iat_std":                  "Flow IAT Std",

    # ── inter-arrival times (forward) ────────────────────────────
    "fwd_iat_tot":              "Fwd IAT Total",
    "fwd_iat_max":              "Fwd IAT Max",
    "fwd_iat_min":              "Fwd IAT Min",
    "fwd_iat_mean":             "Fwd IAT Mean",
    "fwd_iat_std":              "Fwd IAT Std",

    # ── inter-arrival times (backward) ───────────────────────────
    "bwd_iat_tot":              "Bwd IAT Total",
    "bwd_iat_max":              "Bwd IAT Max",
    "bwd_iat_min":              "Bwd IAT Min",
    "bwd_iat_mean":             "Bwd IAT Mean",
    "bwd_iat_std":              "Bwd IAT Std",

    # ── active / idle ─────────────────────────────────────────────
    "active_max":               "Active Max",
    "active_min":               "Active Min",
    "active_mean":              "Active Mean",
    "active_std":               "Active Std",
    "idle_max":                 "Idle Max",
    "idle_min":                 "Idle Min",
    "idle_mean":                "Idle Mean",
    "idle_std":                 "Idle Std",

    # ── TCP flags ─────────────────────────────────────────────────
    "flag_SYN":                 "SYN Flag Count",
    "flag_fin":                 "FIN Flag Count",
    "flag_rst":                 "RST Flag Count",
    "flag_ack":                 "ACK Flag Count",
    "flag_psh":                 "PSH Flag Count",
    "fwd_flag_psh":             "Fwd PSH Flags",
    "bwd_flag_psh":             "Bwd PSH Flags",
    "flag_urg":                 "URG Flag Count",
    "fwd_flag_urg":             "Fwd URG Flags",
    "bwd_flag_urg":             "Bwd URG Flags",
    "flag_cwr":                 "CWE Flag Count",   # CWR renamed CWE in CIC-2017
    "flag_ece":                 "ECE Flag Count",

    # ── bulk / subflow ────────────────────────────────────────────
    "fwd_bulk_bytes_mean":      "Fwd Avg Bytes/Bulk",
    "fwd_bulk_pkt_mean":        "Fwd Avg Packets/Bulk",
    "fwd_bulk_rate_mean":       "Fwd Avg Bulk Rate",
    "bwd_bulk_bytes_mean":      "Bwd Avg Bytes/Bulk",
    "bwd_bulk_pkt_mean":        "Bwd Avg Packets/Bulk",
    "bwd_bulk_rate_mean":       "Bwd Avg Bulk Rate",
    "fwd_subflow_bytes_mean":   "Subflow Fwd Bytes",
    "fwd_subflow_pkt_mean":     "Subflow Fwd Packets",
    "bwd_subflow_bytes_mean":   "Subflow Bwd Bytes",
    "bwd_subflow_pkt_mean":     "Subflow Bwd Packets",

    # ── TCP init window ───────────────────────────────────────────
    "fwd_tcp_init_win_bytes":   "Init_Win_bytes_forward",
    "bwd_tcp_init_win_bytes":   "Init_Win_bytes_backward",

    # ── label ─────────────────────────────────────────────────────
    "label":                    "Label",
}

# LycoS columns that have no CIC-2017 canonical equivalent → DROP during merge
LYCOS_EXTRA_DROP = [
    "ip_prot",              # protocol number; CIC-2017 doesn't expose this
    "fwd_pkt_hdr_len_min",  # min header length fwd; CIC uses total only
    "fwd_non_empty_pkt_cnt",
    "bwd_pkt_hdr_len_min",
    "bwd_non_empty_pkt_cnt",
]

# CIC-2017 columns NOT present in LycoS → will be NULL-filled during merge
LYCOS_MISSING_FROM_LYCOS = [
    "Average Packet Size",      # CIC computes avg pkt size differently
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
]

# ─────────────────────────────────────────────────────────────────────────────
# CICIDS2018  →  Canonical
# ─────────────────────────────────────────────────────────────────────────────
# CICIDS2018 has 80 cols vs CIC-2017's 78.
# Extra cols: "Protocol" and "Timestamp" (not in CIC-2017).
# Several cols use abbreviated names ("Fwd Pkt Len Max" vs "Fwd Packet Length Max")
# and slightly different abbreviations for flag counts ("Cnt" vs "Count").

CIC18_RENAME: dict[str, str] = {
    # ── identity ──────────────────────────────────────────────────
    "Dst Port":             "Destination Port",
    # "Protocol" → CICIDS2018-only, no CIC-2017 equivalent (see CIC18_EXTRA_DROP)
    # "Timestamp" → CICIDS2018-only (see CIC18_EXTRA_DROP)

    # ── flow ─────────────────────────────────────────────────────
    "Flow Duration":        "Flow Duration",     # same name, keep explicit
    "Flow Byts/s":          "Flow Bytes/s",
    "Flow Pkts/s":          "Flow Packets/s",
    "Flow IAT Mean":        "Flow IAT Mean",
    "Flow IAT Std":         "Flow IAT Std",
    "Flow IAT Max":         "Flow IAT Max",
    "Flow IAT Min":         "Flow IAT Min",
    "Down/Up Ratio":        "Down/Up Ratio",

    # ── forward ───────────────────────────────────────────────────
    "Tot Fwd Pkts":         "Total Fwd Packets",
    "TotLen Fwd Pkts":      "Total Length of Fwd Packets",
    "Fwd Pkt Len Max":      "Fwd Packet Length Max",
    "Fwd Pkt Len Min":      "Fwd Packet Length Min",
    "Fwd Pkt Len Mean":     "Fwd Packet Length Mean",
    "Fwd Pkt Len Std":      "Fwd Packet Length Std",
    "Fwd IAT Tot":          "Fwd IAT Total",
    "Fwd IAT Mean":         "Fwd IAT Mean",
    "Fwd IAT Std":          "Fwd IAT Std",
    "Fwd IAT Max":          "Fwd IAT Max",
    "Fwd IAT Min":          "Fwd IAT Min",
    "Fwd PSH Flags":        "Fwd PSH Flags",
    "Fwd URG Flags":        "Fwd URG Flags",
    "Fwd Header Len":       "Fwd Header Length",
    "Fwd Pkts/s":           "Fwd Packets/s",
    "Fwd Seg Size Avg":     "Avg Fwd Segment Size",
    "Fwd Byts/b Avg":       "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg":       "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg":     "Fwd Avg Bulk Rate",
    "Subflow Fwd Pkts":     "Subflow Fwd Packets",
    "Subflow Fwd Byts":     "Subflow Fwd Bytes",
    "Init Fwd Win Byts":    "Init_Win_bytes_forward",
    "Fwd Act Data Pkts":    "act_data_pkt_fwd",
    "Fwd Seg Size Min":     "min_seg_size_forward",

    # ── backward ──────────────────────────────────────────────────
    "Tot Bwd Pkts":         "Total Backward Packets",
    "TotLen Bwd Pkts":      "Total Length of Bwd Packets",
    "Bwd Pkt Len Max":      "Bwd Packet Length Max",
    "Bwd Pkt Len Min":      "Bwd Packet Length Min",
    "Bwd Pkt Len Mean":     "Bwd Packet Length Mean",
    "Bwd Pkt Len Std":      "Bwd Packet Length Std",
    "Bwd IAT Tot":          "Bwd IAT Total",
    "Bwd IAT Mean":         "Bwd IAT Mean",
    "Bwd IAT Std":          "Bwd IAT Std",
    "Bwd IAT Max":          "Bwd IAT Max",
    "Bwd IAT Min":          "Bwd IAT Min",
    "Bwd PSH Flags":        "Bwd PSH Flags",
    "Bwd URG Flags":        "Bwd URG Flags",
    "Bwd Header Len":       "Bwd Header Length",
    "Bwd Pkts/s":           "Bwd Packets/s",
    "Bwd Seg Size Avg":     "Avg Bwd Segment Size",
    "Bwd Byts/b Avg":       "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg":       "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg":     "Bwd Avg Bulk Rate",
    "Subflow Bwd Pkts":     "Subflow Bwd Packets",
    "Subflow Bwd Byts":     "Subflow Bwd Bytes",
    "Init Bwd Win Byts":    "Init_Win_bytes_backward",

    # ── packet length ─────────────────────────────────────────────
    "Pkt Len Min":          "Min Packet Length",
    "Pkt Len Max":          "Max Packet Length",
    "Pkt Len Mean":         "Packet Length Mean",
    "Pkt Len Std":          "Packet Length Std",
    "Pkt Len Var":          "Packet Length Variance",
    "Pkt Size Avg":         "Average Packet Size",

    # ── flags ─────────────────────────────────────────────────────
    "FIN Flag Cnt":         "FIN Flag Count",
    "SYN Flag Cnt":         "SYN Flag Count",
    "RST Flag Cnt":         "RST Flag Count",
    "PSH Flag Cnt":         "PSH Flag Count",
    "ACK Flag Cnt":         "ACK Flag Count",
    "URG Flag Cnt":         "URG Flag Count",
    "CWE Flag Count":       "CWE Flag Count",    # same name
    "ECE Flag Cnt":         "ECE Flag Count",

    # ── active / idle ─────────────────────────────────────────────
    "Active Mean":          "Active Mean",
    "Active Std":           "Active Std",
    "Active Max":           "Active Max",
    "Active Min":           "Active Min",
    "Idle Mean":            "Idle Mean",
    "Idle Std":             "Idle Std",
    "Idle Max":             "Idle Max",
    "Idle Min":             "Idle Min",

    # ── label ─────────────────────────────────────────────────────
    "Label":                "Label",
}

# CICIDS2018-only columns → DROP
CIC18_EXTRA_DROP = [
    "Protocol",    # not in CIC-2017 canonical
    "Timestamp",   # collection timestamp; not a feature
]

# ─────────────────────────────────────────────────────────────────────────────
# IDS2025  →  Canonical  (held-out validation set only)
# ─────────────────────────────────────────────────────────────────────────────
# IDS2025 is nearly identical to CIC-2017 with minor naming differences:
#   "Flow Bytess" (double-s typo), "Flow Packetss", "Fwd Packetss", "Bwd Packetss"
#   "Down Up Ratio" (missing slash), bulk column names (no slash)
#   "newLabel" instead of "Label"

IDS25_RENAME: dict[str, str] = {
    # ── typo fixes (double-s) ─────────────────────────────────────
    "Flow Bytess":              "Flow Bytes/s",
    "Flow Packetss":            "Flow Packets/s",
    "Fwd Packetss":             "Fwd Packets/s",
    "Bwd Packetss":             "Bwd Packets/s",

    # ── spacing fixes ─────────────────────────────────────────────
    "Down Up Ratio":            "Down/Up Ratio",

    # ── bulk names (spaces instead of slashes) ────────────────────
    "Fwd Avg Bytes Bulk":       "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets Bulk":     "Fwd Avg Packets/Bulk",
    "Bwd Avg Bytes Bulk":       "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets Bulk":     "Bwd Avg Packets/Bulk",

    # ── label ─────────────────────────────────────────────────────
    "newLabel":                 "Label",

    # ── source port (IDS2025-only, not in CIC-2017) ───────────────
    # "Source Port" → dropped (see IDS25_EXTRA_DROP)
}

# IDS2025-only columns → DROP
IDS25_EXTRA_DROP = [
    "Source Port",   # CIC-2017 doesn't include source port as a feature
]

# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED LABEL MAP
# ─────────────────────────────────────────────────────────────────────────────
# Maps every raw label string (from any dataset) to a single canonical label.
# This is used in merge_corpus.py to produce a consistent "Label" column.
# All comparisons are done after .strip().upper() on the raw value.

LABEL_NORMALISE: dict[str, str] = {
    # ── benign ────────────────────────────────────────────────────
    "BENIGN":                           "BENIGN",
    "BENIGN ":                          "BENIGN",
    "NORMAL":                           "BENIGN",

    # ── DoS variants ─────────────────────────────────────────────
    "DOS HULK":                         "DoS Hulk",
    "DOS GOLDENEYE":                    "DoS GoldenEye",
    "DOS SLOWLORIS":                    "DoS slowloris",
    "DOS SLOWHTTPTEST":                 "DoS Slowhttptest",
    "DOS/DDOS":                         "DoS/DDoS",      # IDS2025 merged class

    # ── DDoS variants ────────────────────────────────────────────
    "DDOS":                             "DDoS",
    "DDOS HOIC":                        "DDoS",          # LycoS → merge into DDoS
    "DDOS LOIC-HTTP":                   "DDoS",
    "DDOS LOIC-UDP":                    "DDoS",

    # ── Brute force / patator ─────────────────────────────────────
    "FTP-PATATOR":                      "FTP-Patator",
    "SSH-PATATOR":                      "SSH-Patator",
    "BRUTE FORCE":                      "Brute Force",   # IDS2025

    # ── Web attacks ───────────────────────────────────────────────
    "WEB ATTACK \x96 BRUTE FORCE":     "Web Attack - Brute Force",
    "WEB ATTACK \x96 XSS":             "Web Attack - XSS",
    "WEB ATTACK \x96 SQL INJECTION":   "Web Attack - Sql Injection",
    "WEB ATTACK - BRUTE FORCE":        "Web Attack - Brute Force",
    "WEB ATTACK - XSS":                "Web Attack - XSS",
    "WEB ATTACK - SQL INJECTION":      "Web Attack - Sql Injection",
    "WEB ATTACK":                       "Web Attack - Brute Force",  # IDS2025 merged

    # ── Botnet ────────────────────────────────────────────────────
    "BOT":                              "Bot",
    "BOTNET ARES":                      "Bot",           # IDS2025

    # ── Infiltration ─────────────────────────────────────────────
    "INFILTRATION":                     "Infiltration",
    "INFILTERATION":                    "Infiltration",  # CIC-2018 typo

    # ── PortScan ──────────────────────────────────────────────────
    "PORTSCAN":                         "PortScan",

    # ── Heartbleed ────────────────────────────────────────────────
    "HEARTBLEED":                       "Heartbleed",
}


def normalise_label(raw: str) -> str:
    """Return canonical label for a raw label string. Falls back to raw.strip()."""
    key = raw.strip().upper()
    return LABEL_NORMALISE.get(key, raw.strip())


# ─────────────────────────────────────────────────────────────────────────────
# QUICK SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== schema_maps self-test ===\n")

    print(f"Canonical feature cols  : {len(CANONICAL_FEATURE_COLS)}")
    print(f"LycoS rename entries    : {len(LYCOS_RENAME)}")
    print(f"LycoS drop cols         : {LYCOS_EXTRA_DROP}")
    print(f"LycoS null-filled cols  : {LYCOS_MISSING_FROM_LYCOS}")
    print(f"CIC18 rename entries    : {len(CIC18_RENAME)}")
    print(f"CIC18 drop cols         : {CIC18_EXTRA_DROP}")
    print(f"IDS25 rename entries    : {len(IDS25_RENAME)}")
    print(f"IDS25 drop cols         : {IDS25_EXTRA_DROP}")
    print(f"Label normalisations    : {len(LABEL_NORMALISE)}")

    # Verify every canonical col (except Label) is covered by LycoS rename
    lycos_tgts = set(LYCOS_RENAME.values()) | set(LYCOS_MISSING_FROM_LYCOS) | {"Label"}
    missing_lycos = [c for c in CANONICAL_FEATURE_COLS if c not in lycos_tgts]
    print(f"\nCanonical cols NOT covered by LycoS map : {missing_lycos}")

    # Verify CIC18 rename covers all canonical cols except known-absent ones
    cic18_tgts = set(CIC18_RENAME.values())
    missing_cic18 = [c for c in CANONICAL_FEATURE_COLS if c not in cic18_tgts]
    print(f"Canonical cols NOT covered by CIC18 map : {missing_cic18}")

    # Sample label normalisations
    print("\nSample label normalisations:")
    samples = [
        "BENIGN", "Benign", "benign",
        "DoS Hulk", "DOS HULK",
        "Infilteration", "INFILTERATION",
        "DDoS HOIC", "DDOS HOIC",
        "Web Attack \x96 Brute Force",
        "Bot", "Botnet ARES",
        "PortScan", "PORTSCAN",
    ]
    for s in samples:
        print(f"  {s!r:45s} -> {normalise_label(s)!r}")
