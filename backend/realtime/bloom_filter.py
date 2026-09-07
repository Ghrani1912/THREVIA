"""
Phase 4A — Bloom Filter
=======================
Builds and maintains a Bloom Filter of known malicious IPs extracted from
the UNSW-NB15 dataset (Label == 1).  Supports:
  - build_from_dataset()   : scan CSVs, extract attacker IPs, populate filter
  - check(ip)              : O(1) membership test
  - refresh()              : rebuild filter (call periodically or after blocklist update)
  - save() / load()        : persist filter to disk so it survives restarts
  - add_external_blocklist(): merge a plain-text IP list (one IP per line)

Dependencies: pybloom-live
"""

from __future__ import annotations

import csv
import logging
import pickle
import time
from pathlib import Path

from pybloom_live import ScalableBloomFilter

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent                          # backend/realtime/
_BACKEND = _HERE.parent                                # backend/
_DATA_DIR = _BACKEND / "data" / "UNSW-NB15" / "CSV Files"
_FILTER_PATH = _HERE / "bloom_filter.pkl"
_BLOCKLIST_PATH = _HERE / "blocklist_ips.txt"          # optional external list

# UNSW-NB15 column indices (no header row in the CSVs)
_COL_SRCIP = 0
_COL_LABEL = 48   # 0 = normal, 1 = attack

# ── Core class ─────────────────────────────────────────────────────────────────

class ThreatBloomFilter:
    """
    Wraps a ScalableBloomFilter with dataset-aware build/refresh logic.

    ScalableBloomFilter grows automatically when capacity is exceeded, so we
    never have to hard-code a size.  The default error rate is 0.1 % (1 in 1000
    lookups is a false positive; false negatives are impossible by design).
    """

    def __init__(self, error_rate: float = 0.001):
        self.error_rate = error_rate
        self._filter: ScalableBloomFilter = self._new_filter()
        self._ip_count: int = 0
        self._built_at: float | None = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def build_from_dataset(self) -> None:
        """Scan all UNSW-NB15 CSV files and add every attacker source IP."""
        logger.info("Building Bloom Filter from UNSW-NB15 dataset …")
        new_filter = self._new_filter()
        ips: set[str] = set()

        csv_files = sorted(_DATA_DIR.glob("UNSW-NB15_*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No UNSW-NB15 CSVs found in {_DATA_DIR}")

        for fpath in csv_files:
            logger.info("  Scanning %s", fpath.name)
            with open(fpath, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) <= _COL_LABEL:
                        continue
                    label = row[_COL_LABEL].strip()
                    if label == "1":
                        ips.add(row[_COL_SRCIP].strip())

        # Also merge any external blocklist file if it exists
        ips.update(self._load_external_blocklist())

        for ip in ips:
            new_filter.add(ip)

        self._filter = new_filter
        self._ip_count = len(ips)
        self._built_at = time.time()
        logger.info(
            "Bloom Filter built: %d unique malicious IPs  (error_rate=%.4f)",
            self._ip_count,
            self.error_rate,
        )

    def check(self, ip: str) -> bool:
        """
        Return True if *ip* is (probably) in the malicious-IP set.
        False negatives are impossible; false positive rate ≈ self.error_rate.
        """
        return ip in self._filter

    def add(self, ip: str) -> None:
        """Add a single IP to the filter (e.g., from a live threat feed)."""
        self._filter.add(ip)
        self._ip_count += 1

    def add_external_blocklist(self, path: str | Path | None = None) -> int:
        """
        Merge a plain-text file of IPs (one per line, # = comment).
        Returns number of IPs added.
        """
        path = Path(path) if path else _BLOCKLIST_PATH
        ips = self._load_external_blocklist(path)
        for ip in ips:
            self._filter.add(ip)
        self._ip_count += len(ips)
        logger.info("Added %d IPs from external blocklist %s", len(ips), path)
        return len(ips)

    def refresh(self) -> None:
        """Rebuild the filter from scratch (dataset + blocklist)."""
        logger.info("Refreshing Bloom Filter …")
        self.build_from_dataset()
        self.save()

    def save(self, path: str | Path | None = None) -> None:
        """Persist filter to disk using pickle."""
        path = Path(path) if path else _FILTER_PATH
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "filter": self._filter,
                    "ip_count": self._ip_count,
                    "built_at": self._built_at,
                    "error_rate": self.error_rate,
                },
                f,
            )
        logger.info("Bloom Filter saved to %s", path)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ThreatBloomFilter":
        """Load a previously saved filter from disk."""
        path = Path(path) if path else _FILTER_PATH
        with open(path, "rb") as f:
            data = pickle.load(f)
        obj = cls(error_rate=data["error_rate"])
        obj._filter = data["filter"]
        obj._ip_count = data["ip_count"]
        obj._built_at = data["built_at"]
        logger.info(
            "Bloom Filter loaded from %s  (%d IPs, built %.0f s ago)",
            path,
            obj._ip_count,
            time.time() - (obj._built_at or 0),
        )
        return obj

    @classmethod
    def load_or_build(cls) -> "ThreatBloomFilter":
        """
        Convenience: load saved filter if it exists, otherwise build fresh.
        Call this at application startup.
        """
        if _FILTER_PATH.exists():
            try:
                return cls.load()
            except Exception as exc:
                logger.warning("Could not load saved filter (%s) — rebuilding.", exc)
        obj = cls()
        obj.build_from_dataset()
        obj.save()
        return obj

    # ── Stats ──────────────────────────────────────────────────────────────────

    @property
    def ip_count(self) -> int:
        return self._ip_count

    @property
    def built_at(self) -> float | None:
        return self._built_at

    def stats(self) -> dict:
        return {
            "ip_count": self._ip_count,
            "error_rate": self.error_rate,
            "built_at": self._built_at,
            "filter_path": str(_FILTER_PATH),
        }

    # ── Internals ──────────────────────────────────────────────────────────────

    def _new_filter(self) -> ScalableBloomFilter:
        return ScalableBloomFilter(
            initial_capacity=1000,
            error_rate=self.error_rate,
            mode=ScalableBloomFilter.LARGE_SET_GROWTH,
        )

    @staticmethod
    def _load_external_blocklist(path: Path | None = None) -> set[str]:
        path = path or _BLOCKLIST_PATH
        ips: set[str] = set()
        if not path.exists():
            return ips
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
        return ips


# ── CLI quick-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    bf = ThreatBloomFilter()
    bf.build_from_dataset()
    bf.save()

    # Verify known attackers are flagged
    known_bad = ["175.45.176.0", "175.45.176.1", "175.45.176.2", "175.45.176.3"]
    known_good = ["8.8.8.8", "1.1.1.1", "192.168.1.1"]

    print("\n── Bloom Filter Verification ──")
    for ip in known_bad:
        result = bf.check(ip)
        status = "✓ FLAGGED (correct)" if result else "✗ MISSED (false negative!)"
        print(f"  {ip:<20} → {status}")
    for ip in known_good:
        result = bf.check(ip)
        status = "✗ FALSE POSITIVE" if result else "✓ clean"
        print(f"  {ip:<20} → {status}")

    print(f"\nFilter stats: {bf.stats()}")
