"""
Phase 4 — Alert Writer
=======================
Writes streaming alerts and Bloom Filter hits to MongoDB so the Phase 6
dashboard can read them.

Collections written:
  - threvia.stream_alerts    : windowed spike alerts from the streaming detector
  - threvia.bloom_hits       : per-row Bloom Filter flagged events

Both collections are time-indexed for efficient dashboard queries.

Dependencies: pymongo
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from pymongo import MongoClient, ASCENDING, errors

logger = logging.getLogger(__name__)

# ── Config (override via environment variables) ────────────────────────────────
_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
_DB_NAME = os.getenv("MONGO_DB", "threvia")

_COL_ALERTS = "stream_alerts"
_COL_BLOOM = "bloom_hits"


class AlertWriter:
    """
    Thin wrapper around PyMongo for writing Phase 4 events.

    Uses a lazy connection so the object can be imported even when MongoDB
    is not yet running (connection only happens on first write).
    """

    def __init__(
        self,
        mongo_uri: str = _MONGO_URI,
        db_name: str = _DB_NAME,
    ):
        self._uri = mongo_uri
        self._db_name = db_name
        self._client: MongoClient | None = None
        self._db = None

    # ── Connection ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open connection and ensure indexes exist."""
        self._client = MongoClient(self._uri, serverSelectionTimeoutMS=5000)
        # Ping to fail fast if Mongo is unreachable
        self._client.admin.command("ping")
        self._db = self._client[self._db_name]
        self._ensure_indexes()
        logger.info("AlertWriter connected to MongoDB at %s (db=%s)", self._uri, self._db_name)

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
            self._db = None

    def __enter__(self) -> "AlertWriter":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ── Write API ──────────────────────────────────────────────────────────────

    def write_spike_alert(
        self,
        src_ip: str,
        window_start: str,
        window_end: str,
        connection_count: int,
        total_bytes: float,
        attack_label: str,
        severity: str,
    ) -> str:
        """
        Persist a windowed spike alert.

        Returns the inserted document id as a string.
        """
        doc: dict[str, Any] = {
            "type": "spike_alert",
            "src_ip": src_ip,
            "window_start": window_start,
            "window_end": window_end,
            "connection_count": connection_count,
            "total_bytes": total_bytes,
            "attack_label": attack_label,
            "severity": severity,
            "created_at": datetime.now(timezone.utc),
        }
        result = self._col(_COL_ALERTS).insert_one(doc)
        logger.debug("Spike alert written: %s  ip=%s  count=%d  severity=%s",
                     result.inserted_id, src_ip, connection_count, severity)
        return str(result.inserted_id)

    def write_bloom_hit(
        self,
        src_ip: str,
        dst_ip: str,
        proto: str,
        service: str,
        attack_cat: str,
        label: str,
        event_time: str,
    ) -> str:
        """
        Persist a single Bloom Filter hit (a row whose src_ip was flagged).
        """
        doc: dict[str, Any] = {
            "type": "bloom_hit",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "service": service,
            "attack_cat": attack_cat,
            "label": label,
            "event_time": event_time,
            "created_at": datetime.now(timezone.utc),
        }
        result = self._col(_COL_BLOOM).insert_one(doc)
        logger.debug("Bloom hit written: %s  src=%s  cat=%s", result.inserted_id, src_ip, attack_cat)
        return str(result.inserted_id)

    def write_bloom_hits_bulk(self, hits: list[dict]) -> int:
        """
        Bulk-insert a list of Bloom hit dicts (as returned by the streaming job).
        Returns the number of documents inserted.
        """
        if not hits:
            return 0
        now = datetime.now(timezone.utc)
        for doc in hits:
            doc.setdefault("type", "bloom_hit")
            doc.setdefault("created_at", now)
        result = self._col(_COL_BLOOM).insert_many(hits)
        logger.info("Bulk bloom hits inserted: %d", len(result.inserted_ids))
        return len(result.inserted_ids)

    def write_spike_alerts_bulk(self, alerts: list[dict]) -> int:
        """
        Bulk-insert a list of spike alert dicts.
        Returns the number of documents inserted.
        """
        if not alerts:
            return 0
        now = datetime.now(timezone.utc)
        for doc in alerts:
            doc.setdefault("type", "spike_alert")
            doc.setdefault("created_at", now)
        result = self._col(_COL_ALERTS).insert_many(alerts)
        logger.info("Bulk spike alerts inserted: %d", len(result.inserted_ids))
        return len(result.inserted_ids)

    # ── Query helpers (used by the dashboard) ──────────────────────────────────

    def get_recent_alerts(self, limit: int = 100) -> list[dict]:
        """Return the most recent spike alerts (newest first)."""
        cursor = (
            self._col(_COL_ALERTS)
            .find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        return list(cursor)

    def get_recent_bloom_hits(self, limit: int = 100) -> list[dict]:
        """Return the most recent Bloom Filter hits (newest first)."""
        cursor = (
            self._col(_COL_BLOOM)
            .find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        return list(cursor)

    def count_alerts_by_severity(self) -> dict[str, int]:
        """Aggregate spike alert counts by severity (for dashboard widgets)."""
        pipeline = [
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return {d["_id"]: d["count"] for d in self._col(_COL_ALERTS).aggregate(pipeline)}

    def count_bloom_hits_by_ip(self, top_n: int = 20) -> list[dict]:
        """Return top N attacker IPs by Bloom hit frequency."""
        pipeline = [
            {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": top_n},
            {"$project": {"ip": "$_id", "count": 1, "_id": 0}},
        ]
        return list(self._col(_COL_BLOOM).aggregate(pipeline))

    # ── Internals ──────────────────────────────────────────────────────────────

    def _col(self, name: str):
        if self._db is None:
            self.connect()
        return self._db[name]

    def _ensure_indexes(self) -> None:
        """Create time-based indexes if they don't already exist."""
        try:
            self._db[_COL_ALERTS].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_BLOOM].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_BLOOM].create_index(
                [("src_ip", ASCENDING)], background=True
            )
        except errors.PyMongoError as exc:
            logger.warning("Index creation warning: %s", exc)


# ── Standalone test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    with AlertWriter() as aw:
        # Write a test spike alert
        alert_id = aw.write_spike_alert(
            src_ip="175.45.176.0",
            window_start="2026-09-06 10:00:00",
            window_end="2026-09-06 10:01:00",
            connection_count=5432,
            total_bytes=8_200_000.0,
            attack_label="DoS",
            severity="Critical",
        )
        print(f"Test spike alert inserted: {alert_id}")

        # Write a test bloom hit
        bloom_id = aw.write_bloom_hit(
            src_ip="175.45.176.1",
            dst_ip="149.171.126.6",
            proto="tcp",
            service="http",
            attack_cat="Exploits",
            label="1",
            event_time="2026-09-06 10:00:05",
        )
        print(f"Test bloom hit inserted: {bloom_id}")

        # Query back
        print("\nRecent alerts:", aw.get_recent_alerts(limit=2))
        print("Severity counts:", aw.count_alerts_by_severity())
        print("Top IPs:", aw.count_bloom_hits_by_ip(top_n=5))
