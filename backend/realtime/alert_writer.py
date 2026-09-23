"""
Phase 4 — Alert Writer
=======================
Writes streaming alerts and Bloom Filter hits to MongoDB so the Phase 6
dashboard can read them.

Collections written:
  - threvia.stream_alerts  : windowed spike alerts from the streaming detector
  - threvia.bloom_hits     : per-row Bloom Filter flagged events
  - threvia.ml_alerts      : ML-scored alerts (Pipeline C), aggregated per
                             (src_ip, attack_type, severity) by default -- see
                             ``aggregate_ml_alerts``.  Raw per-flow input is
                             still accepted; the collapse keeps the collection
                             proportional to incidents rather than to packets.
  - threvia.feedback       : analyst verdicts on alerts (confirmed /
                             false_positive).  The ONLY source of human labels
                             for the online-learning layer, and deliberately not
                             TTL-expired: it is training data, and a verdict is
                             as valid a year later as the day it was given.
  - threvia.learning_telemetry : one small document per streaming batch from
                             ``online_learning.OnlineLearningPolicy`` -- what the
                             adaptive layer did and why.  TTL-expired.
  - threvia.learning_state : the current learning state, upserted (one document,
                             ``key='policy'``) so a dashboard can read it without
                             reaching into the detector's filesystem.

Alert collections are time-indexed for efficient dashboard queries.

Dependencies: pymongo
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from pymongo import MongoClient, ASCENDING, errors

logger = logging.getLogger(__name__)

# ── Config (override via environment variables) ─────────────────────────────
# Host-side default. docker-compose publishes MongoDB on host 27018 (container
# 27017), so anything launched from the host — the API venv, populate_mongo.py,
# run_phase5.py — must default there. The detector and the API both pass an
# explicit uri, and the containers get MONGO_URI from compose, so this default
# only governs host-run callers.
_MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")
_DB_NAME   = os.getenv("MONGO_DB", "threvia")

_COL_ALERTS = "stream_alerts"
_COL_BLOOM  = "bloom_hits"
_COL_ML     = "ml_alerts"
_COL_NOMINAL = "nominal_flows"
_COL_FEEDBACK = "feedback"
_COL_LEARNING = "learning_telemetry"
_COL_LEARNING_STATE = "learning_state"
_LEARNING_STATE_KEY = "policy"

# Retention. Alert and nominal collections expire this many hours after
# creation. At the observed ~20 docs/s this caps ml_alerts near ~1.2M docs
# regardless of uptime; tune via env without touching code.
DEFAULT_TTL_HOURS = 72.0
TTL_HOURS = float(os.getenv("ALERT_TTL_HOURS", str(DEFAULT_TTL_HOURS)))

# Learning telemetry is a slower-moving diagnostic than the alerts it describes --
# a drift trend over a week is the useful view -- so it outlives them.
LEARNING_TTL_HOURS = float(os.getenv("LEARNING_TTL_HOURS", "168"))

# Collapse per-flow ML alerts into one document per (src_ip, attack_type,
# severity).  Alert *volume* is what an analyst actually pays for, and a model
# operating point is measured in flows, not documents -- storing 36,901 rows for
# one benign host conflates the two.  Disable to restore row-per-document.
_ML_ALERT_AGGREGATE = os.getenv("ML_ALERT_AGGREGATE", "true").strip().lower() \
    in ("1", "true", "yes", "on")
_ML_MAX_DST_SAMPLES = int(os.getenv("ML_MAX_DST_SAMPLES", "10"))


def aggregate_ml_alerts(
    alerts: list[dict],
    max_dst_samples: int = _ML_MAX_DST_SAMPLES,
) -> tuple[list[dict], int]:
    """
    Collapse per-flow ML alerts into one document per source-IP verdict.

    Each output document keeps the shape the dashboard already reads
    (``src_ip``, ``dst_ip``, ``attack_type``, ``confidence``, ``severity``,
    ``event_time``, ``ground_truth_label``, ``ground_truth_cat``) and adds the
    volume context needed to triage it:

      ``flow_count``      flows in this group
      ``dst_ip_count``    distinct destinations touched
      ``dst_ips``         up to ``max_dst_samples`` example destinations
      ``first_seen`` / ``last_seen`` / ``max_confidence``

    The representative fields come from the highest-confidence flow, so
    ``confidence`` and ``severity`` describe the strongest evidence, not an
    average that hides it.

    Returns ``(documents, original_row_count)``.
    """
    if not alerts:
        return [], 0

    groups: dict[tuple, dict] = {}
    for alert in alerts:
        key = (
            str(alert.get("src_ip")),
            str(alert.get("attack_type")),
            str(alert.get("severity")),
        )
        confidence = alert.get("confidence")
        try:
            confidence = float(confidence) if confidence is not None else 0.0
        except (TypeError, ValueError):
            confidence = 0.0

        group = groups.get(key)
        if group is None:
            group = {
                "_best": alert,
                "_best_conf": confidence,
                "flow_count": 0,
                "dst_ips": [],       # capped sample, for display
                "_dst_seen": set(),  # true distinct count
                "first_seen": alert.get("event_time"),
                "last_seen": alert.get("event_time"),
            }
            groups[key] = group

        group["flow_count"] += 1
        if confidence > group["_best_conf"]:
            group["_best"] = alert
            group["_best_conf"] = confidence

        dst = alert.get("dst_ip")
        if dst:
            if dst not in group["_dst_seen"]:
                group["_dst_seen"].add(dst)
                if len(group["dst_ips"]) < max_dst_samples:
                    group["dst_ips"].append(dst)

        event_time = alert.get("event_time")
        if event_time:
            if group["first_seen"] is None or str(event_time) < str(group["first_seen"]):
                group["first_seen"] = event_time
            if group["last_seen"] is None or str(event_time) > str(group["last_seen"]):
                group["last_seen"] = event_time

    documents: list[dict] = []
    for group in groups.values():
        best = dict(group["_best"])
        best["confidence"] = group["_best_conf"]
        best["max_confidence"] = group["_best_conf"]
        best["flow_count"] = group["flow_count"]
        best["dst_ip_count"] = len(group["_dst_seen"])
        best["dst_ips"] = group["dst_ips"]
        best["first_seen"] = group["first_seen"]
        best["last_seen"] = group["last_seen"]
        documents.append(best)

    return documents, len(alerts)


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
        self._uri      = mongo_uri
        self._db_name  = db_name
        self._client: MongoClient | None = None
        self._db = None

    # ── Connection ──────────────────────────────────────────────────────────

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

    # ── Write API ───────────────────────────────────────────────────────────

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
            "type":             "spike_alert",
            "src_ip":           src_ip,
            "window_start":     window_start,
            "window_end":       window_end,
            "connection_count": connection_count,
            "total_bytes":      total_bytes,
            "attack_label":     attack_label,
            "severity":         severity,
            "created_at":       datetime.now(timezone.utc),
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
            "type":       "bloom_hit",
            "src_ip":     src_ip,
            "dst_ip":     dst_ip,
            "proto":      proto,
            "service":    service,
            "attack_cat": attack_cat,
            "label":      label,
            "event_time": event_time,
            "created_at": datetime.now(timezone.utc),
        }
        result = self._col(_COL_BLOOM).insert_one(doc)
        logger.debug("Bloom hit written: %s  src=%s  cat=%s", result.inserted_id, src_ip, attack_cat)
        return str(result.inserted_id)

    def write_bloom_hits_bulk(self, hits: list[dict]) -> int:
        """
        Bulk-insert a list of Bloom hit dicts.
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

    def write_ml_alerts_bulk(self, alerts: list[dict]) -> int:
        """
        Bulk-insert ML-scored flow alerts (Pipeline C output).

        Each dict should contain:
            src_ip, dst_ip, attack_type, event_time  -- identity fields
            confidence        float  P(attack) from the binary RF
            severity          str    Critical / High / Medium
            p_bot             float  raw Bot-specialist P(bot)
            p_bot_calibrated  float  prior-corrected P(bot), or None
            bot_routed        bool   whether the Bot specialist was consulted

        By default the input is collapsed per (src_ip, attack_type, severity)
        before insertion -- see ``aggregate_ml_alerts``.  Without this, a single
        benign source IP sending N flows that trip the threshold becomes N alert
        documents, so an unchanged model suddenly looks like N false positives.
        Set ``ML_ALERT_AGGREGATE=false`` to store one document per flow.

        Returns the number of documents inserted.
        """
        if not alerts:
            return 0

        if _ML_ALERT_AGGREGATE:
            alerts, raw_count = aggregate_ml_alerts(alerts)
            logger.info("ML alert aggregation: %d flow rows -> %d documents",
                        raw_count, len(alerts))

        now = datetime.now(timezone.utc)
        for doc in alerts:
            doc.setdefault("type", "ml_alert")
            doc.setdefault("created_at", now)
        result = self._col(_COL_ML).insert_many(alerts)
        logger.info("ML alerts inserted: %d", len(result.inserted_ids))
        return len(result.inserted_ids)

    def write_learning_telemetry(self, record: dict) -> str:
        """Persist one online-learning telemetry record (one streaming batch).

        Small and append-only, one document per batch, so the drift history the
        dashboard plots is a plain time-series read rather than a reconstruction.
        """
        if not record:
            return ""
        doc = dict(record)
        doc.setdefault("type", "learning_telemetry")
        doc.setdefault("created_at", datetime.now(timezone.utc))
        result = self._col(_COL_LEARNING).insert_one(doc)
        return str(result.inserted_id)

    def write_learning_state(self, state: dict) -> bool:
        """Upsert the current online-learning state (one document).

        The detector also checkpoints its full state to a local file; this copy
        exists because the API that serves the dashboard runs in a different
        process (and, in this deployment, a different container) than the Spark
        driver, so a file path on the driver is not readable from the dashboard.
        Without it the learning panel could only show history, never current
        weights.
        """
        if not state:
            return False
        doc = dict(state)
        doc.setdefault("type", "learning_state")
        doc["key"] = _LEARNING_STATE_KEY
        doc["updated_at"] = datetime.now(timezone.utc)
        self._col(_COL_LEARNING_STATE).replace_one(
            {"key": _LEARNING_STATE_KEY}, doc, upsert=True
        )
        return True

    def write_feedback(self, verdict: dict) -> str:
        """Record an analyst verdict on an alert.

        Expected keys: ``src_ip``, ``p_attack`` and ``verdict`` (one of the
        polarities ``online_learning.verdict_label`` understands); ``p_bot``,
        ``attack_type``, ``alert_id`` and ``notes`` are carried through when
        present.  Returns the inserted id as a string.
        """
        doc = dict(verdict)
        doc.setdefault("type", "feedback")
        doc.setdefault("created_at", datetime.now(timezone.utc))
        result = self._col(_COL_FEEDBACK).insert_one(doc)
        logger.info(
            "Feedback recorded: %s verdict=%s p_attack=%s",
            doc.get("src_ip"), doc.get("verdict"), doc.get("p_attack"),
        )
        return str(result.inserted_id)

    def fetch_recent_feedback(self, limit: int = 500, since=None) -> list[dict]:
        """Return recent analyst verdicts, oldest first.

        Ordering is oldest-first so a consumer that keeps a high-water mark sees
        the verdicts in the order they were given -- and the consumer here
        (``OnlineLearningPolicy.learn_feedback``) also de-duplicates by ``_id``,
        so re-reading an overlapping window is harmless.
        """
        query: dict = {}
        if since is not None:
            query["created_at"] = {"$gte": since}
        cursor = (
            self._col(_COL_FEEDBACK)
            .find(query)
            .sort("created_at", ASCENDING)
            .limit(limit)
        )
        out = []
        for doc in cursor:
            doc["_id"] = str(doc.get("_id"))
            out.append(doc)
        return out

    def count_feedback(self) -> dict[str, int]:
        """Count recorded verdicts by verdict string."""
        pipeline = [
            {"$group": {"_id": "$verdict", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return {str(d["_id"]): d["count"] for d in self._col(_COL_FEEDBACK).aggregate(pipeline)}

    def write_manual_review_bulk(self, alerts: list[dict]) -> int:
        """
        Bulk-insert flows routed to manual review instead of auto-flagging.

        Populated by the Infiltration-label suppression mitigation: the
        multiclass RF's "Infiltration" verdict was false 980/986 times on the
        streamed corpus (76% of all remaining FPs), so those flows are parked
        here for a human rather than raising alerts.  These documents never
        appear in the dashboard alert feed.

        Accepts the same dict shape as ``write_ml_alerts_bulk``; ``type`` is
        set to ``manual_review`` and the collection carries the same 72h TTL.
        Returns the number of documents inserted.
        """
        if not alerts:
            return 0
        now = datetime.now(timezone.utc)
        for doc in alerts:
            doc.setdefault("type", "manual_review")
            doc.setdefault("created_at", now)
        result = self._col("manual_review").insert_many(alerts)
        logger.info("Manual-review flows inserted: %d", len(result.inserted_ids))
        return len(result.inserted_ids)

    # ── Query helpers (used by the dashboard) ───────────────────────────────

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

    def get_recent_ml_alerts(self, limit: int = 100) -> list[dict]:
        """Return the most recent ML-scored alerts (newest first)."""
        cursor = (
            self._col(_COL_ML)
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

    def count_ml_alerts_by_type(self) -> dict[str, int]:
        """Aggregate ML alert counts by predicted attack type."""
        pipeline = [
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        return {d["_id"]: d["count"] for d in self._col(_COL_ML).aggregate(pipeline)}

    def count_bloom_hits_by_ip(self, top_n: int = 20) -> list[dict]:
        """Return top N attacker IPs by Bloom hit frequency."""
        pipeline = [
            {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": top_n},
            {"$project": {"ip": "$_id", "count": 1, "_id": 0}},
        ]
        return list(self._col(_COL_BLOOM).aggregate(pipeline))

    def write_nominal_flows_bulk(self, flows: list[dict]) -> int:
        """
        Bulk-insert nominal (benign) flow observations (Pipeline C output).

        The alert collections only ever contain flagged flows, which is why the
        radar never showed a green dot: the benign ~66% of the stream was
        scored and silently dropped.  This collection mirrors a sample of those
        rejected flows so dashboards can display baseline traffic alongside
        threats.  Shape matches an ML alert minus verdict fields, plus:

            p_attack        float  the (low) score that rejected it
            observation     str    always "nominal"

        Subject to the same TTL as alerts.
        """
        if not flows:
            return 0
        now = datetime.now(timezone.utc)
        for doc in flows:
            doc.setdefault("type", "nominal_flow")
            doc.setdefault("created_at", now)
        result = self._col(_COL_NOMINAL).insert_many(flows)
        logger.debug("Nominal flows inserted: %d", len(result.inserted_ids))
        return len(result.inserted_ids)

    def get_recent_nominal_flows(self, limit: int = 100) -> list[dict]:
        """Return the most recent nominal flows (newest first)."""
        cursor = (
            self._col(_COL_NOMINAL)
            .find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        return list(cursor)

    # ── Internals ───────────────────────────────────────────────────────────

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
            # ml_alerts indexes
            self._db[_COL_ML].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_ML].create_index(
                [("src_ip", ASCENDING)], background=True
            )
            self._db[_COL_ML].create_index(
                [("attack_type", ASCENDING)], background=True
            )
            # Nominal (benign) traffic mirror -- see write_nominal_flows.
            self._db[_COL_NOMINAL].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_NOMINAL].create_index(
                [("src_ip", ASCENDING)], background=True
            )
            # Learning telemetry is read as a time series, feedback as a queue.
            self._db[_COL_LEARNING].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_FEEDBACK].create_index(
                [("created_at", ASCENDING)], background=True
            )
            self._db[_COL_FEEDBACK].create_index(
                [("verdict", ASCENDING)], background=True
            )
            self._ensure_ttls()
        except errors.PyMongoError as exc:
            logger.warning("Index creation warning: %s", exc)

    def _ensure_ttls(self) -> None:
        """Apply TTL expiry to time-stamped collections.

        Without this, ``ml_alerts`` grows at ~1.7M docs/day and the dashboard's
        unbounded ``find().sort().limit()`` scans keep paying for it.  Each
        collection expires docs ``TTL_HOURS`` after ``created_at``; Mongo's TTL
        monitor sweeps roughly once a minute, so expiry is near-schedule.

        Note on ``expireAfterSeconds`` changes: MongoDB only rebuilds a TTL
        index's clock when the index is dropped and recreated.  The
        drop-and-recreate below is therefore expected on first run after a
        change, and runs in the background.
        """
        ttl_specs = {
            _COL_ALERTS: TTL_HOURS,
            _COL_BLOOM: TTL_HOURS,
            _COL_ML: TTL_HOURS,
            _COL_NOMINAL: TTL_HOURS,
            "manual_review": TTL_HOURS,
            _COL_LEARNING: LEARNING_TTL_HOURS,
            # NOTE: `feedback` and `learning_state` are deliberately absent.
            # Expiring a verdict would silently shrink the online layer's only
            # human-labelled training set, and the current state must not expire
            # at all -- an absent state document reads as "the detector never
            # learned anything", which is a different claim from "no detector is
            # running".
        }
        for name, hours in ttl_specs.items():
            try:
                coll = self._db[name]
                index_name = "created_at_1"
                existing = coll.list_indexes()
                current = next(
                    (i for i in existing if i["name"] == index_name), None
                )
                wanted = int(hours * 3600)
                if current is None:
                    coll.create_index(
                        [("created_at", ASCENDING)],
                        expireAfterSeconds=wanted,
                        background=True,
                    )
                    logger.info("TTL index on %s created (%.0fh)", name, hours)
                elif int(current.get("expireAfterSeconds", -1)) != wanted:
                    logger.info(
                        "TTL on %s is %ss, wanted %ss -- recreating",
                        name, current.get("expireAfterSeconds"), wanted,
                    )
                    coll.drop_index(index_name)
                    coll.create_index(
                        [("created_at", ASCENDING)],
                        expireAfterSeconds=wanted,
                        background=True,
                    )
            except errors.OperationFailure as exc:
                # e.g. a long-running index build; retry on next connect.
                logger.warning("TTL setup for %s deferred: %s", name, exc)
            except errors.PyMongoError as exc:
                logger.warning("TTL index warning for %s: %s", name, exc)


# ── Standalone test ─────────────────────────────────────────────────────────

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

        # Write a test ml alert
        ml_id = aw.write_ml_alerts_bulk([{
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.5",
            "proto": "TCP", "dst_port": 80,
            "p_attack": 0.91, "attack_type": "DDoS",
            "p_bot": 0.12, "cluster_id": 3,
            "severity": "High", "event_time": "2026-09-06 10:00:10",
        }])
        print(f"Test ML alert inserted: {ml_id} docs")

        # Query back
        print("\nRecent alerts:", aw.get_recent_alerts(limit=2))
        print("Severity counts:", aw.count_alerts_by_severity())
        print("ML alert types:", aw.count_ml_alerts_by_type())
        print("Top IPs:", aw.count_bloom_hits_by_ip(top_n=5))
