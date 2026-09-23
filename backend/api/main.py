"""
THREVIA API Server
FastAPI backend to serve real-time threat data to the SOC dashboard
"""

from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient, DESCENDING
from typing import List, Dict, Any
import asyncio
import os
import json
from datetime import datetime, timedelta, timezone
import sys

# Ensure the project root is importable when this file is launched directly
# (`python backend/api/main.py` puts backend/api on sys.path, not the root).
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

# Phase 5 graph views. graph_query only needs the stdlib, so this is safe in the
# API venv; a failure degrades to an explicit error instead of killing the app.
try:
    from backend.graph.graph_query import load_ego, load_view
except ImportError as _exc:  # pragma: no cover - defensive
    load_ego = None
    load_view = None
    _GRAPH_QUERY_ERROR = str(_exc)
else:
    _GRAPH_QUERY_ERROR = None

# Severity ladders, read rather than restated. detection_policy is stdlib-only
# (the Spark detector imports it from the same module), so the API shares the
# detector's definition of where a band starts instead of hardcoding a second
# copy of it in the legend payload.
try:
    from backend.realtime.detection_policy import (
        SPIKE_CRITICAL_CONNECTIONS,
        SPIKE_HIGH_CONNECTIONS,
        load_thresholds,
    )
except ImportError as _exc:  # pragma: no cover - defensive
    SPIKE_CRITICAL_CONNECTIONS = None
    SPIKE_HIGH_CONNECTIONS = None
    load_thresholds = None
    _POLICY_IMPORT_ERROR = str(_exc)
else:
    _POLICY_IMPORT_ERROR = None

# The feedback endpoint writes into the online-learning layer's label store. The
# document shape (and the polarity vocabulary) belong to the modules that consume
# them, so the API imports both rather than restating a second copy of either.
try:
    from backend.realtime.alert_writer import AlertWriter
    from backend.realtime.online_learning import LEARNING_STATE_KEY, verdict_label
except ImportError as _exc:  # pragma: no cover - defensive
    AlertWriter = None
    verdict_label = None
    LEARNING_STATE_KEY = "policy"
    _LEARNING_IMPORT_ERROR = str(_exc)
else:
    _LEARNING_IMPORT_ERROR = None

# Spectral-overlay sample grid. Stdlib-only, so this import cannot fail on the
# API's dependency set; see backend/api/bucket_grid.py for why the granularity
# belongs to the source rather than to the caller.
from backend.api.bucket_grid import (
    FIRST_SEEN_FORMAT,
    MODE_SIMULATED,
    bucket_grid,
    bucket_iso_format,
    bucket_labels,
    bucket_seconds_for,
    parse_first_seen,
)

app = FastAPI(title="THREVIA API", version="1.0.0")

# CORS middleware for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")

# MongoDB connection - create fresh connection for each request to avoid caching
def get_db():
    """Get fresh MongoDB connection"""
    client = MongoClient(MONGO_URI)
    return client["threvia"]

# Keep a global client for WebSocket connections
client = MongoClient(MONGO_URI)
db = client["threvia"]

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# API ENDPOINTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.get("/")
async def root():
    return {"status": "THREVIA API Online", "version": "1.0.0"}

@app.get("/api/v1/realtime/counts")
async def get_realtime_counts():
    """Fresh counts - bypasses all caching"""
    from pymongo import MongoClient
    # A separate short-lived client (deliberately not the shared one) but the
    # same URI: this endpoint runs on the host, where MongoDB is published on
    # 27018. A hardcoded 27017 here reported zeros on every compose setup.
    fresh_client = MongoClient(MONGO_URI)
    fresh_db = fresh_client["threvia"]
    
    try:
        spike = fresh_db.stream_alerts.count_documents({})
        ml = fresh_db.ml_alerts.count_documents({})
        bloom = fresh_db.bloom_hits.count_documents({})
        
        return {
            "spike_alerts": spike,
            "ml_alerts": ml,
            "bloom_hits": bloom,
            "total": spike + ml + bloom,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        fresh_client.close()

@app.get("/api/v1/health")
async def health_check():
    """System health check"""
    try:
        # Check MongoDB connection
        db.command('ping')
        mongo_status = "connected"
        
        # Count real alerts
        spike_count = db.stream_alerts.count_documents({})
        ml_count = db.ml_alerts.count_documents({})
        bloom_count = db.bloom_hits.count_documents({})
        
    except Exception as e:
        mongo_status = f"error: {str(e)}"
        spike_count = ml_count = bloom_count = -1
    
    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "mongodb": mongo_status,
        "active_websockets": len(manager.active_connections),
        "realtime_counts": {
            "spike_alerts": spike_count,
            "ml_alerts": ml_count,
            "bloom_hits": bloom_count
        }
    }

@app.get("/api/v1/metrics/summary")
async def get_summary_metrics():
    """Dashboard KPI metrics"""
    try:
        # Get fresh DB connection to avoid caching
        fresh_db = get_db()
        
        # Count real-time alerts from Phase 4 streaming pipeline
        ml_alerts_count = fresh_db.ml_alerts.count_documents({})
        bloom_hits_count = fresh_db.bloom_hits.count_documents({})
        spike_alerts_count = fresh_db.stream_alerts.count_documents({})
        
        # Total threats from streaming pipeline
        total_threats = ml_alerts_count + bloom_hits_count + spike_alerts_count
        
        # Count ML alerts by severity
        critical_alerts = fresh_db.ml_alerts.count_documents({"severity": "Critical"})
        high_alerts = fresh_db.ml_alerts.count_documents({"severity": "High"})
        
        # Count spike alerts by severity
        critical_spikes = fresh_db.stream_alerts.count_documents({"severity": "Critical"})
        
        # Detection rate: read from the measured metrics artifact, same
        # discipline as /api/v1/model/performance.  The old hardcoded 74.8
        # blended the Bot 65.26% / Infiltration 68.97% figures, both of which
        # were later shown to be measured on in-sample or 29/36-row supports.
        # An explicit unknown beats a stale constant.
        detection_rate: float | None = None
        detection_rate_source = "unavailable"
        try:
            with open(MODEL_METRICS_PATH, encoding="utf-8") as _mf:
                _mm = json.load(_mf)
            _dr = _mm.get("pipeline", {}).get("detection_rate")
            if _dr is not None:
                detection_rate = float(_dr)
                detection_rate_source = "measured"
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        
        # Active threats (last 5 minutes)
        from datetime import timedelta
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        active_ml_threats = fresh_db.ml_alerts.count_documents({
            "timestamp": {"$gte": five_min_ago}
        })
        active_spike_threats = fresh_db.stream_alerts.count_documents({
            "created_at": {"$gte": five_min_ago}
        })
        active_threats = active_ml_threats + active_spike_threats
        
        return {
            "total_threats": total_threats,
            "ml_alerts": ml_alerts_count,
            "bloom_hits": bloom_hits_count,
            "spike_alerts": spike_alerts_count,
            "critical_alerts": critical_alerts + critical_spikes,
            "high_alerts": high_alerts,
            "active_threats": active_threats,
            "detection_rate": detection_rate,
            "detection_rate_source": detection_rate_source,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

# Radar sample window. The detector writes ~55 ml_alerts every 10 s and every
# document in a burst shares one created_at, so "the newest N documents" is a
# ten-second snapshot of a single micro-batch, not a picture of the last N
# minutes.  Five minutes covers ~30 bursts.
RADAR_WINDOW_MINUTES = float(os.getenv("RADAR_WINDOW_MINUTES", "5"))

# Severity bands, worst first. A radar is an alerting surface, so the scope is
# meant to fill from the top of this list: a batch's worth of Medium noise must
# not be able to crowd Critical contacts off the display.
RADAR_SEVERITY_ORDER = ("Critical", "High", "Medium")

# created_at ties are broken by src_ip so the same window yields the same
# contacts on every request. Without a secondary key the winner among tied
# documents is decided by index scan direction, which is not a decision anyone
# made -- see _radar_sample.
_RADAR_SORT = [("created_at", DESCENDING), ("src_ip", 1)]


def _radar_sample(collection, limit: int, window_minutes, bands=None, projection=None):
    """Newest ``limit`` documents inside ``window_minutes``, optionally per band.

    ``find().sort("created_at", -1).limit(n)`` reads like "the newest n", but
    every document in a micro-batch shares a timestamp, and among documents that
    compare equal the order is whatever the plan happens to produce.  Measured on
    this stack: a descending ``created_at`` index scan returns tied documents in
    *reverse insertion* order, and the alert writer inserts each batch grouped by
    ``(src_ip, attack_type, severity)`` with the Critical/DDoS groups first.  So
    "the newest n" was the batch's Medium *tail* (Web Attack, Bot, SSH-Patator),
    and the radar drew a near-total absence of Critical contacts while ~40% of
    every batch was Critical.

    Passing ``bands`` samples each band separately, which makes the composition
    of the result a property of this function instead of of tie order.  Returns
    ``(docs, window_minutes_used)``; a window that comes back empty is retried
    without one, because a stopped pipeline is not the same thing as no alerts
    and a scope that empties itself reads as "nothing is happening".
    """
    if projection is None:
        projection = {"_id": 0}

    def fetch(since):
        if not bands:
            query = {"created_at": {"$gte": since}} if since else {}
            return list(collection.find(query, projection).sort(_RADAR_SORT).limit(limit))
        per_band = max(limit // len(bands), 1)
        docs = []
        for band in bands:
            query = {"severity": band}
            if since:
                query["created_at"] = {"$gte": since}
            docs.extend(
                collection.find(query, projection).sort(_RADAR_SORT).limit(per_band)
            )
        return docs

    if window_minutes:
        since = datetime.utcnow() - timedelta(minutes=float(window_minutes))
        docs = fetch(since)
        if docs:
            return docs, window_minutes
    return fetch(None), None


@app.get("/api/v1/threats/recent")
async def get_recent_threats(limit: int = 100):
    """Get recent threat events from streaming pipeline.

    ``gate`` ships with the feed because the radar's legend is drawn from the same
    contacts these documents produce: a legend of severity bands is a claim about
    *how this feed was graded*, and it has to arrive with the feed to stay true.

    The attack feeds are sampled per severity band out of ``RADAR_WINDOW_MINUTES``
    rather than by "newest n documents"; ``window_minutes`` in the response says
    which window was used (``None`` = the pipeline is idle and the newest stored
    contacts were returned instead).  See ``_radar_sample`` for why the obvious
    query is not a sample at all.
    """
    try:
        # Per-collection quotas: ml_alerts arrive in ~100-doc bursts, so an
        # unbalanced fetch lets one burst evict every other class from the
        # newest-N window (the radar would show zero benign blips).
        # Fetch a sample of nominal (benign) traffic so the radar can render
        # baseline flows, not just alerts.
        n_nominal = max(limit // 3, 10)
        n_spike = max((limit - n_nominal) // 4, 5)
        bloom_limit = max(n_spike // 2, 3)
        n_ml = max(limit - n_nominal - n_spike - bloom_limit, 1)

        ml_alerts, window_minutes = _radar_sample(
            db.ml_alerts, n_ml, RADAR_WINDOW_MINUTES, bands=RADAR_SEVERITY_ORDER)
        spike_alerts, _ = _radar_sample(
            db.stream_alerts, n_spike, RADAR_WINDOW_MINUTES, bands=RADAR_SEVERITY_ORDER)
        bloom_hits, _ = _radar_sample(db.bloom_hits, bloom_limit, RADAR_WINDOW_MINUTES)
        nominal, _ = _radar_sample(db.nominal_flows, n_nominal, RADAR_WINDOW_MINUTES)
        
        # Combine. Do NOT re-sort by time and slice to `limit` here: ml_alerts
        # are bulk-inserted in ~100-doc bursts sharing one timestamp while
        # nominal flows trickle in continuously, so a time-ordered slice
        # oscillates between all-alerts (just after a burst) and all-nominal
        # (just before one). The per-class quotas above ARE the mix; return
        # them all and let the newest-docs-per-class guarantee stand.
        all_threats = spike_alerts + ml_alerts + bloom_hits + nominal
        def _sort_key(x):
            v = x.get("created_at")
            if isinstance(v, datetime):
                return (1, v.isoformat())
            return (0, str(v) if v else "")
        # Stable sort for display ordering only; every doc is returned.
        all_threats.sort(key=_sort_key, reverse=True)
        
        return {
            "threats": all_threats,
            "count": len(all_threats),
            "window_minutes": window_minutes,
            "gate": _deployed_gate(),
        }
    except Exception as e:
        return {"error": str(e), "threats": []}

@app.get("/api/v1/threats/{threat_id}")
async def get_threat_details(threat_id: str):
    """Get detailed information about a specific threat"""
    try:
        from bson.objectid import ObjectId
        threat = db.security_events.find_one({"_id": ObjectId(threat_id)}, {"_id": 0})
        if not threat:
            return {"error": "Threat not found"}
        
        # Get graph data for source IP
        ip = threat.get("source_ip")
        graph_data = {}
        if ip:
            node = db.graph_nodes.find_one({"ip": ip}, {"_id": 0})
            if node:
                graph_data = node
        
        return {
            "threat": threat,
            "graph_data": graph_data
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/ip/{ip_address}/reputation")
async def get_ip_reputation(ip_address: str):
    """Get IP reputation and Bloom Filter status"""
    try:
        # Check Bloom Filter hits
        bloom_hits = list(db.bloom_hits.find(
            {"src_ip": ip_address},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(10))
        
        # Get graph node data
        node_data = db.graph_nodes.find_one({"ip": ip_address}, {"_id": 0})
        
        # Get threat history
        threat_history = list(db.security_events.find(
            {"source_ip": ip_address},
            {"_id": 0}
        ).sort("timestamp", DESCENDING).limit(20))
        
        is_malicious = len(bloom_hits) > 0 or (node_data and node_data.get("is_attacker", False))
        
        return {
            "ip": ip_address,
            "is_malicious": is_malicious,
            "bloom_hits": len(bloom_hits),
            "bloom_details": bloom_hits,
            "graph_data": node_data or {},
            "threat_history": threat_history,
            "reputation_score": node_data.get("danger_score", 0) if node_data else 0
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/graph/nodes")
async def get_graph_nodes(limit: int = 1000):
    """Get network graph nodes"""
    try:
        nodes = list(db.graph_nodes.find(
            {},
            {"_id": 0}
        ).sort("pagerank", DESCENDING).limit(limit))
        
        return {"nodes": nodes, "count": len(nodes)}
    except Exception as e:
        return {"error": str(e), "nodes": []}

@app.get("/api/v1/graph/edges")
async def get_graph_edges(limit: int = 5000):
    """Get network graph edges"""
    try:
        edges = list(db.graph_edges.find(
            {},
            {"_id": 0}
        ).limit(limit))
        
        return {"edges": edges, "count": len(edges)}
    except Exception as e:
        return {"error": str(e), "edges": []}

@app.get("/api/v1/graph/node/{ip_address}")
async def get_node_details(ip_address: str):
    """Get detailed graph analytics for a specific IP"""
    try:
        node = db.graph_nodes.find_one({"ip": ip_address}, {"_id": 0})
        if not node:
            return {"error": "Node not found"}
        
        # Get connected edges
        edges_out = list(db.graph_edges.find({"src_ip": ip_address}, {"_id": 0}).limit(50))
        edges_in = list(db.graph_edges.find({"dst_ip": ip_address}, {"_id": 0}).limit(50))
        
        return {
            "node": node,
            "edges_out": edges_out,
            "edges_in": edges_in,
            "total_edges": len(edges_out) + len(edges_in)
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/analytics/attacks-by-type")
async def get_attacks_by_type():
    """Get attack distribution by type"""
    try:
        pipeline = [
            {"$group": {
                "_id": "$predicted_label",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]
        
        result = list(db.security_events.aggregate(pipeline))
        
        return {
            "attack_types": [
                {"type": r["_id"], "count": r["count"]}
                for r in result
            ]
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/analytics/timeline")
async def get_timeline_data(hours: int = 24):
    """Get time-series attack data"""
    try:
        from datetime import timedelta
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_time}}},
            {"$group": {
                "_id": {
                    "hour": {"$dateToString": {"format": "%Y-%m-%dT%H:00:00", "date": "$timestamp"}},
                    "attack_type": "$predicted_label"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.hour": 1}}
        ]
        
        result = list(db.security_events.aggregate(pipeline))
        
        return {
            "timeline": [
                {
                    "timestamp": r["_id"]["hour"],
                    "attack_type": r["_id"]["attack_type"],
                    "count": r["count"]
                }
                for r in result
            ]
        }
    except Exception as e:
        return {"error": str(e)}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Raw multiclass verdicts are finer-grained than the spectral overlay's traces,
# so they roll up into the CIC-2017 attack families the view draws one line per:
# the four DoS variants are one DoS vector, and the Patators plus the Web-Attack
# brute force are one Brute Force vector.
ATTACK_FAMILY_MAP = {
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "SSH-Patator": "Brute Force",
    "FTP-Patator": "Brute Force",
    "Web Attack - Brute Force": "Brute Force",
    "Web Attack": "Brute Force",
    "Web Attack - XSS": "XSS",
    "Web Attack - Sql Injection": "Sql Injection",
    "Botnet": "Bot",
}


def _attack_family(raw_label):
    raw = (raw_label or "").strip()
    if not raw:
        return "Unknown"
    return ATTACK_FAMILY_MAP.get(raw, raw)


# The deployed operating point travels with the gate model, and the same
# artifact is what the runtime policy loads (backend/realtime/detection_policy.py).
# Read it rather than restating the cut, so the dashboard cannot drift from the
# model that is actually scoring traffic.
THRESHOLDS_PATH = os.getenv(
    "THRESHOLDS_PATH",
    os.path.join(_ROOT_DIR, "backend", "realtime", "thresholds.json"),
)

# Windowed spike gate for stream_alerts -- mirrors the default in
# backend/realtime/streaming_detector.py (SPIKE_THRESHOLD).
SPIKE_THRESHOLD = int(os.getenv("SPIKE_THRESHOLD", "50"))


def _rel_thresholds_path() -> str:
    """Project-relative thresholds path, for display."""
    try:
        return os.path.relpath(THRESHOLDS_PATH, _ROOT_DIR).replace("\\", "/")
    except ValueError:  # pragma: no cover - different drive on Windows
        return THRESHOLDS_PATH


def _deployed_gate():
    """The measured thresholds behind this view, with their provenance.

    Both severity ladders travel together because the dashboard draws one legend
    for both: ``severity_band`` grades ``P(attack)`` (the ``ml_alerts`` feed,
    ``detection_policy.severity_for``) and ``spike_severity_band`` grades
    ``connection_count`` (the ``stream_alerts`` feed,
    ``detection_policy.spike_severity_for``).  The bands are *loaded*, not
    restated, so a legend cannot advertise a cut the pipeline does not use.

    ``resolved_from`` is the policy's own provenance string and matters for
    honesty: ``load_thresholds`` never raises -- an unreadable artifact silently
    falls back to the module defaults -- so ``resolved_from == "defaults"`` is
    the only signal that the numbers below are NOT the deployed calibration.
    """
    gate = {
        "spike_threshold_conn_per_window": SPIKE_THRESHOLD,
        "source": _rel_thresholds_path(),
        "spike_severity_band": {
            "high": SPIKE_HIGH_CONNECTIONS,
            "critical": SPIKE_CRITICAL_CONNECTIONS,
        },
    }
    if SPIKE_HIGH_CONNECTIONS is None:
        # Import failed: say so rather than publishing nulls a legend would
        # render as "≥0 conn/window" and quietly mislead.
        gate["spike_severity_band_error"] = _POLICY_IMPORT_ERROR

    if load_thresholds is None:
        gate["thresholds_error"] = _POLICY_IMPORT_ERROR
    else:
        thresholds = load_thresholds(THRESHOLDS_PATH)
        gate.update({
            "attack_threshold": thresholds.attack_threshold,
            "severity_band": {
                "medium": thresholds.severity_medium,
                "high": thresholds.severity_high,
                "critical": thresholds.severity_critical,
            },
            "resolved_from": thresholds.source,
        })
        if thresholds.source == "defaults":
            gate["severity_band_warning"] = (
                f"{_rel_thresholds_path()} unreadable: bands are the policy "
                "module defaults, not the deployed calibration"
            )

    try:
        with open(THRESHOLDS_PATH, "r", encoding="utf-8") as fh:
            artifact = json.load(fh)
    except Exception as exc:
        gate["error"] = str(exc)
    else:
        if isinstance(artifact, dict):
            gate["generated_at"] = artifact.get("generated_at")
            gate["measured_recall_pct"] = artifact.get("measured_recall_pct")
    return gate


@app.get("/api/v1/analytics/waterfall")
async def get_waterfall_data(minutes: int = 60, mode: str = "live"):
    """Alert volume over time on a uniform bucket grid, split by attack type.

    ``mode=live`` (default) aggregates ``stream_alerts`` -- the alerts the
    deployed policy actually escalated, bucketed per minute by their write time.
    The operating cut is calibrated so that only DDoS clears it on this corpus,
    which is why the live overlay renders a single vector.

    ``mode=simulated`` aggregates ``ml_alerts`` instead: every raw ML verdict,
    *before* alert aggregation and the threshold gate.  That is the full
    multi-vector overlay this view was built to draw, labelled "simulated"
    because it is the detector's pre-gate output rather than escalated alerts.
    It is bucketed by ``first_seen`` -- the event time each document describes --
    at 10-second granularity, because unlike a per-minute stream_alerts window,
    an ml_alerts document carries a real event clock.  A 60-minute window is then
    361 samples rather than 61.

    Both modes return the same three things: ``waterfall`` (only the non-empty
    (bucket, family) rows), ``timestamps`` (the complete uniform grid, including
    windows nothing fired in) and ``bucket_seconds``.  The dashboard plots on the
    returned grid, so a trace, a cross-correlation lag and the STFT spectrogram
    all share one real time base instead of one rebuilt from the sparse rows.
    """
    try:
        from datetime import timedelta
        simulated = mode == MODE_SIMULATED
        bucket_seconds = bucket_seconds_for(mode)
        bucket_iso = bucket_iso_format(bucket_seconds)
        collection = db.ml_alerts if simulated else db.stream_alerts
        type_field = "$attack_type" if simulated else "$attack_label"
        flow_field = "$flow_count" if simulated else "$connection_count"

        start_time = datetime.utcnow() - timedelta(minutes=minutes)

        # Fallback to the latest available data window if no recent data exists.
        # The two modes run on different clocks -- stream_alerts buckets by when
        # the alert was written, the simulated overlay by the event it describes
        # -- so each falls back on the field it buckets by.  first_seen is a
        # fixed-width string, so its maximum is the lexicographic maximum.
        if simulated:
            latest = collection.find_one(
                sort=[("first_seen", DESCENDING)], projection={"first_seen": 1}
            )
            latest_event = parse_first_seen((latest or {}).get("first_seen"))
            if latest_event and latest_event < start_time:
                start_time = latest_event - timedelta(minutes=minutes)
        else:
            latest_record = collection.find_one(sort=[("created_at", -1)])
            if latest_record and latest_record.get("created_at") and latest_record["created_at"] < start_time:
                start_time = latest_record["created_at"] - timedelta(minutes=minutes)

        # The grid every series is drawn and transformed on: 60 min at 10 s is
        # 361 samples, at 1 min it is 61.
        grid = bucket_grid(start_time, minutes, bucket_seconds)
        timestamps = bucket_labels(grid, bucket_seconds)

        if simulated:
            # Bucket on first_seen, not created_at: created_at is when the write
            # landed, and the two can sit hours apart in this corpus.  The range
            # match stays on the raw string (see bucket_grid.FIRST_SEEN_FORMAT)
            # so the date conversion only runs on in-window documents, and the
            # conversion is what lets $dateTrunc cut the 10-second bins.
            pipeline = [
                {"$match": {"first_seen": {"$gte": start_time.strftime(FIRST_SEEN_FORMAT)}}},
                {"$addFields": {"_event_ts": {"$dateFromString": {
                    "dateString": "$first_seen",
                    "format": FIRST_SEEN_FORMAT,
                    "onError": None,
                    "onNull": None,
                }}}},
                # A malformed or absent first_seen yielded null above; it is
                # excluded here rather than being bucketed at the epoch.
                {"$match": {"_event_ts": {"$gte": start_time, "$lte": grid[-1]}}},
                {"$group": {
                    "_id": {
                        "bucket": {"$dateToString": {
                            "format": bucket_iso,
                            "date": {"$dateTrunc": {
                                "date": "$_event_ts",
                                "unit": "second",
                                "binSize": bucket_seconds,
                            }},
                        }},
                        "attack_type": type_field
                    },
                    "count": {"$sum": 1},
                    "connections": {"$sum": flow_field},
                    # total_bytes exists only on stream_alerts, so the byte basis
                    # for a bandwidth axis is a live-mode quantity.  ml_alerts
                    # carries no byte or packet fields at all, which is why the
                    # simulated overlay falls back to flow counts.
                    "bytes": {"$sum": "$total_bytes"},
                }},
                {"$sort": {"_id.bucket": 1}}
            ]
        else:
            pipeline = [
                {"$match": {"created_at": {"$gte": start_time}}},
                {"$group": {
                    "_id": {
                        "minute": {"$dateToString": {"format": bucket_iso, "date": "$created_at"}},
                        "attack_type": type_field
                    },
                    "count": {"$sum": 1},
                    "connections": {"$sum": flow_field},
                    "bytes": {"$sum": "$total_bytes"},
                }},
                {"$sort": {"_id.minute": 1}}
            ]

        result = list(collection.aggregate(pipeline))

        # Collapse the fine-grained raw verdicts onto the families the overlay
        # draws one trace per, keeping one row per (bucket, family).
        merged: Dict[Any, Dict[str, Any]] = {}
        for r in result:
            key = (r["_id"]["bucket" if simulated else "minute"],
                   _attack_family(r["_id"].get("attack_type")))
            row = merged.setdefault(key, {
                "timestamp": key[0],
                "attack_type": key[1],
                "count": 0,
                "connections": 0,
                "bytes": 0.0,
            })
            row["count"] += r["count"]
            row["connections"] += r.get("connections") or 0
            row["bytes"] += r.get("bytes") or 0

        return {
            "mode": "simulated" if simulated else "live",
            "source": "ml_alerts" if simulated else "stream_alerts",
            "window_minutes": minutes,
            # Sample spacing and the full sample grid.  The simulated overlay is
            # resolved at 10 s off ml_alerts.first_seen; the live feed is a
            # per-minute aggregate and stays at 60 s.  Both are labelled as such
            # by the dashboard, and neither is ever resampled to the other's rate.
            "bucket_seconds": bucket_seconds,
            "samples": len(timestamps),
            "timestamps": timestamps,
            "bucket_time_field": "first_seen" if simulated else "created_at",
            # Whether the caller can render an ingress-bandwidth axis.  Summed
            # bytes are a per-bucket total, so Gbps = bytes * 8 / bucket_seconds
            # / 1e9.
            "bytes_available": not simulated,
            "gate": _deployed_gate(),
            "waterfall": sorted(merged.values(), key=lambda d: (d["timestamp"], d["attack_type"])),
        }
    except Exception as e:
        return {"error": str(e)}

# Model performance is a *measured* artifact, not a constant.  The endpoint used
# to return hardcoded numbers, several of which came from a known-broken
# evaluation path (the 18.24% C2 FPR figure was itself later traced to a
# missing Fwd-Header-Length rename in the evaluation scripts -- the documented
# 12.87% was the faithful one), so the dashboard could disagree with the models
# actually deployed.  ``backend/ml/train_clean_corpus.py`` now emits this file on
# every retrain; see documentation/FINAL_MODEL_EVALUATION.md.
MODEL_METRICS_PATH = os.getenv(
    "MODEL_METRICS_PATH",
    os.path.join(_ROOT_DIR, "backend", "ml", "model_metrics.json"),
)


@app.get("/api/v1/model/performance")
async def get_model_performance():
    """Measured model evaluation metrics, read from the retrain artifact.

    Returns ``source: "measured"`` with the artifact's contents when the file
    exists.  When it does not, returns ``source: "unavailable"`` and no recall
    numbers at all -- an explicit gap is preferable to stale constants that
    look like telemetry.
    """
    import json

    try:
        with open(MODEL_METRICS_PATH, "r", encoding="utf-8") as fh:
            metrics = json.load(fh)
    except FileNotFoundError:
        return {
            "source": "unavailable",
            "path": MODEL_METRICS_PATH,
            "note": (
                "No measured metrics artifact. Re-run the retrain "
                "(backend/ml/train_clean_corpus.py) to generate it."
            ),
        }
    except Exception as exc:  # malformed artifact should not 500 the dashboard
        return {
            "source": "unavailable",
            "path": MODEL_METRICS_PATH,
            "error": str(exc),
        }

    metrics["source"] = "measured"
    metrics["path"] = MODEL_METRICS_PATH
    return metrics

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# ONLINE LEARNING
# ────────────────────────────────────────────────────────────────────────────────

# Beyond this age the state document describes a detector that is not running, and
# the dashboard says so instead of plotting a stale cut as if it were live.
LEARNING_STALE_SECONDS = float(os.getenv("LEARNING_STALE_SECONDS", "120"))


def _seconds_since(moment) -> float | None:
    """Age in seconds of a Mongo datetime (naive UTC) or ISO string, else None."""
    if moment is None:
        return None
    if isinstance(moment, str):
        try:
            moment = datetime.fromisoformat(moment.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(moment, datetime):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - moment).total_seconds()


@app.get("/api/v1/learning/status")
async def get_learning_status(history: int = 60):
    """What the online-learning layer is doing, and what it has learned.

    Reads the state document the detector upserts (``learning_state``) plus the
    per-batch telemetry series, because the detector runs in a different process --
    its checkpoint file is not reachable from here.

    ``source: "unavailable"`` means no detector has ever reported state; it is an
    explicit gap, not a zeroed-out panel.  ``stale: true`` means the last report is
    older than the staleness window, so the numbers describe a detector that has
    stopped rather than one that is merely idle.

    Uses a short server-selection timeout rather than the driver default: this
    endpoint is polled every few seconds by the dashboard, and the default 30 s
    wait turns an unreachable MongoDB into a stack of pending requests instead of
    one honest "unavailable".
    """
    fresh = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)["threvia"]
    try:
        state = fresh["learning_state"].find_one({"key": LEARNING_STATE_KEY}, {"_id": 0})
        series = list(
            fresh["learning_telemetry"]
            .find({}, {"_id": 0})
            .sort("created_at", DESCENDING)
            .limit(max(1, min(int(history), 500)))
        )
        verdicts = {
            str(d["_id"]): d["count"]
            for d in fresh["feedback"].aggregate(
                [{"$group": {"_id": "$verdict", "count": {"$sum": 1}}},
                 {"$sort": {"count": -1}}]
            )
        }
    except Exception as exc:  # a Mongo outage should not 500 the dashboard
        return {"source": "unavailable", "error": str(exc)}
    finally:
        fresh.client.close()

    # Oldest-first for plotting: a time series drawn right-to-left is a chart whose
    # x axis means the opposite of what it looks like.
    series.reverse()

    if not state:
        return {
            "source": "unavailable",
            "note": (
                "No detector has reported learning state. Start the streaming "
                "detector (backend/realtime/streaming_detector.py), or set "
                "ONLINE_LEARNING=off to run the frozen operating point deliberately."
            ),
            "history": series,
            "feedback_recorded": verdicts,
        }

    age = _seconds_since(state.get("updated_at") or state.get("saved_at"))
    state["source"] = "measured"
    state["age_seconds"] = age
    state["stale"] = age is not None and age > LEARNING_STALE_SECONDS
    state["history"] = series
    state["feedback_recorded"] = verdicts
    state["feedback_total"] = int(sum(verdicts.values()))
    return state


@app.post("/api/v1/feedback")
async def submit_feedback(payload: Dict[str, Any] = Body(...)):
    """Record an analyst verdict on an alert; the only source of human labels.

    Body: ``{src_ip, p_attack, verdict, p_bot?, attack_type?, notes?}``, where
    ``verdict`` is one of the polarities the online layer understands
    (``confirmed`` / ``false_positive`` and their synonyms).  Unusable verdicts are
    rejected rather than stored as an ambiguous row the learner would have to guess
    at, and a verdict with no score is rejected because it cannot teach a
    calibrator anything.
    """
    if AlertWriter is None or verdict_label is None:
        return {"ok": False, "error": f"feedback store unavailable: {_LEARNING_IMPORT_ERROR}"}

    verdict = payload.get("verdict")
    label = verdict_label(verdict)
    if label is None:
        return {"ok": False, "error": f"unusable verdict {verdict!r}"}

    p_attack = payload.get("p_attack")
    if p_attack is None:
        return {"ok": False, "error": "p_attack is required (the score the verdict is about)"}
    try:
        p_attack = float(p_attack)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"p_attack must be numeric, got {payload.get('p_attack')!r}"}
    if not 0.0 <= p_attack <= 1.0:
        return {"ok": False, "error": "p_attack must be in [0, 1]"}

    doc = {
        "src_ip": payload.get("src_ip"),
        "p_attack": p_attack,
        "verdict": str(verdict),
        "source": payload.get("source") or "analyst",
        "attack_type": payload.get("attack_type"),
        "alert_id": payload.get("alert_id"),
        "notes": payload.get("notes"),
    }
    for optional in ("p_bot", "threshold_used"):
        value = payload.get(optional)
        if value is None:
            continue
        try:
            doc[optional] = float(value)
        except (TypeError, ValueError):
            pass

    writer = AlertWriter(mongo_uri=MONGO_URI)
    try:
        inserted = writer.write_feedback(doc)
    except Exception as exc:
        return {"ok": False, "error": f"could not store verdict: {exc}"}
    finally:
        writer.close()

    return {
        "ok": True,
        "id": inserted,
        "label": label,
        "note": (
            "Consumed by the streaming detector's online-learning layer on its next "
            "feedback poll; it re-ranks the score band this verdict belongs to, "
            "bounded by the residual cap."
        ),
    }


# ────────────────────────────────────────────────────────────────────────────────
# WEBSOCKET FOR REAL-TIME UPDATES
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.websocket("/api/v1/threats/live")
async def websocket_threats(websocket: WebSocket):
    """WebSocket endpoint for real-time threat streaming"""
    await manager.connect(websocket)
    try:
        # Send initial data - get recent alerts from all three collections
        spike_alerts = list(db.stream_alerts.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(5))
        
        ml_alerts = list(db.ml_alerts.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(5))
        
        bloom_hits = list(db.bloom_hits.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(5))
        
        all_threats = spike_alerts + ml_alerts + bloom_hits
        # Sort by created_at
        all_threats.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        await websocket.send_json({
            "type": "initial",
            "threats": all_threats[:10]
        })
        
        # Keep connection alive and stream updates
        last_check = datetime.now(timezone.utc)
        while True:
            await asyncio.sleep(2)
            
            # Get latest threats since last check
            new_threats = []
            
            # Check each collection
            for threat in db.ml_alerts.find({"created_at": {"$gt": last_check}}, {"_id": 0}):
                new_threats.append(threat)
            for threat in db.stream_alerts.find({"created_at": {"$gt": last_check}}, {"_id": 0}):
                new_threats.append(threat)
            for threat in db.bloom_hits.find({"created_at": {"$gt": last_check}}, {"_id": 0}):
                new_threats.append(threat)
            
            last_check = datetime.now(timezone.utc)
            
            if new_threats:
                await websocket.send_json({
                    "type": "update",
                    "threats": new_threats
                })
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SERVE STATIC DASHBOARD
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# Mount static files directory
dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "dashboard")
if os.path.exists(dashboard_path):
    app.mount("/static", StaticFiles(directory=dashboard_path), name="static")

@app.get("/dashboard")
async def serve_dashboard():
    """Serve the SOC dashboard HTML"""
    dashboard_file = os.path.join(dashboard_path, "index.html")
    if os.path.exists(dashboard_file):
        return FileResponse(dashboard_file)
    return {"error": "Dashboard not found"}




# ─────────────────────────────────────────────────────────────────────────────
# GRAPH API ENDPOINTS (Phase 5)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/graph/topology")
async def get_graph_topology():
    """
    Get network topology graph data for visualization.
    Returns nodes and edges with analytics (PageRank, danger scores, communities).
    """
    try:
        # Try to load from JSON export first (fastest)
        import json
        from pathlib import Path
        
        json_path = Path(__file__).parent.parent / "graph" / "graph_export.json"
        if json_path.exists():
            with open(json_path, 'r') as f:
                return json.load(f)
        
        # Fallback: build from MongoDB collections
        nodes = list(db.graph_nodes.find({}, {"_id": 0}).limit(1000))
        edges = list(db.graph_edges.find({}, {"_id": 0}).limit(5000))
        meta = db.graph_meta.find_one({}, {"_id": 0}) or {}
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": meta
        }
    except Exception as e:
        return {"error": str(e), "nodes": [], "edges": [], "metadata": {}}

@app.get("/api/v1/graph/node/{ip_address}")
async def get_node_details(ip_address: str):
    """Get detailed information about a specific node in the graph."""
    try:
        node = db.graph_nodes.find_one({"ip": ip_address}, {"_id": 0})
        if not node:
            return {"error": "Node not found"}
        
        # Get edges connected to this node
        outgoing = list(db.graph_edges.find({"src": ip_address}, {"_id": 0}).limit(50))
        incoming = list(db.graph_edges.find({"dst": ip_address}, {"_id": 0}).limit(50))
        
        return {
            "node": node,
            "outgoing_edges": outgoing,
            "incoming_edges": incoming,
            "out_degree": len(outgoing),
            "in_degree": len(incoming)
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/graph/communities")
async def get_communities():
    """Get all detected communities with their members and characteristics."""
    try:
        communities = list(db.graph_communities.find({}, {"_id": 0}))
        return {"communities": communities, "count": len(communities)}
    except Exception as e:
        return {"error": str(e), "communities": []}


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — ATTACKER-CENTRED TOPOLOGY VIEWS
# ─────────────────────────────────────────────────────────────────────────────
# /api/v1/graph/view supersedes /api/v1/graph/topology for the dashboard. It
# returns a targeted *subgraph* rather than the whole graph:
#
#   scope=threat (default) : malicious communities (top k) ∪ attackers
#                            ∪ every node directly connected to an attacker
#   scope=full             : sampled macro view (structure-spotting only)
#
# Ranked nodes by danger score alone would sever exactly the edges that make a
# campaign visible, so selection is structural, never score-thresholded.

def _graph_unavailable():
    return {
        "error": _GRAPH_QUERY_ERROR or "graph query layer unavailable",
        "nodes": [],
        "edges": [],
        "communities": [],
        "metadata": {},
    }


@app.get("/api/v1/graph/view")
async def get_graph_view(scope: str = "threat", k: int = 3, max_nodes: int = 0):
    """
    View-ready subgraph for the SOC topology workspace.

    scope=threat  Level 0 — top-k malicious clusters, fully intact
    scope=full    Level 2 — sampled macro view of the entire graph
    k             number of malicious communities to expand (<=0 → all)
    """
    if load_view is None:
        return _graph_unavailable()
    try:
        return load_view(db, scope=scope, k=k, max_nodes=max_nodes or None)
    except Exception as e:
        return {"error": str(e), "nodes": [], "edges": [], "communities": [], "metadata": {}}

@app.get("/api/v1/graph/ego/{ip_address}")
async def get_graph_ego(ip_address: str, limit: int = 200):
    """
    Level 1 expansion — one node plus its 1-hop neighbourhood, whether or not
    any of it sits inside a flagged community. This answers the actual
    investigative question: "who else is this attacker talking to?"
    """
    if load_ego is None:
        return _graph_unavailable()
    try:
        return load_ego(ip_address, db, limit=limit)
    except Exception as e:
        return {"error": str(e), "nodes": [], "edges": [], "communities": [], "metadata": {}}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)

