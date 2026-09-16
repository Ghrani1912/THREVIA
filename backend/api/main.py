"""
THREVIA API Server
FastAPI backend to serve real-time threat data to the SOC dashboard
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient, DESCENDING
from typing import List, Dict, Any
import asyncio
import os
from datetime import datetime, timezone
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
    fresh_client = MongoClient("mongodb://localhost:27017/")
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
        
        # Detection rate from Phase 3 evaluation
        detection_rate = 74.8  # (Bot 65.26% + Infiltration 68.97% + BENIGN 90.04%) / 3
        
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
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/threats/recent")
async def get_recent_threats(limit: int = 100):
    """Get recent threat events from streaming pipeline"""
    try:
        # Fetch spike alerts (most common currently)
        spike_alerts = list(db.stream_alerts.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(limit))
        
        # Fetch ML alerts
        ml_alerts = list(db.ml_alerts.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(limit))
        
        # Fetch bloom hits
        bloom_hits = list(db.bloom_hits.find(
            {},
            {"_id": 0}
        ).sort("created_at", DESCENDING).limit(limit))
        
        # Combine all and sort by created_at
        all_threats = spike_alerts + ml_alerts + bloom_hits
        all_threats.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return {"threats": all_threats[:limit], "count": len(all_threats[:limit])}
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

@app.get("/api/v1/model/performance")
async def get_model_performance():
    """Get current model performance metrics.
    Updated: v2 class-weighted RF + Tier-2 Bot specialist (Sept 13 2026)
    """
    return {
        "supervised": {
            # Tier-1: Main RF (inverse-frequency class-weighted, Corpus v4)
            "ddos":             {"recall": 99.83, "status": "optimal",  "tier": 1},
            "portscan":         {"recall": 99.91, "status": "optimal",  "tier": 1},
            "benign":           {"recall": 90.04, "status": "optimal",  "tier": 1},
            "ssh_patator":      {"recall": 99.78, "status": "optimal",  "tier": 1},
            "ftp_patator":      {"recall": 97.39, "status": "optimal",  "tier": 1},
            "dos_hulk":         {"recall": 100.00, "status": "optimal", "tier": 1},
            "dos_goldeneye":    {"recall": 89.34, "status": "good",     "tier": 1},
            "dos_slowhttptest": {"recall": 44.75, "status": "marginal", "tier": 1},
            "bot":              {"recall": 68.25, "status": "good",     "tier": 1},
            "infiltration":     {"recall": 68.97, "status": "good",     "tier": 1},
        },
        "tier2_bot_specialist": {
            "model": "rf_bot_binary",
            "routing": "main RF confidence < 0.80",
            "status": "active",
            "note": "Dedicated Bot binary RF (100 trees, depth 12, balanced 50/50)"
        },
        "tier3_infiltration_rules": {
            "rules": ["duration>=60s + bytes/s<=500", "duration>=60s + port in C2 set", "duration>=60s + bwd/fwd ratio>=3x"],
            "status": "active",
            "note": "Overrides BENIGN prediction when Infiltration rules fire"
        },
        "unsupervised": {
            "kmeans_purity": 91.31,
            "status": "optimal"
        },
        "bloom_filter": {
            "false_positive_rate": 0.01,
            "latency_us": 0.12,
            "status": "deterministic"
        },
        "overall": {
            "friday_benign_fpr": 18.24,
            "macro_f1": 88.5,
            "weighted_f1": 99.51,
            "accuracy": 99.51,
            "note": "Macro-F1 estimated post class-weight fix; C2 FPR=18.24% on Friday BENIGN (temporal shift)"
        }
    }

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)




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
