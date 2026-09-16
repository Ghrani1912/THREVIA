# THREVIA SOC Dashboard

**Professional Security Operations Center Interface**

A military-grade, real-time cybersecurity intelligence dashboard featuring polar attack radar, live threat streaming, and honest ML evaluation metrics.

---

## Features

### 🎯 Polar Attack Radar
- Real-time rotating sweep visualization
- Spatial threat positioning (azimuth/distance)
- Color-coded severity (Critical, High, Medium)
- Interactive target selection
- Keyboard controls ([SPACE] to freeze)

### 📡 Live Telemetry Stream
- WebSocket real-time threat feed
- Filterable incident list (IP, protocol, attack type)
- Click-to-drill-down forensics
- Graph analytics integration (PageRank, degree, community)
- Bloom Filter hit verification

### 🔬 Honest ML Evaluation
- **NO GREENWASHING**: Shows actual model performance
- DDoS: 99.8% ✅ (Optimal)
- PortScan: 99.3% ✅ (Optimal)
- Slowhttptest: 44.8% ⚠️ (Marginal)
- Bot: 0.3% ❌ (Degraded)
- Infiltration: 0.0% ❌ (Failed/Blind)
- Bloom Filter: 100% ✅ (O(1) lookup)

### 📊 MITRE ATT&CK Kill-Chain Matrix
- 7-phase tactical overview
- Real-time phase status
- MITRE technique mapping

---

## Architecture

```
Frontend (HTML/JS)          Backend (FastAPI)        Data Layer
┌─────────────────┐         ┌─────────────────┐     ┌──────────────┐
│  index.html     │ ◄─HTTP─►│   main.py       │     │  MongoDB     │
│  app.js         │         │                 │ ◄───┤              │
│  (Radar Canvas) │ ◄─WS──►│   /api/v1/...   │     │  HDFS        │
└─────────────────┘         └─────────────────┘     └──────────────┘
```

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/health` | GET | System health check |
| `/api/v1/metrics/summary` | GET | Dashboard KPIs |
| `/api/v1/threats/recent` | GET | Recent threat events |
| `/api/v1/threats/live` | WebSocket | Real-time threat stream |
| `/api/v1/ip/{ip}/reputation` | GET | IP reputation + Bloom Filter |
| `/api/v1/graph/node/{ip}` | GET | Graph analytics for IP |
| `/api/v1/model/performance` | GET | Model evaluation metrics |

---

## Quick Start

### Option 1: Using Pipeline Script (Recommended)

```powershell
# Run Phase 6 (installs dependencies automatically)
.\run_threvia_pipeline.ps1 -Phases 6
```

### Option 2: Manual Start

```powershell
# 1. Install dependencies
cd backend/api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Start MongoDB (if not running)
docker start threvia-mongo

# 3. Start API server
python main.py
```

**Dashboard:** http://localhost:8000/dashboard  
**API Docs:** http://localhost:8000/docs

---

## Configuration

### API Base URL

Dashboard auto-detects environment:
- **Localhost:** `http://localhost:8000`
- **Production:** Uses current host

To override, edit `dashboard/app.js`:
```javascript
const API_BASE = 'http://your-server:8000';
const WS_BASE = 'ws://your-server:8000';
```

### MongoDB Connection

Edit `backend/api/main.py`:
```python
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
```

Or set environment variable:
```powershell
$env:MONGO_URI = "mongodb://your-server:27017/"
```

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `[SPACE]` | Freeze/Resume radar sweep |
| `[/]` | Focus search filter |
| `[ESC]` | Clear filter / Close drawer |

---

## Data Flow

```
Phase 4 (Streaming) → MongoDB.security_events
                              ↓
Phase 5 (Graph)     → MongoDB.graph_nodes, graph_edges
                              ↓
API Server          → Fetch + Aggregate
                              ↓
WebSocket Stream    → Push real-time updates
                              ↓
Dashboard           → Render (Polar Radar, Stream, Metrics)
```

---

## Troubleshooting

### Dashboard shows "Connecting to live stream..."

**Problem:** API server not running or MongoDB empty

**Solution:**
```powershell
# Check API server
curl http://localhost:8000/api/v1/health

# Check MongoDB has data
docker exec threvia-mongo mongosh threvia --eval "db.security_events.countDocuments()"

# Populate sample data
python backend/realtime/stream_simulator.py --quick-populate
```

### WebSocket disconnects frequently

**Problem:** Firewall or network timeout

**Solution:**
- Check firewall allows port 8000
- Increase WebSocket timeout in `main.py`:
  ```python
  @app.websocket("/api/v1/threats/live")
  async def websocket_threats(websocket: WebSocket):
      await websocket.send_json({"type": "ping"})  # Add keepalive
  ```

### Radar shows no targets

**Problem:** No threats in MongoDB or data not loading

**Solution:**
```powershell
# Check recent threats via API
curl http://localhost:8000/api/v1/threats/recent

# If empty, run Phase 4 to generate threats
.\run_threvia_pipeline.ps1 -Phases 4
```

### API returns 500 errors

**Problem:** MongoDB connection failed

**Solution:**
```powershell
# Restart MongoDB
docker restart threvia-mongo

# Wait 10 seconds, then restart API
Start-Sleep -Seconds 10
python backend/api/main.py
```

---

## Development

### Adding New API Endpoints

1. Edit `backend/api/main.py`
2. Add route:
   ```python
   @app.get("/api/v1/your-endpoint")
   async def your_endpoint():
       # Fetch from MongoDB
       data = db.your_collection.find_one()
       return {"result": data}
   ```
3. Update `dashboard/app.js` to call endpoint
4. Restart API server

### Customizing Radar

Edit `dashboard/app.js` → `drawRadar()` function:

```javascript
// Change sweep speed
radarAngle = (radarAngle + 2.0) % 360;  // Faster sweep

// Change target colors
const color = {
    'Critical': '#ff0000',  // Bright red
    'High': '#ffa500',      // Orange
    'Medium': '#ffff00'     // Yellow
}[severity];
```

### Adding New Telemetry Metrics

1. Add metric to `backend/api/main.py`:
   ```python
   @app.get("/api/v1/metrics/summary")
   async def get_summary_metrics():
       # ... existing code ...
       new_metric = db.collection.count_documents({})
       return {
           # ... existing metrics ...
           "new_metric": new_metric
       }
   ```

2. Update `dashboard/app.js`:
   ```javascript
   async function fetchSummaryMetrics() {
       const data = await res.json();
       document.getElementById('new-metric').textContent = data.new_metric;
   }
   ```

3. Add HTML element in `dashboard/index.html`:
   ```html
   <span id="new-metric">0</span>
   ```

---

## Production Deployment

### 1. Use Production WSGI Server

Replace `uvicorn` development server:

```powershell
# Install gunicorn (Linux) or hypercorn (Windows)
pip install hypercorn

# Run with multiple workers
hypercorn backend.api.main:app --bind 0.0.0.0:8000 --workers 4
```

### 2. Configure Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name threvia.your-domain.com;

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        proxy_pass http://localhost:8000/dashboard;
    }
}
```

### 3. Enable HTTPS

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d threvia.your-domain.com
```

### 4. Environment Variables

```bash
export MONGO_URI="mongodb://prod-server:27017/"
export API_BASE_URL="https://threvia.your-domain.com"
```

---

## Comparison: Old vs. New Dashboard

| Feature | Old (Streamlit) | New (SOC UI) |
|---------|-----------------|--------------|
| **Aesthetic** | Generic data app | Military SOC theme |
| **Real-time** | Polling (5s) | WebSocket (instant) |
| **Radar View** | ❌ No | ✅ Yes (canvas) |
| **Honest Metrics** | ✅ Yes | ✅ Yes (prominent) |
| **Keyboard Shortcuts** | ❌ No | ✅ Yes ([SPACE], [/], [ESC]) |
| **Performance** | ~500ms load | ~50ms load |
| **Customization** | Limited (Streamlit) | Full control (HTML/JS) |
| **Professional Look** | Basic | Enterprise-grade |

---

## Credits

- **Design Inspiration:** Military radar systems, SOC dashboards
- **UI Framework:** Tailwind CSS
- **Icons:** Material Symbols
- **Fonts:** Inter (UI), JetBrains Mono (telemetry)
- **Backend:** FastAPI + MongoDB

---

**Last Updated:** September 12, 2026  
**Version:** 1.0.0 (Production)  
**Contact:** See main project README
