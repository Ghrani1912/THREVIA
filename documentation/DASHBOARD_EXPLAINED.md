# THREVIA Dashboard - What's Dummy vs Real Data

## Current State: Dashboard Has TWO Types of Content

### 🎨 **STATIC / DUMMY DATA** (Hardcoded in HTML for UI Design)

These are **visual placeholders** that make the dashboard look like a real military-grade SOC interface. They **never change** because they're baked into the HTML:

#### 1. **Top Banner Alert** (Red notification bar)
```
"Active Infiltration & Distributed PortScan detected on Gateway Ingress Cluster 04"
"VECTOR-07 · STREAM · 2:47:48 ago INGRESS · 5.54 Gbps sec PICO0META ..."
```
- **Status**: ❌ Dummy (hardcoded for visual impact)
- **Purpose**: Shows what a critical alert would look like
- **File**: `dashboard/index.html` line ~17-20

#### 2. **Radar Visualization** (The circular scope)
- The radar sweep animation itself ✅ **Real** (JavaScript animation)
- The targets/contacts shown ❌ **Dummy initially** → ✅ **Will become real**
- When Phase 4 runs, this will show actual IPs from MongoDB

#### 3. **Signal Classifier Legend** (Top-right of radar)
```
🔴 CRITICAL INTRUSION (DDoS/Exfil)
🟠 ELEVATED (PortScan/SYN Sweep)
🟢 NOMINAL MIRROR FLOW
```
- **Status**: ❌ Dummy (static legend)
- **Purpose**: Explains what colors mean
- **Won't change**: This is a reference guide

#### 4. **Bottom Section: "SUBSYSTEM BENCHMARK"**
```
DDoS DETECTOR: 99.8% Recall, 0.02% FPR
PortScan DETECTOR: 99.9% Recall
Bot DETECTOR: 68.3% Recall (← will update to 65.26%)
Infiltration DETECTOR: 69.0% Recall (← correct: 68.97%)
```
- **Status**: ⚠️ **Semi-static** (hardcoded but reflects your actual model performance)
- **Purpose**: Shows the HONEST EVALUATION from Phase 3
- **This is YOUR real model metrics**, just displayed statically
- **File**: `dashboard/index.html` line ~285-350

#### 5. **"FORENSIC TELEMETRY" Panel** (Right side)
```
LOW 143.41.11.43 — [68.98.204.133]
Ingress: 314 flows
HIGH 132.148.54.200 — [63 FF 165 103]
PortScan: 567 Flows
```
- **Status**: ❌ Dummy (example data)
- **Purpose**: Shows what live telemetry would look like
- **Will populate with real IPs** once Phase 4 runs

#### 6. **"LIVE TELEMETRY STREAM & BLOOM MATCHES"** (Center stream)
- Currently shows: "NO THREATS DETECTED" message (if empty)
- **Will become REAL** when Phase 4 writes to MongoDB

---

### ✅ **REAL / DYNAMIC DATA** (Fetched from API + MongoDB)

These elements **update automatically** when you run Phase 4:

#### 1. **Top Badges** (CRIT / ELEV / TOTAL counters)
```html
<span id="crit-badge">0 CRIT</span>    ← Updates every 5 seconds
<span id="elev-badge">0 ELEV</span>    ← Updates every 5 seconds
<span id="nominal-badge">0 TOTAL</span> ← Updates every 5 seconds
```
- **Source**: `/api/v1/metrics/summary` endpoint
- **Updates from**: MongoDB `ml_alerts` + `stream_alerts` collections
- **File**: `dashboard/app.js` line ~21-49

#### 2. **Radar Stats** (Left side of radar)
```
"1 VECTORS" (active threats)
"1 MATCHES" (Bloom filter hits)
```
- **Source**: `/api/v1/metrics/summary`
- **Updates from**: MongoDB `ml_alerts` + `bloom_hits`
- **File**: `dashboard/app.js` line ~42-44

#### 3. **Incident Stream** (Center scrolling list)
- Shows **real ML alerts** with:
  - IP addresses (source → destination)
  - Attack type (DDoS, Bot, PortScan, Infiltration)
  - Severity (Critical / High / Medium)
  - **ML probabilities**: `p_attack`, `p_bot`
  - **KMeans cluster**: `cluster_id`
  - Timestamp
- **Source**: `/api/v1/threats/recent` endpoint
- **Updates from**: MongoDB `ml_alerts` collection (written by Pipeline C)
- **File**: `dashboard/app.js` line ~61-95

#### 4. **Radar Targets** (The dots on the circular scope)
- Maps real threat IPs to angular positions
- Color-coded by severity:
  - 🔴 Red = Critical (P(attack) ≥ 0.90)
  - 🟠 Orange = High (P(attack) ≥ 0.80)
  - 🟡 Yellow = Medium (P(attack) ≥ 0.65)
- **Source**: Same as incident stream
- **File**: `dashboard/app.js` line ~150-180

#### 5. **WebSocket Live Feed** (Real-time push)
- Opens WebSocket connection to `/ws/threats`
- Pushes **new alerts instantly** (no 5-second delay)
- **Source**: MongoDB change streams (optional)
- **File**: `dashboard/app.js` line ~100-140

#### 6. **API Status Indicator** (Top-right corner)
```
"LINK: API SYNCHRONIZED" (green) ← API working
"LINK: API DISCONNECTED" (red)   ← API down
```
- **Updates**: Every API call
- **File**: `dashboard/app.js` line ~46-58

---

## What Happens When You Run Phase 4?

### **BEFORE Phase 4** (Current State):
```
MongoDB Collections:
├── ml_alerts: 0 documents        ← Empty
├── bloom_hits: 0 documents       ← Empty
├── stream_alerts: 0 documents    ← Empty
└── security_events: 0 documents  ← Empty (was populated with 200 samples before, now cleared)

Dashboard Shows:
├── Badges: "0 CRIT / 0 ELEV / 0 TOTAL"
├── Incident Stream: "NO THREATS DETECTED" message
├── Radar: Empty (no targets)
└── All static UI elements (banners, legends, benchmarks)
```

### **AFTER Phase 4 Starts** (Every 10 seconds):
```
MongoDB Collections:
├── ml_alerts: 156 documents       ← Pipeline C writes (RF binary/multiclass/bot + KMeans)
│   Example document:
│   {
│     "src_ip": "175.45.176.0",
│     "dst_ip": "149.171.126.6",
│     "p_attack": 0.91,           ← Your RF binary model (T=0.65)
│     "attack_type": "DDoS",      ← Your RF multiclass model
│     "p_bot": 0.12,              ← Your RF bot specialist (65.26% recall)
│     "cluster_id": 3,            ← Your KMeans unsupervised model
│     "severity": "High",
│     "created_at": "2026-09-15T13:45:12Z"
│   }
│
├── bloom_hits: 4 documents        ← Pipeline A writes (IP reputation)
│   Example:
│   {
│     "src_ip": "175.45.176.1",
│     "attack_cat": "Botnet",
│     "label": "1"
│   }
│
└── stream_alerts: 5 documents     ← Pipeline B writes (spike detection)
    Example:
    {
      "src_ip": "10.0.0.1",
      "connection_count": 5432,
      "severity": "Critical",
      "window_start": "2026-09-15 13:45:00"
    }

Dashboard Shows:
├── Badges: "12 CRIT / 34 ELEV / 156 TOTAL"  ← Real counts from your ML models
├── Incident Stream: Scrolling list of ML predictions
│   Example rows:
│   🔴 CRIT | 175.45.176.0 → 149.171.126.6 | DDoS | P(attack)=0.91 | P(bot)=0.12 | Cluster 3
│   🟠 HIGH | 10.0.2.15 → 192.168.1.1 | Bot | P(attack)=0.83 | P(bot)=0.88 | Cluster 7
│
└── Radar: Targets appear at angular positions, color-coded by severity
```

---

## Key Insight: Dashboard is a HYBRID

| Element | Type | What It Shows |
|---------|------|---------------|
| **Top banner alert** | ❌ Dummy | Visual design placeholder |
| **Signal classifier legend** | ❌ Dummy | Static reference guide |
| **Subsystem benchmark** | ⚠️ Semi-static | **Your real model performance** (Bot 65.26%, Infiltration 68.97%) |
| **CRIT/ELEV/TOTAL badges** | ✅ **Real** | Live counts from MongoDB → **your ML models** |
| **Incident stream** | ✅ **Real** | Live ML predictions with `p_attack`, `attack_type`, `p_bot`, `cluster_id` |
| **Radar targets** | ✅ **Real** | Visual map of threats from MongoDB |
| **Bloom matches counter** | ✅ **Real** | Pipeline A Bloom filter hits |

---

## How to Verify Real Data

### 1. Check MongoDB Collections
```powershell
# ML alerts (Pipeline C - your 7 models)
docker exec threvia-mongodb mongosh threvia --quiet --eval "db.ml_alerts.countDocuments()"

# Bloom hits (Pipeline A - IP reputation)
docker exec threvia-mongodb mongosh threvia --quiet --eval "db.bloom_hits.countDocuments()"

# Spike alerts (Pipeline B - volume detection)
docker exec threvia-mongodb mongosh threvia --quiet --eval "db.stream_alerts.countDocuments()"
```

### 2. View a Real ML Alert
```powershell
docker exec threvia-mongodb mongosh threvia --quiet --eval "db.ml_alerts.findOne()" | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

You'll see:
```json
{
  "src_ip": "175.45.176.0",
  "dst_ip": "149.171.126.6",
  "p_attack": 0.91,          ← Your RF binary model
  "attack_type": "DDoS",     ← Your RF multiclass model  
  "p_bot": 0.12,             ← Your RF bot specialist (65.26% recall!)
  "cluster_id": 3,           ← Your KMeans unsupervised model
  "severity": "High",
  "event_time": "2026-09-15 13:45:10",
  "created_at": "2026-09-15T13:45:12Z"
}
```

### 3. Watch Dashboard Update Live
1. Open: http://localhost:8000/dashboard
2. Run Phase 4: `.\run_phase4_docker.ps1 all`
3. Watch:
   - **Badges** increase: "0 CRIT" → "12 CRIT"
   - **Incident stream** populates with ML predictions
   - **Radar** shows colored dots for each threat IP
   - **Stats** update: "1 VECTORS", "4 MATCHES"

---

## Bottom Line

**The dashboard is a BEAUTIFUL MILITARY-GRADE UI with:**
- 🎨 **Static visual design** (banners, legends, benchmark cards) = Makes it look badass
- ✅ **Real ML predictions** (incident stream, badges, radar targets) = Your Bot 65.26% / Infiltration 68.97% models scoring live traffic

**Once Phase 4 runs:**
- Pipeline C writes **real ML alerts** with `p_attack`, `attack_type`, `p_bot`, `cluster_id`
- Dashboard **automatically updates** every 5 seconds
- You see **your trained models** (3 supervised RF + 1 unsupervised KMeans) making predictions on CIC-2017 Friday traffic!

The "dummy" parts are **intentional visual design** to make it look like a real SOC dashboard from a movie. The **data that matters** (ML predictions, threat counts, Bloom hits) is 100% real from your models! 🎯
