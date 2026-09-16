# Graph Topology API Documentation

## Overview

Phase 5 now exports the network graph in **JSON format** for easy frontend integration. This replaces the PyVis HTML-only approach and enables real-time graph visualization in any JavaScript framework.

## Backend Implementation

### JSON Export

The graph is exported to `backend/graph/graph_export.json` with this structure:

```json
{
  "nodes": [
    {
      "id": "175.45.176.0",
      "label": "175.45.176.0",
      "pagerank": 0.003421,
      "danger_score": 0.8234,
      "is_attacker": true,
      "community_id": 2,
      "attack_cats": ["DoS", "Exploits"],
      "total_flows": 1247,
      "out_degree": 42,
      "in_degree": 8,
      "color": "#ff3344",
      "size": 34
    }
  ],
  "edges": [
    {
      "source": "175.45.176.0",
      "target": "192.168.1.100",
      "weight": 156,
      "has_attack": true,
      "attack_cats": ["DoS"],
      "total_bytes": 245678,
      "proto_counts": {"tcp": 150, "udp": 6},
      "color": "#ff4757",
      "width": 3
    }
  ],
  "metadata": {
    "total_nodes": 248,
    "total_edges": 1523,
    "attacker_nodes": 4,
    "attack_edges": 892,
    "communities": 8,
    "generated_at": "2026-09-16T04:00:00Z"
  }
}
```

### Color Coding

**Nodes:**
- `#ff3344` (Red) - Confirmed attacker (`is_attacker = true`)
- `#ffaa00` (Orange) - In malicious community but not itself an attacker
- `#00d9ff` (Cyan) - Normal node

**Edges:**
- `#ff4757` (Red) - Contains attack traffic (`has_attack = true`)
- `#00d9ff` (Cyan) - Normal traffic only

### Size Scaling

- **Nodes**: Scaled by PageRank (10-60px)
- **Edges**: Scaled by weight/connection count (1-5px)

## API Endpoints

### GET /api/v1/graph/topology

Returns the complete graph topology with nodes, edges, and metadata.

**Response:**
```json
{
  "nodes": [...],
  "edges": [...],
  "metadata": {...}
}
```

**Usage:**
```javascript
const response = await fetch('http://localhost:8000/api/v1/graph/topology');
const graphData = await response.json();
// Use with vis-network, Cytoscape.js, React Flow, etc.
```

### GET /api/v1/graph/node/{ip_address}

Get detailed information about a specific node.

**Response:**
```json
{
  "node": {
    "ip": "175.45.176.0",
    "pagerank": 0.003421,
    "danger_score": 0.8234,
    "is_attacker": true,
    "community_id": 2,
    ...
  },
  "outgoing_edges": [...],
  "incoming_edges": [...],
  "out_degree": 42,
  "in_degree": 8
}
```

### GET /api/v1/graph/communities

Get all detected communities with member lists.

**Response:**
```json
{
  "communities": [
    {
      "community_id": 0,
      "members": ["192.168.1.1", "192.168.1.2", ...],
      "size": 24,
      "has_attacker": false
    },
    ...
  ],
  "count": 8
}
```

## Frontend Integration

### Option 1: vis-network (Recommended for THREVIA)

```bash
npm install vis-network
```

```jsx
import { Network } from 'vis-network';
import { useEffect, useRef } from 'react';

function TopologyGraph() {
  const containerRef = useRef(null);
  
  useEffect(() => {
    async function loadGraph() {
      const res = await fetch('http://localhost:8000/api/v1/graph/topology');
      const data = await res.json();
      
      const network = new Network(
        containerRef.current,
        { nodes: data.nodes, edges: data.edges },
        {
          nodes: {
            shape: 'dot',
            font: { color: '#00ff88', face: 'monospace' }
          },
          edges: {
            arrows: 'to',
            smooth: { type: 'continuous' }
          },
          physics: {
            stabilization: { iterations: 150 },
            barnesHut: { gravitationalConstant: -8000 }
          }
        }
      );
      
      // Handle node clicks
      network.on('click', (params) => {
        if (params.nodes.length > 0) {
          const nodeId = params.nodes[0];
          // Fetch detailed node info
          // Update detail panel, etc.
        }
      });
    }
    
    loadGraph();
  }, []);
  
  return <div ref={containerRef} style={{ width: '100%', height: '750px' }} />;
}
```

### Option 2: Cytoscape.js (More Customizable)

```bash
npm install cytoscape
```

```jsx
import cytoscape from 'cytoscape';

function TopologyGraph() {
  useEffect(() => {
    async function loadGraph() {
      const res = await fetch('http://localhost:8000/api/v1/graph/topology');
      const { nodes, edges } = await res.json();
      
      // Transform to Cytoscape format
      const elements = [
        ...nodes.map(n => ({ data: { id: n.id, ...n } })),
        ...edges.map(e => ({ data: { source: e.source, target: e.target, ...e } }))
      ];
      
      const cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': 'data(color)',
              'label': 'data(label)',
              'width': 'data(size)',
              'height': 'data(size)',
              'font-family': 'monospace',
              'font-size': '10px',
              'color': '#00ff88'
            }
          },
          {
            selector: 'edge',
            style: {
              'line-color': 'data(color)',
              'width': 'data(width)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier'
            }
          }
        ],
        layout: { name: 'cose', animate: false }
      });
    }
    
    loadGraph();
  }, []);
  
  return <div id="cy" style={{ width: '100%', height: '750px' }} />;
}
```

### Option 3: React Flow (Modern React-Native)

```bash
npm install reactflow
```

```jsx
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

function TopologyGraph() {
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  
  useEffect(() => {
    async function loadGraph() {
      const res = await fetch('http://localhost:8000/api/v1/graph/topology');
      const data = await res.json();
      
      // Transform to ReactFlow format
      const flowNodes = data.nodes.map(n => ({
        id: n.id,
        data: { label: n.label, ...n },
        position: { x: Math.random() * 500, y: Math.random() * 500 },
        style: { background: n.color }
      }));
      
      const flowEdges = data.edges.map((e, i) => ({
        id: `e${i}`,
        source: e.source,
        target: e.target,
        style: { stroke: e.color, strokeWidth: e.width }
      }));
      
      setNodes(flowNodes);
      setEdges(flowEdges);
    }
    
    loadGraph();
  }, []);
  
  return (
    <ReactFlow nodes={nodes} edges={edges}>
      <Background />
      <Controls />
    </ReactFlow>
  );
}
```

## Regenerating the Graph

To update the graph with new data:

```powershell
# Run Phase 5 to regenerate
python backend/graph/run_phase5.py all

# Or use the pipeline script
.\run_threvia_pipeline.ps1 -Phases 5
```

This will:
1. Rebuild the NetworkX graph from UNSW-NB15
2. Run analytics (PageRank, community detection, danger scores)
3. Export to MongoDB (`graph_nodes`, `graph_edges`, `graph_communities`)
4. Export JSON to `backend/graph/graph_export.json`
5. Export PyVis HTML (legacy)

## Testing

```powershell
# Verify JSON export exists and is valid
python backend/graph/test_json_export.py

# Test API endpoint
curl http://localhost:8000/api/v1/graph/topology | python -m json.tool | head -50
```

## Benefits Over PyVis HTML

✅ **Real-time updates** - API can fetch live data from MongoDB  
✅ **Full styling control** - Match your tactical/SOC theme  
✅ **Framework integration** - Works with React, Vue, Angular  
✅ **Click interactions** - Proper event handlers for detail panels  
✅ **No iframe hacks** - Direct component integration  
✅ **Smaller bundle** - Only load what you need  
✅ **Better performance** - Native JS rendering  

## Next Steps

When building the graph UI:
1. Create a new dashboard route (e.g., `/topology`)
2. Choose visualization library (vis-network recommended for physics)
3. Implement detail panel for node clicks
4. Add filters (show only attackers, specific communities, etc.)
5. Add search/highlight functionality
6. Consider real-time updates via WebSocket
