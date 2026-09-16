#!/usr/bin/env python3
"""
Quick test: Verify JSON export works
"""
import json
from pathlib import Path

json_path = Path(__file__).parent / "graph_export.json"

if not json_path.exists():
    print("❌ graph_export.json not found!")
    print(f"   Run: python backend/graph/run_phase5.py all")
    exit(1)

with open(json_path) as f:
    data = json.load(f)

print("✅ JSON export exists and is valid!")
print(f"\n📊 Graph Statistics:")
print(f"   Nodes: {len(data['nodes'])}")
print(f"   Edges: {len(data['edges'])}")
print(f"   Attacker nodes: {data['metadata']['attacker_nodes']}")
print(f"   Attack edges: {data['metadata']['attack_edges']}")

print(f"\n🔍 Sample Node:")
if data['nodes']:
    node = data['nodes'][0]
    print(f"   IP: {node['id']}")
    print(f"   Is Attacker: {node['is_attacker']}")
    print(f"   PageRank: {node['pagerank']:.6f}")
    print(f"   Danger Score: {node['danger_score']:.4f}")
    print(f"   Community: {node['community_id']}")
    print(f"   Color: {node['color']}")

print(f"\n🔗 Sample Edge:")
if data['edges']:
    edge = data['edges'][0]
    print(f"   {edge['source']} → {edge['target']}")
    print(f"   Weight: {edge['weight']}")
    print(f"   Has Attack: {edge['has_attack']}")
    print(f"   Color: {edge['color']}")

print("\n✨ Ready for frontend integration!")
print("   API endpoint: GET /api/v1/graph/topology")
print("   Use with: vis-network, Cytoscape.js, or React Flow")
