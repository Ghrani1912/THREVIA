#!/usr/bin/env python3
"""Test MongoDB connection from API context"""
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["threvia"]

print("Testing MongoDB connection...")
print(f"MongoDB URI: {MONGO_URI}")

try:
    # Test connection
    db.command('ping')
    print("✓ MongoDB connected")
    
    # Count documents
    spike_count = db.stream_alerts.count_documents({})
    ml_count = db.ml_alerts.count_documents({})
    bloom_count = db.bloom_hits.count_documents({})
    
    print(f"\nCurrent counts:")
    print(f"  Spike alerts: {spike_count}")
    print(f"  ML alerts: {ml_count}")
    print(f"  Bloom hits: {bloom_count}")
    print(f"  TOTAL: {spike_count + ml_count + bloom_count}")
    
    # Show sample alert
    if spike_count > 0:
        sample = db.stream_alerts.find_one()
        print(f"\nSample spike alert:")
        print(f"  Source IP: {sample.get('src_ip')}")
        print(f"  Connections: {sample.get('connection_count')}")
        print(f"  Severity: {sample.get('severity')}")
        
except Exception as e:
    print(f"✗ Error: {e}")
finally:
    client.close()
