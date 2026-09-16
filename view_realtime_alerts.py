#!/usr/bin/env python3
"""
Quick viewer for real-time Phase 4 alerts
Shows live data from MongoDB as the pipeline processes
"""
from pymongo import MongoClient
from datetime import datetime
import time

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["threvia"]

def show_summary():
    """Display current alert counts"""
    ml_count = db.ml_alerts.count_documents({})
    spike_count = db.stream_alerts.count_documents({})
    bloom_count = db.bloom_hits.count_documents({})
    total = ml_count + spike_count + bloom_count
    
    print(f"\n{'='*60}")
    print(f"  THREVIA PHASE 4 - REAL-TIME ALERTS")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")
    print(f"  Total Alerts:     {total}")
    print(f"  Spike Alerts:     {spike_count}")
    print(f"  ML Alerts:        {ml_count}")
    print(f"  Bloom Filter:     {bloom_count}")
    print(f"{'='*60}\n")
    
    # Show recent spike alerts
    if spike_count > 0:
        print("Recent Spike Alerts:")
        print(f"{'Time':<20} {'Source IP':<18} {'Connections':<12} {'Severity':<10}")
        print("-" * 60)
        
        recent = db.stream_alerts.find().sort("created_at", -1).limit(5)
        for alert in recent:
            time_str = alert.get('created_at', 'N/A')
            if isinstance(time_str, datetime):
                time_str = time_str.strftime('%H:%M:%S')
            elif hasattr(time_str, 'strftime'):
                time_str = time_str.strftime('%H:%M:%S')
            else:
                time_str = str(time_str)[:19]
                
            src = alert.get('src_ip', 'N/A')
            count = alert.get('connection_count', 0)
            severity = alert.get('severity', 'Unknown')
            print(f"{time_str:<20} {src:<18} {count:<12} {severity:<10}")
    
    # Show recent ML alerts
    if ml_count > 0:
        print("\nRecent ML Alerts:")
        print(f"{'Time':<20} {'Source IP':<18} {'Attack Type':<15} {'Confidence':<10}")
        print("-" * 65)
        
        recent = db.ml_alerts.find().sort("timestamp", -1).limit(5)
        for alert in recent:
            time_str = str(alert.get('timestamp', 'N/A'))[:19]
            src = alert.get('src_ip', 'N/A')
            attack = alert.get('predicted_label', 'N/A')
            conf = alert.get('rf_binary_prob', 0.0)
            print(f"{time_str:<20} {src:<18} {attack:<15} {conf:.3f}")

if __name__ == "__main__":
    print("THREVIA Real-Time Alert Viewer")
    print("Press Ctrl+C to exit\n")
    
    try:
        while True:
            show_summary()
            print("Refreshing in 5 seconds...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n\nExiting...")
