"""
Quick MongoDB Populator for THREVIA Dashboard
==============================================
Populates MongoDB with sample security events for testing the dashboard
"""

import os
import sys
from datetime import datetime, timedelta
from pymongo import MongoClient
import random

# MongoDB connection.
# 27018 is the HOST port: docker-compose publishes MongoDB there (host 27018 ->
# container 27017) because 27017 is often already taken by a MongoDB installed
# on the machine. This script is launched from the host by start_dashboard.ps1
# and populate_sample_data.ps1, so it has to use the host port; the detector and
# API containers get MONGO_URI=mongodb://mongodb:27017/ from compose instead.
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018/")
client = MongoClient(MONGO_URI)
db = client["threvia"]

# Sample attack types and severities
ATTACK_TYPES = [
    ("DDoS", "Critical"),
    ("PortScan", "High"),
    ("Botnet", "Critical"),
    ("DoS Slowhttptest", "High"),
    ("Infiltration", "Critical"),
    ("Web Attack", "High"),
    ("SSH-Patator", "Medium"),
    ("FTP-Patator", "Medium"),
    ("Benign", "Low"),
]

def generate_ip():
    """Generate a random IP address"""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_threat_event():
    """Generate a single threat event"""
    attack_type, severity = random.choice(ATTACK_TYPES)
    
    # Generate timestamp within last 24 hours
    hours_ago = random.randint(0, 24)
    minutes_ago = random.randint(0, 59)
    timestamp = datetime.utcnow() - timedelta(hours=hours_ago, minutes=minutes_ago)
    
    event = {
        "source_ip": generate_ip(),
        "dest_ip": generate_ip(),
        "source_port": random.randint(1024, 65535),
        "dest_port": random.choice([80, 443, 22, 3389, 8080, 3306, 5432]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "predicted_label": attack_type,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": round(random.uniform(0.75, 0.99), 3),
        "flow_count": random.randint(1, 1000),
        "bytes_sent": random.randint(100, 100000),
        "bytes_received": random.randint(100, 100000),
        "packets_sent": random.randint(10, 1000),
        "packets_received": random.randint(10, 1000),
        "duration": round(random.uniform(0.1, 300.0), 2),
        "danger_index": round(random.uniform(50, 99.9) if severity in ["Critical", "High"] else random.uniform(10, 50), 1),
        "pagerank": round(random.uniform(0.001, 0.1), 4),
        "degree": random.randint(1, 100),
        "community": f"Cluster-{random.choice(['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon'])}",
        "is_malicious": severity in ["Critical", "High"],
        "bloom_hits": random.randint(0, 5) if severity in ["Critical", "High"] else 0,
        "timestamp": timestamp,
        "created_at": datetime.utcnow(),
    }
    
    return event

def populate_database(num_events=200):
    """Populate MongoDB with sample events"""
    print(f"\n{'='*50}")
    print(f"THREVIA MongoDB Sample Data Populator")
    print(f"{'='*50}\n")
    
    # Check connection
    try:
        db.command('ping')
        print(f"✓ Connected to MongoDB at {MONGO_URI}")
    except Exception as e:
        print(f"✗ Failed to connect to MongoDB at {MONGO_URI}: {e}")
        print("  Is the container up?   docker compose up -d mongodb")
        print("  Host port is 27018 (container 27017); override with MONGO_URI.")
        sys.exit(1)
    
    # Check current count
    current_count = db.security_events.count_documents({})
    print(f"✓ Current events in database: {current_count}")
    
    # Generate events
    print(f"\n→ Generating {num_events} sample security events...")
    events = []
    
    for i in range(num_events):
        events.append(generate_threat_event())
        if (i + 1) % 50 == 0:
            print(f"  Generated {i + 1}/{num_events} events...")
    
    # Insert into MongoDB
    print(f"\n→ Inserting events into MongoDB...")
    try:
        result = db.security_events.insert_many(events)
        print(f"✓ Successfully inserted {len(result.inserted_ids)} events")
    except Exception as e:
        print(f"✗ Failed to insert events: {e}")
        sys.exit(1)
    
    # Verify
    new_count = db.security_events.count_documents({})
    print(f"✓ Total events in database: {new_count}")
    
    # Show distribution
    print(f"\n{'='*50}")
    print("Event Distribution:")
    print(f"{'='*50}")
    
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    for doc in db.security_events.aggregate(pipeline):
        print(f"  {doc['_id']:12s}: {doc['count']:4d} events")
    
    print(f"\n{'='*50}")
    print("✓ Database population complete!")
    print(f"{'='*50}\n")
    print("Next steps:")
    print("  1. Refresh your dashboard: http://localhost:8000/dashboard")
    print("  2. Press F5 to reload the page")
    print("  3. You should now see threats in the incident stream\n")

if __name__ == "__main__":
    # Get number of events from command line, default to 200
    num_events = 200
    if len(sys.argv) > 1:
        try:
            num_events = int(sys.argv[1])
        except ValueError:
            print(f"Invalid number: {sys.argv[1]}, using default 200")
    
    populate_database(num_events)
