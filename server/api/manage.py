#!/usr/bin/env python3
"""
Ophanim EDR Database Management CLI

Usage:
    uv run manage.py seed     # Seed with diverse demo data
    uv run manage.py clear    # Clear all data
    uv run manage.py status   # Show database stats
"""

import asyncio
import sys
import random
import uuid
from datetime import datetime, timedelta

from pymongo import MongoClient
import os


def get_db():
    """Get MongoDB connection."""
    mongo_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DATABASE_NAME", "ophanim_edr")
    client = MongoClient(mongo_url)
    return client[db_name]


def seed_data():
    """Seed the database with diverse demo data."""
    db = get_db()
    now = datetime.utcnow()
    
    # Clear existing data
    db.endpoints.delete_many({})
    db.events.delete_many({})
    db.detections.delete_many({})
    
    print("🗑️  Cleared existing data")
    
    # Demo endpoints with diverse OS types
    endpoints = [
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "DESKTOP-WIN01",
            "ip_address": "192.168.1.101",
            "os_type": "windows",
            "os_version": "Windows 11 Pro 23H2",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=7),
            "last_seen": now - timedelta(seconds=15),
            "events_today": 1247,
            "policy": "default",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "ubuntu-server-01",
            "ip_address": "192.168.1.50",
            "os_type": "linux",
            "os_version": "Ubuntu 22.04.3 LTS",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=14),
            "last_seen": now - timedelta(seconds=5),
            "events_today": 3421,
            "policy": "server",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "suse-enterprise-db",
            "ip_address": "192.168.1.55",
            "os_type": "suse",
            "os_version": "SLES 15 SP5",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=21),
            "last_seen": now - timedelta(seconds=30),
            "events_today": 2156,
            "policy": "database",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "MacBook-Dev-001",
            "ip_address": "192.168.1.142",
            "os_type": "macos",
            "os_version": "macOS Sonoma 14.2",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=3),
            "last_seen": now - timedelta(seconds=45),
            "events_today": 856,
            "policy": "developer",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "LAPTOP-WIN02",
            "ip_address": "192.168.1.105",
            "os_type": "windows",
            "os_version": "Windows 10 Enterprise",
            "agent_version": "0.1.0",
            "status": "offline",
            "registered_at": now - timedelta(days=10),
            "last_seen": now - timedelta(hours=2),
            "events_today": 0,
            "policy": "finance",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "debian-web-prod",
            "ip_address": "192.168.1.60",
            "os_type": "linux",
            "os_version": "Debian 12 Bookworm",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=30),
            "last_seen": now - timedelta(seconds=10),
            "events_today": 5872,
            "policy": "server",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "iMac-Design-01",
            "ip_address": "192.168.1.180",
            "os_type": "macos",
            "os_version": "macOS Ventura 13.6",
            "agent_version": "0.1.0",
            "status": "offline",
            "registered_at": now - timedelta(days=5),
            "last_seen": now - timedelta(hours=8),
            "events_today": 0,
            "policy": "default",
        },
        {
            "endpoint_id": str(uuid.uuid4())[:8],
            "hostname": "SERVER-WIN-DC01",
            "ip_address": "192.168.1.10",
            "os_type": "windows",
            "os_version": "Windows Server 2022",
            "agent_version": "0.1.0",
            "status": "online",
            "registered_at": now - timedelta(days=60),
            "last_seen": now - timedelta(seconds=8),
            "events_today": 8934,
            "policy": "server",
        },
    ]
    
    db.endpoints.insert_many(endpoints)
    print(f"✅ Seeded {len(endpoints)} endpoints (Windows, Linux, SUSE, macOS)")
    
    # Demo events
    event_types = ["process_start", "process_end", "file_created", "file_modified", "network_connection"]
    process_names = ["chrome.exe", "notepad.exe", "powershell.exe", "python3", "nginx", "postgres", "code", "docker"]
    
    events = []
    for endpoint in endpoints:
        if endpoint["status"] == "online":
            for i in range(random.randint(30, 80)):
                events.append({
                    "event_type": random.choice(event_types),
                    "timestamp": now - timedelta(minutes=random.randint(1, 1440)),
                    "endpoint_id": endpoint["endpoint_id"],
                    "data": {
                        "name": random.choice(process_names),
                        "pid": random.randint(1000, 9999),
                    },
                    "received_at": now,
                })
    
    if events:
        db.events.insert_many(events)
    print(f"✅ Seeded {len(events)} events")
    
    # Demo detections with dates for trend chart
    detections = [
        {
            "detection_type": "suspicious_process",
            "severity": "critical",
            "title": "Suspicious PowerShell with encoded command",
            "description": "PowerShell executed with Base64 encoded command line.",
            "endpoint_id": endpoints[0]["endpoint_id"],
            "ml_confidence": 0.94,
            "mitre_technique": "T1059.001",
            "related_event_ids": [],
            "status": "new",
            "created_at": now - timedelta(hours=2),
            "updated_at": now - timedelta(hours=2),
            "assigned_to": None,
            "notes": "",
        },
        {
            "detection_type": "anomaly",
            "severity": "high",
            "title": "Unusual outbound connection from server",
            "description": "Linux server established connection to unknown IP.",
            "endpoint_id": endpoints[1]["endpoint_id"],
            "ml_confidence": 0.87,
            "mitre_technique": "T1071.001",
            "related_event_ids": [],
            "status": "investigating",
            "created_at": now - timedelta(hours=5),
            "updated_at": now - timedelta(hours=1),
            "assigned_to": None,
            "notes": "",
        },
        {
            "detection_type": "malware",
            "severity": "critical",
            "title": "Known malware signature detected",
            "description": "File hash matches known Emotet variant.",
            "endpoint_id": endpoints[3]["endpoint_id"],
            "ml_confidence": 0.99,
            "mitre_technique": "T1204.002",
            "related_event_ids": [],
            "status": "new",
            "created_at": now - timedelta(minutes=30),
            "updated_at": now - timedelta(minutes=30),
            "assigned_to": None,
            "notes": "",
        },
        {
            "detection_type": "file_tampering",
            "severity": "medium",
            "title": "System configuration file modified",
            "description": "Modification to /etc/hosts detected on SUSE server.",
            "endpoint_id": endpoints[2]["endpoint_id"],
            "ml_confidence": 0.72,
            "mitre_technique": "T1565.001",
            "related_event_ids": [],
            "status": "resolved",
            "created_at": now - timedelta(days=1),
            "updated_at": now - timedelta(hours=12),
            "assigned_to": None,
            "notes": "Verified as legitimate admin change",
        },
        {
            "detection_type": "privilege_escalation",
            "severity": "high",
            "title": "Potential privilege escalation attempt",
            "description": "Process attempted to access LSASS memory.",
            "endpoint_id": endpoints[7]["endpoint_id"],
            "ml_confidence": 0.91,
            "mitre_technique": "T1003.001",
            "related_event_ids": [],
            "status": "new",
            "created_at": now - timedelta(hours=1),
            "updated_at": now - timedelta(hours=1),
            "assigned_to": None,
            "notes": "",
        },
        # Historical detections for trend chart
        {
            "detection_type": "anomaly",
            "severity": "low",
            "title": "Unusual login time detected",
            "description": "User logged in outside normal hours.",
            "endpoint_id": endpoints[0]["endpoint_id"],
            "ml_confidence": 0.65,
            "mitre_technique": "T1078",
            "related_event_ids": [],
            "status": "resolved",
            "created_at": now - timedelta(days=2),
            "updated_at": now - timedelta(days=2),
            "assigned_to": None,
            "notes": "",
        },
        {
            "detection_type": "suspicious_process",
            "severity": "medium",
            "title": "Scripting engine invoked from unusual path",
            "description": "Python executed from temp directory.",
            "endpoint_id": endpoints[5]["endpoint_id"],
            "ml_confidence": 0.78,
            "mitre_technique": "T1059.006",
            "related_event_ids": [],
            "status": "false_positive",
            "created_at": now - timedelta(days=3),
            "updated_at": now - timedelta(days=3),
            "assigned_to": None,
            "notes": "Developer testing",
        },
        {
            "detection_type": "unusual_network",
            "severity": "high",
            "title": "Large data transfer to external IP",
            "description": "Unusual volume of data sent externally.",
            "endpoint_id": endpoints[1]["endpoint_id"],
            "ml_confidence": 0.85,
            "mitre_technique": "T1041",
            "related_event_ids": [],
            "status": "resolved",
            "created_at": now - timedelta(days=4),
            "updated_at": now - timedelta(days=4),
            "assigned_to": None,
            "notes": "Scheduled backup",
        },
    ]
    
    db.detections.insert_many(detections)
    print(f"✅ Seeded {len(detections)} detections")
    
    print("\n🎉 Database seeded successfully!")
    print(f"   Endpoints: {len(endpoints)}")
    print(f"   Events: {len(events)}")
    print(f"   Detections: {len(detections)}")


def clear_data():
    """Clear all data from the database."""
    db = get_db()
    
    db.endpoints.delete_many({})
    db.events.delete_many({})
    db.detections.delete_many({})
    
    print("🗑️  All data cleared from database")


def show_status():
    """Show database statistics."""
    db = get_db()
    
    endpoints = db.endpoints.count_documents({})
    events = db.events.count_documents({})
    detections = db.detections.count_documents({})
    
    # OS breakdown
    os_counts = {}
    for doc in db.endpoints.aggregate([
        {"$group": {"_id": "$os_type", "count": {"$sum": 1}}}
    ]):
        os_counts[doc["_id"]] = doc["count"]
    
    print("📊 Ophanim EDR Database Status")
    print("=" * 40)
    print(f"   Endpoints: {endpoints}")
    print(f"   Events: {events}")
    print(f"   Detections: {detections}")
    print()
    print("   Endpoints by OS:")
    for os_type, count in os_counts.items():
        print(f"     - {os_type}: {count}")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "seed":
        seed_data()
    elif command == "clear":
        clear_data()
    elif command == "status":
        show_status()
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
