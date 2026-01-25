"""MongoDB database connection and operations."""

import os
from datetime import datetime, timedelta
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import DESCENDING

from .models import (
    EndpointInDB,
    EndpointRegistration,
    EventCreate,
    EventInDB,
    AgentStatus,
)


# Global database client
_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


def get_mongodb_url() -> str:
    """Get MongoDB connection URL from environment."""
    return os.environ.get("MONGODB_URL", "mongodb://localhost:27017")


def get_database_name() -> str:
    """Get database name from environment."""
    return os.environ.get("DATABASE_NAME", "ophanim_edr")


async def connect_db() -> None:
    """Initialize MongoDB connection."""
    global _client, _db
    url = get_mongodb_url()
    db_name = get_database_name()
    
    _client = AsyncIOMotorClient(url)
    _db = _client[db_name]
    
    # Create indexes
    await _db.endpoints.create_index("endpoint_id", unique=True)
    await _db.events.create_index([("endpoint_id", 1), ("timestamp", DESCENDING)])
    await _db.events.create_index("timestamp")
    
    print(f"Connected to MongoDB: {url}/{db_name}")


async def close_db() -> None:
    """Close MongoDB connection."""
    global _client
    if _client:
        _client.close()
        print("MongoDB connection closed")


def get_db() -> AsyncIOMotorDatabase:
    """Get database instance."""
    if _db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _db


# ============================================================================
# Endpoint Operations
# ============================================================================

async def register_endpoint(registration: EndpointRegistration) -> EndpointInDB:
    """Register or update an endpoint."""
    db = get_db()
    now = datetime.utcnow()
    
    # Check if endpoint exists
    existing = await db.endpoints.find_one({"endpoint_id": registration.endpoint_id})
    
    if existing:
        # Update existing endpoint
        await db.endpoints.update_one(
            {"endpoint_id": registration.endpoint_id},
            {
                "$set": {
                    "hostname": registration.hostname,
                    "ip_address": registration.ip_address,
                    "os_type": registration.os_type.value,
                    "os_version": registration.os_version,
                    "agent_version": registration.agent_version,
                    "last_seen": now,
                    "status": AgentStatus.ONLINE.value,
                }
            }
        )
    else:
        # Create new endpoint
        endpoint_doc = {
            "endpoint_id": registration.endpoint_id,
            "hostname": registration.hostname,
            "ip_address": registration.ip_address,
            "os_type": registration.os_type.value,
            "os_version": registration.os_version,
            "agent_version": registration.agent_version,
            "status": AgentStatus.ONLINE.value,
            "registered_at": now,
            "last_seen": now,
            "events_today": 0,
            "policy": "default",
        }
        await db.endpoints.insert_one(endpoint_doc)
    
    # Return the endpoint
    doc = await db.endpoints.find_one({"endpoint_id": registration.endpoint_id})
    return EndpointInDB(**doc)


async def get_endpoint(endpoint_id: str) -> Optional[EndpointInDB]:
    """Get a single endpoint by ID."""
    db = get_db()
    doc = await db.endpoints.find_one({"endpoint_id": endpoint_id})
    if doc:
        return EndpointInDB(**doc)
    return None


async def get_all_endpoints() -> list[EndpointInDB]:
    """Get all registered endpoints."""
    db = get_db()
    endpoints = []
    
    # Update status based on last_seen
    now = datetime.utcnow()
    offline_threshold = now - timedelta(seconds=60)
    
    async for doc in db.endpoints.find():
        # Determine online/offline status
        if doc.get("last_seen", now) < offline_threshold:
            doc["status"] = AgentStatus.OFFLINE.value
        else:
            doc["status"] = AgentStatus.ONLINE.value
        
        endpoints.append(EndpointInDB(**doc))
    
    return endpoints


async def update_heartbeat(endpoint_id: str) -> bool:
    """Update endpoint last_seen timestamp."""
    db = get_db()
    result = await db.endpoints.update_one(
        {"endpoint_id": endpoint_id},
        {
            "$set": {
                "last_seen": datetime.utcnow(),
                "status": AgentStatus.ONLINE.value,
            }
        }
    )
    return result.modified_count > 0


# ============================================================================
# Event Operations
# ============================================================================

async def insert_events(events: list[EventCreate]) -> int:
    """Insert multiple events into database."""
    if not events:
        return 0
    
    db = get_db()
    now = datetime.utcnow()
    
    docs = []
    endpoint_ids = set()
    
    for event in events:
        endpoint_ids.add(event.endpoint_id)
        docs.append({
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "endpoint_id": event.endpoint_id,
            "data": event.data,
            "received_at": now,
        })
    
    result = await db.events.insert_many(docs)
    
    # Update events_today count for each endpoint
    for endpoint_id in endpoint_ids:
        await db.endpoints.update_one(
            {"endpoint_id": endpoint_id},
            {
                "$inc": {"events_today": len([e for e in events if e.endpoint_id == endpoint_id])},
                "$set": {"last_seen": now, "status": AgentStatus.ONLINE.value},
            }
        )
    
    return len(result.inserted_ids)


async def get_events(
    endpoint_id: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[datetime] = None,
    limit: int = 50,
    skip: int = 0,
) -> tuple[list[EventInDB], int]:
    """Query events with filters."""
    db = get_db()
    
    # Build query
    query = {}
    if endpoint_id:
        query["endpoint_id"] = endpoint_id
    if event_type:
        query["event_type"] = event_type
    if since:
        query["timestamp"] = {"$gte": since}
    
    # Get total count
    total = await db.events.count_documents(query)
    
    # Get events
    events = []
    cursor = db.events.find(query).sort("timestamp", DESCENDING).skip(skip).limit(limit)
    
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        events.append(EventInDB(**doc))
    
    return events, total


# ============================================================================
# Detection Operations
# ============================================================================

from .models import (
    DetectionCreate,
    DetectionInDB,
    DetectionStatus,
    DetectionStats,
    Severity,
)


async def insert_detection(detection: DetectionCreate) -> DetectionInDB:
    """Insert a new detection."""
    db = get_db()
    now = datetime.utcnow()
    
    doc = {
        "detection_type": detection.detection_type.value,
        "severity": detection.severity.value,
        "title": detection.title,
        "description": detection.description,
        "endpoint_id": detection.endpoint_id,
        "ml_confidence": detection.ml_confidence,
        "mitre_technique": detection.mitre_technique,
        "related_event_ids": detection.related_event_ids,
        "status": DetectionStatus.NEW.value,
        "created_at": now,
        "updated_at": now,
        "assigned_to": None,
        "notes": "",
    }
    
    result = await db.detections.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return DetectionInDB(**doc)


async def get_detections(
    endpoint_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
) -> tuple[list[DetectionInDB], int]:
    """Query detections with filters."""
    db = get_db()
    
    # Build query
    query = {}
    if endpoint_id:
        query["endpoint_id"] = endpoint_id
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
        ]
    
    # Get total count
    total = await db.detections.count_documents(query)
    
    # Get detections
    detections = []
    cursor = db.detections.find(query).sort("created_at", DESCENDING).skip(skip).limit(limit)
    
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        detections.append(DetectionInDB(**doc))
    
    return detections, total


async def update_detection_status(detection_id: str, new_status: DetectionStatus, notes: str = "") -> bool:
    """Update detection status."""
    db = get_db()
    from bson import ObjectId
    
    update = {
        "$set": {
            "status": new_status.value,
            "updated_at": datetime.utcnow(),
        }
    }
    if notes:
        update["$set"]["notes"] = notes
    
    result = await db.detections.update_one(
        {"_id": ObjectId(detection_id)},
        update
    )
    return result.modified_count > 0


async def get_detection_stats() -> DetectionStats:
    """Get detection statistics."""
    db = get_db()
    
    pipeline = [
        {
            "$group": {
                "_id": None,
                "total": {"$sum": 1},
                "new": {"$sum": {"$cond": [{"$eq": ["$status", "new"]}, 1, 0]}},
                "investigating": {"$sum": {"$cond": [{"$eq": ["$status", "investigating"]}, 1, 0]}},
                "resolved": {"$sum": {"$cond": [{"$eq": ["$status", "resolved"]}, 1, 0]}},
            }
        }
    ]
    
    result = await db.detections.aggregate(pipeline).to_list(1)
    
    if not result:
        return DetectionStats()
    
    stats = result[0]
    
    # Get counts by severity
    severity_pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
    severity_result = await db.detections.aggregate(severity_pipeline).to_list(10)
    by_severity = {item["_id"]: item["count"] for item in severity_result}
    
    # Get counts by type
    type_pipeline = [{"$group": {"_id": "$detection_type", "count": {"$sum": 1}}}]
    type_result = await db.detections.aggregate(type_pipeline).to_list(10)
    by_type = {item["_id"]: item["count"] for item in type_result}
    
    return DetectionStats(
        total=stats.get("total", 0),
        new=stats.get("new", 0),
        investigating=stats.get("investigating", 0),
        resolved=stats.get("resolved", 0),
        by_severity=by_severity,
        by_type=by_type,
    )

