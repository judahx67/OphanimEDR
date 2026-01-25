"""FastAPI application for EDR Management Server."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .database import (
    connect_db,
    close_db,
    register_endpoint,
    get_endpoint,
    get_all_endpoints,
    update_heartbeat,
    insert_events,
    get_events,
)
from .models import (
    EndpointRegistration,
    EndpointResponse,
    EndpointListResponse,
    EventBatch,
    EventListResponse,
    HealthResponse,
    RegistrationResponse,
    EventsReceivedResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - connect/disconnect database."""
    await connect_db()
    yield
    await close_db()


# OpenAPI tag metadata for Swagger docs
tags_metadata = [
    {
        "name": "Health",
        "description": "Server health and status checks",
    },
    {
        "name": "Endpoints",
        "description": "Manage EDR agent endpoints - registration, status, heartbeat",
    },
    {
        "name": "Events",
        "description": "Event ingestion and querying from agent telemetry",
    },
    {
        "name": "Detections",
        "description": "Security detections and alerts from ML analysis",
    },
    {
        "name": "Agents",
        "description": "Agent distribution and configuration",
    },
]

app = FastAPI(
    title="Ophanim EDR Server",
    description="""
## Ophanim EDR Management Server

RESTful API for managing EDR agents, collecting telemetry, and viewing security detections.

### Features
- **Endpoint Management**: Register and monitor Windows endpoints
- **Event Collection**: Ingest process, file, and network events
- **Detection Engine**: ML-powered threat detection (Phase 5)
- **Real-time Monitoring**: WebSocket support for live updates

### Authentication
Currently using API key authentication via `X-API-Key` header (development mode).
    """,
    version=__version__,
    lifespan=lifespan,
    openapi_tags=tags_metadata,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check
# ============================================================================

@app.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Check server health and database connection."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        database="connected",
    )


# ============================================================================
# Endpoint Management
# ============================================================================

@app.post("/api/endpoints/register", response_model=RegistrationResponse, tags=["Endpoints"])
async def register_agent(registration: EndpointRegistration):
    """Register a new agent or update existing registration."""
    endpoint = await register_endpoint(registration)
    return RegistrationResponse(
        success=True,
        endpoint_id=endpoint.endpoint_id,
        message=f"Endpoint {endpoint.hostname} registered successfully",
    )


@app.get("/api/endpoints", response_model=EndpointListResponse, tags=["Endpoints"])
async def list_endpoints():
    """Get list of all registered endpoints."""
    endpoints = await get_all_endpoints()
    return EndpointListResponse(
        endpoints=endpoints,
        total=len(endpoints),
    )


@app.get("/api/endpoints/{endpoint_id}", response_model=EndpointResponse, tags=["Endpoints"])
async def get_endpoint_details(endpoint_id: str):
    """Get details for a specific endpoint."""
    endpoint = await get_endpoint(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint


@app.post("/api/endpoints/{endpoint_id}/heartbeat", tags=["Endpoints"])
async def endpoint_heartbeat(endpoint_id: str):
    """Update endpoint heartbeat timestamp."""
    success = await update_heartbeat(endpoint_id)
    if not success:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    return {"success": True, "message": "Heartbeat received"}


# ============================================================================
# Event Ingestion
# ============================================================================

@app.post("/api/events", response_model=EventsReceivedResponse, tags=["Events"])
async def receive_events(batch: EventBatch):
    """Receive a batch of events from an agent."""
    # Ensure all events have the correct endpoint_id
    for event in batch.events:
        event.endpoint_id = batch.endpoint_id
    
    count = await insert_events(batch.events)
    return EventsReceivedResponse(
        success=True,
        received_count=count,
        message=f"Received {count} events from {batch.endpoint_id}",
    )


@app.get("/api/events", response_model=EventListResponse, tags=["Events"])
async def query_events(
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    hours: int = Query(24, description="Events from last N hours"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Events per page"),
):
    """Query events with optional filters."""
    since = datetime.utcnow() - timedelta(hours=hours)
    skip = (page - 1) * page_size
    
    events, total = await get_events(
        endpoint_id=endpoint_id,
        event_type=event_type,
        since=since,
        limit=page_size,
        skip=skip,
    )
    
    return EventListResponse(
        events=events,
        total=total,
        page=page,
        page_size=page_size,
    )


# ============================================================================
# Detections API
# ============================================================================

from .database import get_detections, get_detection_stats, insert_detection, update_detection_status
from .models import DetectionListResponse, DetectionStats, DetectionCreate, DetectionResponse, DetectionStatus


@app.get("/api/detections", response_model=DetectionListResponse, tags=["Detections"])
async def query_detections(
    endpoint_id: Optional[str] = Query(None, description="Filter by endpoint"),
    severity: Optional[str] = Query(None, description="Filter by severity: low, medium, high, critical"),
    status: Optional[str] = Query(None, description="Filter by status: new, investigating, resolved, false_positive"),
    search: Optional[str] = Query(None, description="Search in title and description"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Detections per page"),
):
    """Query detections with optional filters and search."""
    skip = (page - 1) * page_size
    
    detections, total = await get_detections(
        endpoint_id=endpoint_id,
        severity=severity,
        status=status,
        search=search,
        limit=page_size,
        skip=skip,
    )
    
    return DetectionListResponse(
        detections=detections,
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get("/api/detections/stats", response_model=DetectionStats, tags=["Detections"])
async def detections_statistics():
    """Get detection statistics summary."""
    return await get_detection_stats()


@app.post("/api/detections", response_model=DetectionResponse, tags=["Detections"])
async def create_detection(detection: DetectionCreate):
    """Create a new detection (typically called by ML engine)."""
    return await insert_detection(detection)


@app.patch("/api/detections/{detection_id}/status", tags=["Detections"])
async def update_status(
    detection_id: str,
    status: DetectionStatus = Query(..., description="New status"),
    notes: str = Query("", description="Optional notes"),
):
    """Update detection investigation status."""
    success = await update_detection_status(detection_id, status, notes)
    if not success:
        raise HTTPException(status_code=404, detail="Detection not found")
    return {"success": True, "message": f"Status updated to {status.value}"}


# ============================================================================
# Seed Data (for development/demo)
# ============================================================================

@app.post("/api/seed", tags=["Development"])
async def seed_demo_data():
    """Seed the database with demo data for testing."""
    from .database import get_db
    import random
    import uuid
    
    db = get_db()
    now = datetime.utcnow()
    
    # Clear existing data
    await db.endpoints.delete_many({})
    await db.events.delete_many({})
    await db.detections.delete_many({})
    
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
    
    await db.endpoints.insert_many(endpoints)
    
    # Demo events
    event_types = ["process_start", "process_end", "file_created", "file_modified", "network_connection"]
    process_names = ["chrome.exe", "notepad.exe", "powershell.exe", "cmd.exe", "python.exe", "code.exe", "explorer.exe"]
    
    events = []
    for endpoint in endpoints[:3]:
        for i in range(50):
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
    
    await db.events.insert_many(events)
    
    # Demo detections
    detections = [
        {
            "detection_type": "suspicious_process",
            "severity": "critical",
            "title": "Suspicious PowerShell with encoded command",
            "description": "PowerShell executed with Base64 encoded command line, commonly used by malware for obfuscation.",
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
            "title": "Unusual network connection to rare destination",
            "description": "Process established connection to IP address not seen in baseline, potential C2 communication.",
            "endpoint_id": endpoints[2]["endpoint_id"],
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
            "description": "File hash matches known Emotet variant. Immediate containment recommended.",
            "endpoint_id": endpoints[1]["endpoint_id"],
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
            "title": "System file modification detected",
            "description": "Modification to hosts file detected, may indicate DNS hijacking attempt.",
            "endpoint_id": endpoints[0]["endpoint_id"],
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
            "description": "Process attempted to access LSASS memory, common in credential theft attacks.",
            "endpoint_id": endpoints[2]["endpoint_id"],
            "ml_confidence": 0.91,
            "mitre_technique": "T1003.001",
            "related_event_ids": [],
            "status": "new",
            "created_at": now - timedelta(hours=1),
            "updated_at": now - timedelta(hours=1),
            "assigned_to": None,
            "notes": "",
        },
    ]
    
    await db.detections.insert_many(detections)
    
    return {
        "success": True,
        "message": "Demo data seeded successfully",
        "seeded": {
            "endpoints": len(endpoints),
            "events": len(events),
            "detections": len(detections),
        }
    }


# ============================================================================
# Agent Download (placeholder for now)
# ============================================================================

@app.get("/api/agents/download/{endpoint_id}", tags=["Agents"])
async def download_agent(endpoint_id: str):
    """Download a pre-configured agent executable."""
    # TODO: Implement agent building with embedded config
    return {
        "message": "Agent download not yet implemented",
        "endpoint_id": endpoint_id,
        "instructions": "Use scripts/build.ps1 to build the agent manually",
    }


# ============================================================================
# Entry Point
# ============================================================================

def main():
    """Run the server with uvicorn."""
    import uvicorn
    uvicorn.run(
        "edr_server.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
