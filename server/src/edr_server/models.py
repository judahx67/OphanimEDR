"""Pydantic models for EDR Server API."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AgentStatus(str, Enum):
    """Agent connection status."""
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class OSType(str, Enum):
    """Operating system type."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


# ============================================================================
# Endpoint Models
# ============================================================================

class EndpointBase(BaseModel):
    """Base endpoint information."""
    hostname: str = Field(..., description="System hostname")
    ip_address: str = Field(..., description="Primary IP address")
    os_type: OSType = Field(default=OSType.WINDOWS)
    os_version: str = Field(default="", description="OS version string")
    agent_version: str = Field(default="0.1.0")


class EndpointRegistration(EndpointBase):
    """Request model for agent registration."""
    endpoint_id: str = Field(..., description="Unique endpoint identifier")


class EndpointInDB(EndpointBase):
    """Endpoint stored in database."""
    endpoint_id: str
    status: AgentStatus = AgentStatus.UNKNOWN
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    events_today: int = 0
    policy: str = "default"

    class Config:
        from_attributes = True


class EndpointResponse(EndpointInDB):
    """Response model for endpoint details."""
    pass


class EndpointListResponse(BaseModel):
    """Response model for endpoints list."""
    endpoints: list[EndpointResponse]
    total: int


# ============================================================================
# Event Models
# ============================================================================

class EventType(str, Enum):
    """Types of events collected by agent."""
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    PROCESS_SNAPSHOT = "process_snapshot"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_MOVED = "file_moved"
    SYSMON_EVENT = "sysmon_event"
    NETWORK_CONNECTION = "network_connection"


class EventBase(BaseModel):
    """Base event structure."""
    event_type: str = Field(..., description="Type of event")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    endpoint_id: str = Field(..., description="Source endpoint")
    data: dict[str, Any] = Field(default_factory=dict)


class EventCreate(EventBase):
    """Request model for creating events."""
    pass


class EventBatch(BaseModel):
    """Batch of events from agent."""
    events: list[EventCreate]
    endpoint_id: str


class EventInDB(EventBase):
    """Event stored in database."""
    id: str = Field(default="", alias="_id")
    received_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True
        populate_by_name = True


class EventResponse(EventInDB):
    """Response model for event details."""
    pass


class EventListResponse(BaseModel):
    """Response model for events list."""
    events: list[EventResponse]
    total: int
    page: int = 1
    page_size: int = 50


# ============================================================================
# API Response Models
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str = "0.1.0"
    database: str = "connected"


class RegistrationResponse(BaseModel):
    """Response after successful registration."""
    success: bool = True
    endpoint_id: str
    message: str = "Registered successfully"
    server_time: datetime = Field(default_factory=datetime.utcnow)


class EventsReceivedResponse(BaseModel):
    """Response after receiving events."""
    success: bool = True
    received_count: int
    message: str = "Events received"


# ============================================================================
# Detection Models (for ML/Alerts - Phase 5)
# ============================================================================

class Severity(str, Enum):
    """Detection severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionStatus(str, Enum):
    """Detection investigation status."""
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class DetectionType(str, Enum):
    """Types of detections from ML analysis."""
    ANOMALY = "anomaly"
    MALWARE = "malware"
    SUSPICIOUS_PROCESS = "suspicious_process"
    UNUSUAL_NETWORK = "unusual_network"
    FILE_TAMPERING = "file_tampering"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class DetectionBase(BaseModel):
    """Base detection/alert structure."""
    detection_type: DetectionType = Field(..., description="Type of detection")
    severity: Severity = Field(default=Severity.MEDIUM)
    title: str = Field(..., description="Short description")
    description: str = Field(default="", description="Detailed explanation")
    endpoint_id: str = Field(..., description="Affected endpoint")
    ml_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="ML model confidence")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")
    related_event_ids: list[str] = Field(default_factory=list)


class DetectionCreate(DetectionBase):
    """Request model for creating a detection."""
    pass


class DetectionInDB(DetectionBase):
    """Detection stored in database."""
    id: str = Field(default="", alias="_id")
    status: DetectionStatus = DetectionStatus.NEW
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    assigned_to: Optional[str] = None
    notes: str = ""

    class Config:
        from_attributes = True
        populate_by_name = True


class DetectionResponse(DetectionInDB):
    """Response model for detection details."""
    pass


class DetectionListResponse(BaseModel):
    """Response model for detections list."""
    detections: list[DetectionResponse]
    total: int
    page: int = 1
    page_size: int = 50


class DetectionStats(BaseModel):
    """Summary statistics for detections."""
    total: int = 0
    new: int = 0
    investigating: int = 0
    resolved: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)

