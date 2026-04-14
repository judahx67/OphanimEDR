"""Pydantic models for EDR Server API (Neo4j backend)."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Incident models  (primary output of the rule engine)
# ---------------------------------------------------------------------------

class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentInDB(BaseModel):
    """An incident as stored in Neo4j and returned by the API."""
    incident_id: str
    rule_id: str
    rule_name: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    title: str
    description: str = ""
    mitre_technique: Optional[str] = None
    endpoint_id: str = "theia-e3"

    # Causal subgraph snapshot (serialized lists)
    matched_nodes: list[dict[str, Any]] = Field(default_factory=list)
    matched_edges: list[dict[str, Any]] = Field(default_factory=list)
    rule_conditions: list[str] = Field(default_factory=list)

    # Pivot: UUID of the root process that triggered the rule
    root_node_id: Optional[str] = None

    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""

    class Config:
        from_attributes = True


class IncidentListResponse(BaseModel):
    incidents: list[IncidentInDB]
    total: int
    page: int = 1
    page_size: int = 50


class IncidentStats(BaseModel):
    total: int = 0
    new: int = 0
    investigating: int = 0
    resolved: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Graph stats
# ---------------------------------------------------------------------------

class GraphStats(BaseModel):
    node_counts: dict[str, int] = Field(default_factory=dict)
    total_edges: int = 0
    total_incidents: int = 0
    new_incidents: int = 0
    process_count: int = 0
    file_count: int = 0
    socket_count: int = 0


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.2.0"
    database: str = "connected"
