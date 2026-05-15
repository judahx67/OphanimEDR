"""Shared schema - symlinked or copied from ingest/schema.py."""

# Re-export everything from the canonical schema
# In Docker, we copy this file. Locally, import from ingest.
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    PROCESS = "PROCESS"
    FILE = "FILE"
    SOCKET = "SOCKET"
    REGISTRY = "REGISTRY"
    MEMORY = "MEMORY"
    PIPE = "PIPE"
    # BOTSv2 / Splunk superset
    HOST = "HOST"
    USER = "USER"
    URL = "URL"


class EdgeType(str, Enum):
    FORK = "FORK"
    EXEC = "EXEC"
    READ = "READ"
    WRITE = "WRITE"
    CONNECT = "CONNECT"
    SEND = "SEND"
    RECEIVE = "RECEIVE"
    MMAP = "MMAP"
    RENAME = "RENAME"
    DELETE = "DELETE"
    LOAD = "LOAD"
    MODIFY_REG = "MODIFY_REG"
    # BOTSv2 / Splunk superset
    ACCESS = "ACCESS"
    AUTH = "AUTH"


class ProvenanceNode(BaseModel):
    node_type: NodeType
    id: str
    name: str
    properties: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: int
    endpoint_id: str = "botsv2"
    edge_type: EdgeType
    subject: ProvenanceNode
    object: ProvenanceNode
    size: Optional[int] = None
    properties: dict[str, Any] = Field(default_factory=dict)
    raw_event: Optional[str] = None
    sourcetype: Optional[str] = None
