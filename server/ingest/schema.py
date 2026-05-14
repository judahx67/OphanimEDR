"""
Normalized provenance graph event schema.

Node types and edge types based on DARPA TC program / ActMiner paper conventions.
Designed for causal provenance tracking from system audit logs.

9 Node Types:
  PROCESS   - Running process (pid, exe, cmdline, user)
  FILE      - File on disk (path)
  SOCKET    - Network socket (ip:port)
  REGISTRY  - Windows registry key (key path)
  MEMORY    - Memory-mapped region
  PIPE      - IPC pipe / named pipe
  HOST      - Network host / machine (BOTSv2 / Splunk sources)
  USER      - User account (BOTSv2 login/DB events)
  URL       - HTTP URL (BOTSv2 web traffic)

Edge Types (causal relationships):
  FORK      - Process spawns child process       (proc -> proc)
  EXEC      - Process executes a binary          (proc -> file)
  READ      - Process reads file/socket          (file/socket -> proc)
  WRITE     - Process writes to file/socket      (proc -> file/socket)
  CONNECT   - Process opens network connection   (proc -> socket)
  SEND      - Process sends data over socket     (proc -> socket)
  RECEIVE   - Process receives data from socket  (socket -> proc)
  MMAP      - Process memory-maps a file         (proc -> file)
  RENAME    - Process renames/moves a file       (proc -> file)
  DELETE    - Process deletes a file             (proc -> file)
  LOAD      - Process loads library/module       (proc -> file)
  MODIFY_REG- Process modifies registry          (proc -> registry)
  ACCESS    - Host/process accesses URL/resource (host -> url, BOTSv2 HTTP)
  AUTH      - Authentication event               (user -> host, BOTSv2 logins)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Edge types (causal operations)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Normalized event: one event = one edge in the provenance graph
# ---------------------------------------------------------------------------

class ProvenanceNode(BaseModel):
    """A node in the provenance graph (entity)."""
    node_type: NodeType
    id: str = Field(..., description="Unique ID within the dataset (e.g. uuid from THEIA)")
    name: str = Field(..., description="Human-readable name (exe path, file path, ip:port)")
    properties: dict[str, Any] = Field(default_factory=dict)


class NormalizedEvent(BaseModel):
    """
    A single normalized provenance event.
    Each event represents one causal edge: subject --[action]--> object.
    """
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: int = Field(..., description="Unix timestamp in nanoseconds (DARPA TC format)")
    endpoint_id: str = Field(default="theia-e3", description="Source host/endpoint")

    # Edge
    edge_type: EdgeType

    # Subject (source node - usually a process)
    subject: ProvenanceNode

    # Object (destination node - file, socket, process, etc.)
    object: ProvenanceNode

    # Extra metadata
    size: Optional[int] = Field(None, description="Bytes transferred (for read/write/send/recv)")
    properties: dict[str, Any] = Field(default_factory=dict)

    # BOTSv2 / Splunk passthrough — None for THEIA events
    raw_event: Optional[str] = Field(None, description="Original Splunk _raw field for feature re-extraction")
    sourcetype: Optional[str] = Field(None, description="Splunk sourcetype (e.g. XmlWinEventLog..._Sysmon, stream_http)")


# ---------------------------------------------------------------------------
# Raw THEIA event (before normalization)
# ---------------------------------------------------------------------------

class RawTheiaEvent(BaseModel):
    """
    Raw event as it arrives from the DARPA THEIA E3 dataset or agent.
    This is the format pushed to the raw RabbitMQ queue.
    """
    datum: dict[str, Any] = Field(..., description="Raw CDM datum from THEIA JSON")


class RawSplunkEvent(BaseModel):
    """
    Raw Splunk event as published by the BOTSv2 simulator mode.
    Pushed to the same raw_events queue; ingest branches on SOURCE_FORMAT=botsv2.
    Field name matches the dict key published by the simulator.
    """
    model_config = {"populate_by_name": True}

    raw_event: str = Field(..., alias="_raw", description="Original Splunk _raw log line")
    sourcetype: str = Field(..., description="Splunk sourcetype")
    host: Optional[str] = Field(None, description="Source host/endpoint")
    event_time: Optional[int] = Field(None, alias="_time", description="Unix epoch seconds")
    label: Optional[int] = Field(None, description="Ground-truth label (1=malicious, 0=benign)")
    scenario: Optional[str] = Field(None, description="BOTSv2 scenario tag")
