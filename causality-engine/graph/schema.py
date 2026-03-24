"""
CDM-aligned provenance graph schema for Ophanim-EDR.

Defines the node and edge type vocabularies used throughout the causality engine.
These follow the Common Data Model (CDM) used by DARPA Transparent Computing
(TC) program, which is the standard schema for provenance-based threat detection
research (KAIROS, ORCHID, CAPTAIN all use CDM).

Node types correspond to OS-level entities that participate in system calls.
Edge types correspond to the causal relationships between those entities.

Feature dimensions per node type reflect the raw telemetry fields available
from Sysmon/ETW on Windows and auditd on Linux:
  - process(8):  pid, ppid, uid, gid, start_time, cmd_hash, privilege_level, session_id
  - file(4):     path_hash, size, permissions, inode
  - socket(6):   src_ip, src_port, dst_ip, dst_port, protocol, state
  - registry(5): hive, key_hash, value_hash, access_mask, data_type
  - memory(4):   base_addr, size, protection, mapped_file_hash
  - other(3):    type_indicator, timestamp, generic_hash
"""

from enum import IntEnum
from typing import Dict


class NodeType(IntEnum):
    """Six CDM entity types with their raw feature dimensionalities."""
    PROCESS = 0
    FILE = 1
    SOCKET = 2
    REGISTRY = 3
    MEMORY = 4
    OTHER = 5


# Raw feature dimensions per node type, before projection to common space.
NODE_FEATURE_DIMS: Dict[NodeType, int] = {
    NodeType.PROCESS: 8,
    NodeType.FILE: 4,
    NodeType.SOCKET: 6,
    NodeType.REGISTRY: 5,
    NodeType.MEMORY: 4,
    NodeType.OTHER: 3,
}

# Human-readable names for display/logging.
NODE_TYPE_NAMES: Dict[NodeType, str] = {
    NodeType.PROCESS: "process",
    NodeType.FILE: "file",
    NodeType.SOCKET: "socket",
    NodeType.REGISTRY: "registry",
    NodeType.MEMORY: "memory",
    NodeType.OTHER: "other",
}


class EdgeType(IntEnum):
    """
    Nine CDM edge types representing causal relationships.

    These are the 9 system-call classes used by KAIROS for edge-type prediction
    (cross-entropy over 9 classes). They cover the fundamental OS interactions
    observable through provenance tracking:

      Data flow:    WRITE, READ
      Execution:    EXECUTE, FORK_CLONE
      Networking:   CONNECT, SEND, RECEIVE
      Memory:       MMAP
      Filesystem:   RENAME_LINK
    """
    WRITE = 0
    READ = 1
    EXECUTE = 2
    FORK_CLONE = 3
    CONNECT = 4
    SEND = 5
    RECEIVE = 6
    MMAP = 7
    RENAME_LINK = 8


NUM_NODE_TYPES = len(NodeType)   # 6
NUM_EDGE_TYPES = len(EdgeType)   # 9

# Common embedding dimension after NodeTypeProjection.
EMBEDDING_DIM = 64
