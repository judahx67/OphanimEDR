"""
THEIA E3 (CDM18) normalizer.

Maps a structured, type-resolved edge event from the theia-replay service into a
NormalizedEvent. The replay has already resolved CDM node types and extracted
cmdLine/path, so this layer just translates to the graph schema and preserves the
native CDM fields (action / exec / path / cdm types) under `properties` so the
GNN scorer can rebuild the FLASH token document downstream.

raw_event dict shape (from theia-replay):
  {dataset, actor_id, actor_cdm, object_id, object_cdm, action, exec, path,
   timestamp, label}
"""

import hashlib
from typing import Optional

from schema import EdgeType, NodeType, NormalizedEvent, ProvenanceNode

# CDM18 object type -> graph NodeType (display/label only; the GNN reads the raw
# cdm type from properties). Defaults to FILE for unknown object kinds.
_CDM_NODE = {
    "SUBJECT_PROCESS": NodeType.PROCESS,
    "FILE_OBJECT_BLOCK": NodeType.FILE,
    "FILE_OBJECT_FILE": NodeType.FILE,
    "FILE_OBJECT_DIR": NodeType.FILE,
    "NetFlowObject": NodeType.SOCKET,
    "MemoryObject": NodeType.MEMORY,
    "UnnamedPipeObject": NodeType.PIPE,
    "PRINCIPAL_LOCAL": NodeType.USER,
    "PRINCIPAL_REMOTE": NodeType.USER,
}

# CDM18 EVENT_* -> nearest causal EdgeType. The GNN uses the raw action string
# from properties for its token doc, so this mapping is for graph display only.
_CDM_EDGE = {
    "EVENT_EXECUTE": EdgeType.EXEC,
    "EVENT_CLONE": EdgeType.FORK,
    "EVENT_FORK": EdgeType.FORK,
    "EVENT_READ": EdgeType.READ,
    "EVENT_READ_SOCKET_PARAMS": EdgeType.READ,
    "EVENT_OPEN": EdgeType.READ,
    "EVENT_RECVFROM": EdgeType.RECEIVE,
    "EVENT_RECVMSG": EdgeType.RECEIVE,
    "EVENT_WRITE": EdgeType.WRITE,
    "EVENT_WRITE_SOCKET_PARAMS": EdgeType.WRITE,
    "EVENT_MODIFY_FILE_ATTRIBUTES": EdgeType.WRITE,
    "EVENT_SENDTO": EdgeType.SEND,
    "EVENT_SENDMSG": EdgeType.SEND,
    "EVENT_CONNECT": EdgeType.CONNECT,
    "EVENT_MMAP": EdgeType.MMAP,
    "EVENT_MPROTECT": EdgeType.MMAP,
    "EVENT_SHM": EdgeType.MMAP,
    "EVENT_UNLINK": EdgeType.DELETE,
}


def _event_id(actor: str, obj: str, action: str, ts: str) -> str:
    return hashlib.sha1(f"{actor}|{obj}|{action}|{ts}".encode()).hexdigest()


def normalize_theia_event(d: dict) -> Optional[NormalizedEvent]:
    actor = d.get("actor_id")
    obj = d.get("object_id")
    action = d.get("action", "")
    if not actor or not obj or not action:
        return None

    edge_type = _CDM_EDGE.get(action)
    if edge_type is None:
        return None  # action carries no causal edge we model

    exec_cmd = d.get("exec") or ""
    path = d.get("path") or ""
    actor_cdm = d.get("actor_cdm", "SUBJECT_PROCESS")
    object_cdm = d.get("object_cdm", "FILE_OBJECT_BLOCK")
    try:
        ts = int(d.get("timestamp") or 0)
    except (TypeError, ValueError):
        ts = 0

    subject = ProvenanceNode(
        node_type=_CDM_NODE.get(actor_cdm, NodeType.PROCESS),
        id=actor,
        name=exec_cmd or f"process:{actor[:8]}",
        properties={"cdm_type": actor_cdm},
    )
    obj_node = ProvenanceNode(
        node_type=_CDM_NODE.get(object_cdm, NodeType.FILE),
        id=obj,
        name=path or f"{object_cdm}:{obj[:8]}",
        properties={"cdm_type": object_cdm},
    )

    # Native CDM fields the GNN scorer needs to rebuild the FLASH token document.
    props = {
        "dataset": "theia",
        "action": action,
        "exec": exec_cmd,
        "path": path,
        "actor_cdm": actor_cdm,
        "object_cdm": object_cdm,
        "label": d.get("label", 0),
    }

    return NormalizedEvent(
        event_id=_event_id(actor, obj, action, str(ts)),
        timestamp=ts,
        endpoint_id="theia",
        edge_type=edge_type,
        subject=subject,
        object=obj_node,
        properties=props,
        raw_event=None,
        sourcetype="cdm18_theia",
    )
