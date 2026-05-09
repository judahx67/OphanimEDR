"""
BOTSv2 / Splunk ingest normalizer.

Converts raw Splunk events (from the BOTSv2 simulator mode) into
NormalizedEvent objects, using the shared botsv2_parsers package.

Each Splunk message on the raw_events queue is a JSON dict:
  {
    "_raw":       str,   # original log line
    "sourcetype": str,   # e.g. "XmlWinEventLog_..._Sysmon", "stream_http"
    "host":       str,   # producing machine
    "_time":      int,   # unix epoch seconds
    "label":      int,   # 0/1 ground-truth (present only in BOTSv2 replay)
    "scenario":   str,   # BOTSv2 scenario tag
  }

Returns None for events where the parser yields an empty graph triple
(no subject/object/edge) — these are dropped by the ingest main loop.
"""
from __future__ import annotations

import uuid as _uuid
from typing import Optional

from botsv2_parsers import get_parser
from botsv2_parsers.parsers import NodeType as BNodeType, EdgeType as BEdgeType

from schema import (
    EdgeType, NodeType, NormalizedEvent, ProvenanceNode,
)

# Map BOTSv2 parser NodeType strings → live ingest NodeType enum
_NODE_MAP: dict[str, NodeType] = {
    BNodeType.PROCESS:  NodeType.PROCESS,
    BNodeType.FILE:     NodeType.FILE,
    BNodeType.SOCKET:   NodeType.SOCKET,
    BNodeType.REGISTRY: NodeType.REGISTRY,
    BNodeType.PIPE:     NodeType.PIPE,
    BNodeType.MEMORY:   NodeType.MEMORY,
    BNodeType.HOST:     NodeType.HOST,
    BNodeType.USER:     NodeType.USER,
    BNodeType.URL:      NodeType.URL,
}

# Map BOTSv2 parser EdgeType strings → live ingest EdgeType enum
_EDGE_MAP: dict[str, EdgeType] = {
    BEdgeType.FORK:       EdgeType.FORK,
    BEdgeType.EXEC:       EdgeType.EXEC,
    BEdgeType.READ:       EdgeType.READ,
    BEdgeType.WRITE:      EdgeType.WRITE,
    BEdgeType.CONNECT:    EdgeType.CONNECT,
    BEdgeType.SEND:       EdgeType.SEND,
    BEdgeType.RECEIVE:    EdgeType.RECEIVE,
    BEdgeType.MMAP:       EdgeType.MMAP,
    BEdgeType.RENAME:     EdgeType.RENAME,
    BEdgeType.DELETE:     EdgeType.DELETE,
    BEdgeType.LOAD:       EdgeType.LOAD,
    BEdgeType.MODIFY_REG: EdgeType.MODIFY_REG,
    BEdgeType.ACCESS:     EdgeType.ACCESS,
    BEdgeType.AUTH:       EdgeType.AUTH,
}


def normalize_splunk_event(msg: dict) -> Optional[NormalizedEvent]:
    """
    Normalize a single BOTSv2 Splunk message dict → NormalizedEvent.

    Returns None if the parser yields no usable graph triple.
    """
    raw = msg.get("_raw") or ""
    sourcetype = msg.get("sourcetype") or ""
    host = msg.get("host")
    time_epoch_s = msg.get("_time")

    parser = get_parser(sourcetype)
    parsed = parser(raw, host)

    if not parsed.has_graph_triple:
        return None

    # Map types — drop if unknown
    node_type_subj = _NODE_MAP.get(parsed.subject_type)
    node_type_obj = _NODE_MAP.get(parsed.object_type)
    edge_type = _EDGE_MAP.get(parsed.edge_type)
    if not (node_type_subj and node_type_obj and edge_type):
        return None

    # Require both node IDs for graph linkage
    if not parsed.subject_id or not parsed.object_id:
        return None

    # Timestamp: BOTSv2 _time is epoch seconds; convert to nanoseconds for
    # schema parity with THEIA (which uses nanos throughout).
    ts_ns = int(time_epoch_s) * 1_000_000_000 if time_epoch_s else 0

    subj = ProvenanceNode(
        node_type=node_type_subj,
        id=parsed.subject_id,
        name=parsed.subject_name or parsed.subject_id,
        properties={},
    )
    obj = ProvenanceNode(
        node_type=node_type_obj,
        id=parsed.object_id,
        name=parsed.object_name or parsed.object_id,
        properties={},
    )

    props: dict = {}
    # Carry ground-truth label through as a property so the rule engine /
    # dashboard can show whether an event was known-malicious (thesis only).
    label = msg.get("label")
    if label is not None:
        props["botsv2_label"] = int(label)
    scenario = msg.get("scenario")
    if scenario:
        props["botsv2_scenario"] = scenario
    # Carry content fields as properties so the scorer can skip re-parsing
    # for simple numeric/categorical features when _raw is available.
    if parsed.fields:
        props["botsv2_fields"] = parsed.fields

    return NormalizedEvent(
        event_id=str(_uuid.uuid4()),
        timestamp=ts_ns,
        endpoint_id=host or "botsv2",
        edge_type=edge_type,
        subject=subj,
        object=obj,
        size=parsed.fields.get("bytes"),
        properties=props,
        raw_event=raw,
        sourcetype=sourcetype,
    )
