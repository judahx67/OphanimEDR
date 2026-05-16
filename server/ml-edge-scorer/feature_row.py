"""
Build a feature dict from a NormalizedEvent for LightGBM scoring.

For BOTSv2 events (_raw + sourcetype set on the event) we re-run the
botsv2_parsers dispatch to fill the content features. If `_raw` is missing
or the parser returns nothing useful, only the graph-triple features are
populated and the score is flagged as "degraded".

Output is a flat dict matching the 42-column model feature schema:
  sourcetype, subject_type, object_type, edge_type,
  external_ip, src_ip, dest_ip,
  + NUMERIC_FEATURES + CATEGORICAL_FEATURES
"""
from __future__ import annotations

from botsv2_parsers import get_parser
from botsv2_parsers.parsers import NUMERIC_FEATURES, CATEGORICAL_FEATURES

_PRIVATE_PREFIXES = ("10.", "192.168.")
_PRIVATE_172 = tuple(f"172.{i}." for i in range(16, 32))


def _is_private(ip: str | None) -> bool:
    if not ip or not isinstance(ip, str):
        return True
    return ip.startswith(_PRIVATE_PREFIXES) or ip.startswith(_PRIVATE_172)


def _external_ip(src: str | None, dst: str | None) -> str | None:
    """Return the non-RFC-1918 endpoint; falls back to dst if both private."""
    if not _is_private(src):
        return src
    if not _is_private(dst):
        return dst
    return dst

# BOTSv2 NodeType strings → model-schema strings (PascalCase to match training data)
# The training data used the BOTSv2 schema NodeType which is already PascalCase.
# The live NormalizedEvent uses UPPER_CASE. We map here.
_NODE_TYPE_MAP = {
    "PROCESS": "Process",
    "FILE": "File",
    "SOCKET": "Socket",
    "REGISTRY": "Registry",
    "PIPE": "Pipe",
    "MEMORY": "Memory",
    "HOST": "Host",
    "USER": "User",
    "URL": "Url",
}

# EdgeType is all-caps in both schemas; no mapping needed.


def build_feature_row(event_dict: dict) -> tuple[dict, str]:
    """
    Build a feature row for the LightGBM model from a NormalizedEvent dict.

    Returns (feature_dict, quality) where quality is:
      "full"     — _raw present and parsed cleanly
      "degraded" — no _raw or parser returned empty content fields
    """
    raw = event_dict.get("raw_event") or ""
    sourcetype = event_dict.get("sourcetype") or ""

    # Graph triple from NormalizedEvent fields
    subject = event_dict.get("subject") or {}
    obj = event_dict.get("object") or {}
    subject_type_raw = subject.get("node_type", "")
    object_type_raw = obj.get("node_type", "")
    edge_type = event_dict.get("edge_type", "")

    subject_type = _NODE_TYPE_MAP.get(subject_type_raw, subject_type_raw)
    object_type = _NODE_TYPE_MAP.get(object_type_raw, object_type_raw)

    # Network IPs from graph nodes or properties
    props = event_dict.get("properties", {})
    src_ip = props.get("src_ip") or subject.get("ip") or None
    dest_ip = props.get("dest_ip") or obj.get("ip") or None
    external_ip = _external_ip(src_ip, dest_ip)

    row: dict = {
        "sourcetype": sourcetype or None,
        "subject_type": subject_type or None,
        "object_type": object_type or None,
        "edge_type": edge_type or None,
        "external_ip": external_ip,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
    }

    # Numeric + categorical defaults
    for c in NUMERIC_FEATURES:
        row[c] = None
    for c in CATEGORICAL_FEATURES:
        if c not in row:  # don't overwrite src_ip/dest_ip already set above
            row[c] = None

    quality = "degraded"

    if raw and sourcetype:
        parser = get_parser(sourcetype)
        parsed = parser(raw, event_dict.get("endpoint_id"))

        if parsed.fields:
            for k, v in parsed.fields.items():
                if k in row:
                    row[k] = v
            quality = "full"

        # Also pick up botsv2_fields if the normalizer already cached them
        # (avoids double-parsing when ingest already did the work).
    elif event_dict.get("properties", {}).get("botsv2_fields"):
        cached = event_dict["properties"]["botsv2_fields"]
        for k, v in cached.items():
            if k in row:
                row[k] = v
        quality = "full"

    return row, quality
