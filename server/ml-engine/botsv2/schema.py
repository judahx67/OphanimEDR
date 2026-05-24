"""Layer 2 schema — single source of truth for the BOTSv2 featured Parquet.

Imported by both extract_features.py (writes featured rows) and train.py
(reads them, picks the model-feature subset). Keep these in sync by importing
from here, never by hard-coding column lists in either script.

The featured row has three logical groups of columns:

  IDENTITY    metadata for splitting and bookkeeping. Some are leaky and dropped
              at train time; sourcetype is the only one kept as a feature.

  GRAPH       subject/object/edge triple. Required for downstream Neo4j push.
              Names and IDs are graph metadata only (dropped at train); the
              *types* and edge_type carry signal and are kept as features.

  CONTENT     numeric and categorical features extracted from _raw. The bulk
              of the model's input.

The model-feature view (what train.py feeds LightGBM) is:
    sourcetype, subject_type, object_type, edge_type,
    + NUMERIC_FEATURES + CATEGORICAL_FEATURES
    minus LEAKY_COLS

See docs/plans/botsv2-rebuild-from-zero.md for design rationale.
"""
from __future__ import annotations

# ──────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────

MAX_STR_LEN = 100  # truncation cap for every string column at parse time


# ──────────────────────────────────────────────────────────────────────────
# Enums (as plain string constants — Polars/pandas-friendly)
# ──────────────────────────────────────────────────────────────────────────

class NodeType:
    """Subject/object kinds. Superset of the Neo4j graph-builder labels.

    Process/File/Socket/Registry/Pipe/Memory match server/graph-builder/main.py
    LABELS exactly. Host/User/Url are BOTSv2-specific additions for events
    that don't have a clean process subject (HTTP requests, login events).
    """
    PROCESS = "Process"
    FILE = "File"
    SOCKET = "Socket"
    REGISTRY = "Registry"
    PIPE = "Pipe"
    MEMORY = "Memory"
    HOST = "Host"
    USER = "User"
    URL = "Url"


NODE_TYPES = frozenset({
    NodeType.PROCESS, NodeType.FILE, NodeType.SOCKET, NodeType.REGISTRY,
    NodeType.PIPE, NodeType.MEMORY, NodeType.HOST, NodeType.USER, NodeType.URL,
})


class EdgeType:
    """Edge kinds. Superset of the Neo4j graph-builder edge types.

    FORK..MODIFY_REG match server/graph-builder/main.py exactly.
    ACCESS = HTTP request (BOTSv2 has lots of these and they don't fit
             cleanly into READ/CONNECT — distinct semantics).
    AUTH   = login / authentication event (Windows Security 4624/4625 etc).
    """
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
    ACCESS = "ACCESS"
    AUTH = "AUTH"


EDGE_TYPES = frozenset({
    EdgeType.FORK, EdgeType.EXEC, EdgeType.READ, EdgeType.WRITE,
    EdgeType.CONNECT, EdgeType.SEND, EdgeType.RECEIVE, EdgeType.MMAP,
    EdgeType.RENAME, EdgeType.DELETE, EdgeType.LOAD, EdgeType.MODIFY_REG,
    EdgeType.ACCESS, EdgeType.AUTH,
})


# ──────────────────────────────────────────────────────────────────────────
# Column groups
# ──────────────────────────────────────────────────────────────────────────

# Identity / metadata. Carried in featured rows for splitting and bookkeeping.
IDENTITY_COLS = [
    "_time",       # Int64 epoch seconds — temporal-split key, dropped at train
    "source",      # String log file path — leaky (host-correlated), dropped at train
    "host",        # String producing machine — leaky, dropped at train
    "sourcetype",  # String partition tag — KEPT as feature (most predictive)
    "label",       # Int8 0/1 — the target
    "scenario",    # String s200/s300/s400/null — leaky (it IS the answer), dropped at train
]

# Graph triple. Required on every featured row that represents a real event.
# Stub rows from low-signal sourcetypes (Perfmon_*) may have nulls; the
# Phase-4 validation gate requires ≥80% non-null across the dataset.
GRAPH_TYPE_COLS = ["subject_type", "object_type", "edge_type"]
GRAPH_NAME_COLS = ["subject_name", "object_name"]    # human-readable, train-dropped
GRAPH_ID_COLS = ["subject_id", "object_id"]          # MERGE keys for Neo4j, train-dropped
GRAPH_COLS = GRAPH_TYPE_COLS + GRAPH_NAME_COLS + GRAPH_ID_COLS


# Numeric content features. Int64 with nulls where parser couldn't fill.
# LightGBM handles NaN natively; no imputation needed.
_BASE_NUMERIC_FEATURES = [
    "src_port", "dest_port",
    "http_status", "http_content_length",
    "bytes", "bytes_in", "bytes_out",
    "packets_in", "packets_out",
    "duration",
    "event_id",
    "process_id",
    "suricata_alert_severity",
]

# Engineered MITRE-derived boolean features (0/1). Computed by
# botsv2_parsers.engineered_features.compute(). Single source of truth shared
# by training (extract_features.py) and runtime (feature_row.py).
# Added inline so they're treated as standard numeric features by train.py.
import sys as _sys
from pathlib import Path as _Path
_SERVER_DIR = _Path(__file__).resolve().parents[2]
if str(_SERVER_DIR) not in _sys.path:
    _sys.path.insert(0, str(_SERVER_DIR))
try:
    from botsv2_parsers.engineered_features import FEATURE_NAMES as _ENG
except ImportError:
    _ENG: list[str] = []

NUMERIC_FEATURES = _BASE_NUMERIC_FEATURES + list(_ENG)

# Categorical content features. String, truncated to MAX_STR_LEN at parse time.
# Converted to pandas category at train time (codes aligned across train/val/test).
CATEGORICAL_FEATURES = [
    # Network identity — external_ip is the non-RFC-1918 endpoint of the flow,
    # direction-independent (C2 IP appears in src or dest depending on phase).
    # src_ip/dest_ip kept too for directional signal where it exists.
    "external_ip", "src_ip", "dest_ip",
    # Network metadata
    "transport", "protocol", "app_proto",
    # HTTP
    "http_method", "http_uri", "http_user_agent", "http_referrer",
    "http_content_type", "site",
    # DNS
    "dns_query", "dns_qtype", "dns_rcode",
    # Process / Sysmon
    "process_name", "image", "command_line", "parent_command_line",
    "parent_image",
    "user", "integrity_level", "registry_key", "registry_value",
    # Suricata
    "suricata_event_type", "suricata_alert_category",
    # Derived content features (2026-05-24) — promote attack-bearing tokens
    # out of object_name/image (which are dropped at train) into bounded-
    # cardinality categoricals the model can actually generalise across.
    "object_name_ext",   # last "." segment of object_name (e.g. ".crypt", ".dll", ".exe")
    "object_basename",   # last "/" or "\" segment of object_name (e.g. "winsys32.dll")
    "image_basename",    # basename of image (e.g. "powershell.exe")
    "target_dir",        # parent directory of object_name (e.g. "C:/Windows/System32")
]

# IPs are now features (see CATEGORICAL_FEATURES above).
NETWORK_ID_COLS = ["src_ip", "dest_ip"]


# Full union schema written by extract_features.py.
# NETWORK_ID_COLS (src_ip, dest_ip) are now in CATEGORICAL_FEATURES — not listed separately.
ALL_FEATURED_COLS = (
    IDENTITY_COLS
    + GRAPH_COLS
    + NUMERIC_FEATURES
    + CATEGORICAL_FEATURES
)


# ──────────────────────────────────────────────────────────────────────────
# Train-time drop lists
# ──────────────────────────────────────────────────────────────────────────

# Columns the model is forbidden from seeing. Kept in featured Parquet so
# leakage ablations can toggle them on/off without re-running FE.
LEAKY_COLS = [
    "_time",       # temporal info would let the model trivially overfit splits
    "source",      # log file path correlates with host
    "host",        # the answer is sometimes just "this host got compromised"
    "scenario",    # literally the label we're trying to predict
    "subject_id",  # high-cardinality graph merge key, not a content feature
    "object_id",   # same
    # src_ip / dest_ip moved to CATEGORICAL_FEATURES
]

# Graph-metadata columns the model doesn't need (the *types* are kept).
TRAIN_DROP_NAMES = ["subject_name", "object_name"]

# Low-value categoricals confirmed by the AutoGluon experiment. Near-unique
# values per row → no learnable signal, just memory and category-dict bloat.
LOW_VALUE_COLS = [
    "logon_id",
    "parent_image",
    "suricata_alert_signature",
]

# Final train-time drop set (label is separate, becomes y).
TRAIN_DROP_COLS = LEAKY_COLS + TRAIN_DROP_NAMES + LOW_VALUE_COLS


def model_feature_columns() -> list[str]:
    """The exact feature column list train.py feeds LightGBM (in order)."""
    keep = [
        "sourcetype",
        "subject_type", "object_type", "edge_type",
    ] + NUMERIC_FEATURES + CATEGORICAL_FEATURES
    return [c for c in keep if c not in TRAIN_DROP_COLS]


def model_categorical_columns() -> list[str]:
    """Subset of model_feature_columns() that LightGBM should treat as categorical."""
    cats = [
        "sourcetype",
        "subject_type", "object_type", "edge_type",
    ] + CATEGORICAL_FEATURES
    return [c for c in cats if c not in TRAIN_DROP_COLS]


# ──────────────────────────────────────────────────────────────────────────
# Subject/object ID derivation (deterministic, used by parsers)
# ──────────────────────────────────────────────────────────────────────────

def proc_id(host: str | None, pid: str | int | None, image: str | None) -> str | None:
    """Stable Process node id within an endpoint.

    Prefer pid (most specific); fall back to image basename so we still get a
    node for KV-parsed rows that don't carry pid.
    """
    h = (host or "?")
    if pid is not None and str(pid).strip() not in ("", "0"):
        return f"proc:{h}:{pid}"
    if image:
        base = image.replace("\\", "/").rsplit("/", 1)[-1]
        if base:
            return f"proc:{h}:{base}"
    return None


def file_id(host: str | None, path: str | None) -> str | None:
    if not path:
        return None
    h = (host or "?")
    return f"file:{h}:{path.lower()}"[:200]


def socket_id(
    src_ip: str | None, src_port: str | int | None,
    dest_ip: str | None, dest_port: str | int | None,
    transport: str | None,
) -> str | None:
    """5-tuple socket id. Contains IPs by design — used for graph linkage,
    never exposed to the model (subject_id/object_id are in LEAKY_COLS)."""
    if not (src_ip or dest_ip):
        return None
    t = (transport or "?").lower()
    return f"sock:{src_ip or '?'}:{src_port or '?'}->{dest_ip or '?'}:{dest_port or '?'}/{t}"


def registry_id(host: str | None, key: str | None) -> str | None:
    if not key:
        return None
    h = (host or "?")
    return f"reg:{h}:{key.lower()}"[:200]


def url_id(site: str | None, uri: str | None) -> str | None:
    if not (site or uri):
        return None
    return f"url:{site or ''}{uri or ''}"[:200]


def host_id(host: str | None) -> str | None:
    return f"host:{host}" if host else None


def user_id(host: str | None, user: str | None) -> str | None:
    if not user:
        return None
    h = (host or "?")
    return f"user:{h}:{user.lower()}"


# ──────────────────────────────────────────────────────────────────────────
# Self-check
# ──────────────────────────────────────────────────────────────────────────

def _validate() -> None:
    """Cheap structural checks. Run on import in __main__ block."""
    feat = set(model_feature_columns())
    cat = set(model_categorical_columns())
    assert cat.issubset(feat), f"categorical not subset of features: {cat - feat}"
    assert "label" not in feat, "label must not be a feature"
    assert not (feat & set(LEAKY_COLS)), f"leaky cols leaked into features: {feat & set(LEAKY_COLS)}"
    # Every numeric feature must NOT also be categorical
    assert not (set(NUMERIC_FEATURES) & set(CATEGORICAL_FEATURES)), "numeric/categorical overlap"
    # Every column in the featured Parquet must be unique
    assert len(ALL_FEATURED_COLS) == len(set(ALL_FEATURED_COLS)), "duplicate column in ALL_FEATURED_COLS"


_validate()


if __name__ == "__main__":
    print(f"MAX_STR_LEN: {MAX_STR_LEN}")
    print(f"\nIDENTITY_COLS ({len(IDENTITY_COLS)}): {IDENTITY_COLS}")
    print(f"\nGRAPH_COLS ({len(GRAPH_COLS)}): {GRAPH_COLS}")
    print(f"\nNUMERIC_FEATURES ({len(NUMERIC_FEATURES)}): {NUMERIC_FEATURES}")
    print(f"\nCATEGORICAL_FEATURES ({len(CATEGORICAL_FEATURES)}): {CATEGORICAL_FEATURES}")
    print(f"\nALL_FEATURED_COLS ({len(ALL_FEATURED_COLS)}): {ALL_FEATURED_COLS}")
    print(f"\nLEAKY_COLS ({len(LEAKY_COLS)}): {LEAKY_COLS}")
    print(f"\nLOW_VALUE_COLS ({len(LOW_VALUE_COLS)}): {LOW_VALUE_COLS}")
    print(f"\nNodeType enum: {sorted(NODE_TYPES)}")
    print(f"EdgeType enum: {sorted(EDGE_TYPES)}")
    feats = model_feature_columns()
    cats = model_categorical_columns()
    print(f"\nModel feature columns ({len(feats)}): {feats}")
    print(f"\nModel categorical columns ({len(cats)}): {cats}")
    print(f"\nNumeric (model sees): {len(feats) - len(cats)}")
    print("\nself-check OK")
