"""Phase 4: feature engineering — parse `_raw` per sourcetype into typed columns.

Output schema is defined in schema.py (50 columns, single source of truth).
Each parsed row carries:
  - identity:    _time, source, host, sourcetype, label, scenario  (carried from labeled.parquet)
  - graph:       subject_type/id/name, object_type/id/name, edge_type
  - net id:      src_ip, dest_ip                                   (graph linkage only)
  - numeric:     src_port, dest_port, bytes, packets, http_status, ...
  - categorical: transport, http_method, command_line, registry_key, ...

A parser returns a ParsedRow; the framework merges identity columns + writes the union
schema. Strings are truncated to schema.MAX_STR_LEN at the framework level, not in
each parser, so truncation is uniform.

Output: J:/THESIS-EDR/datasets/botsv2_features_v2/sourcetype=*/featured.parquet

Sibling-and-rename: writes to _v2/, caller renames to botsv2_features/ on success.

Usage:
  python extract_features.py                       # run all partitions
  python extract_features.py --only stream_http    # run one (for iteration)
  python extract_features.py --validate            # validation gates only, no rerun
"""
from __future__ import annotations

import argparse
import gc
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
from tqdm import tqdm

import schema as S

IN_DIR = Path("J:/THESIS-EDR/datasets/botsv2_labeled")
OUT_DIR = Path("J:/THESIS-EDR/datasets/botsv2_features_v2")

# Read partitions in batches to keep peak RAM bounded for huge sourcetypes
# (WinRegistry 50M, Perfmon_Process 43M).
BATCH_ROWS = 500_000


# ──────────────────────────────────────────────────────────────────────────
# Parser return type
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRow:
    """Output of a single parser invocation."""
    # Graph triple (any may be None for stub rows)
    subject_type: str | None = None
    subject_id: str | None = None
    subject_name: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    object_name: str | None = None
    edge_type: str | None = None
    # Network ids (used by socket id derivation; never features)
    src_ip: str | None = None
    dest_ip: str | None = None
    # Content fields — flat dict, keyed by column name from schema.NUMERIC_FEATURES
    # or schema.CATEGORICAL_FEATURES. Unknown keys are dropped at write time.
    fields: dict = field(default_factory=dict)


EMPTY = ParsedRow()


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

_NUMERIC_SET = set(S.NUMERIC_FEATURES)
_CATEGORICAL_SET = set(S.CATEGORICAL_FEATURES)


def _to_int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _trunc(v) -> str | None:
    """Coerce to string, truncate to MAX_STR_LEN. None → None."""
    if v is None:
        return None
    s = str(v)
    if len(s) > S.MAX_STR_LEN:
        return s[: S.MAX_STR_LEN]
    return s


def _basename(path: str | None) -> str | None:
    """Last component of a path, splitting on both / and \\."""
    if not path:
        return None
    p = str(path).replace("\\", "/")
    return p.rsplit("/", 1)[-1] or None


def _ext(name: str | None) -> str | None:
    """Final .extension of a filename (lowercased, includes dot). e.g.
    '/x/y.docx.crypt' -> '.crypt'. Returns None if no dot in basename."""
    base = _basename(name)
    if not base or "." not in base:
        return None
    return "." + base.rsplit(".", 1)[-1].lower()


def _parent_dir(path: str | None) -> str | None:
    """Parent directory of a path. e.g. 'C:\\Windows\\System32\\foo.dll' ->
    'C:/Windows/System32'. Returns None if no separator."""
    if not path:
        return None
    p = str(path).replace("\\", "/")
    if "/" not in p:
        return None
    return p.rsplit("/", 1)[0] or None


# ──────────────────────────────────────────────────────────────────────────
# Parser: stream_* (Splunk Stream JSON)
# ──────────────────────────────────────────────────────────────────────────

# Splunk Stream JSON keys → canonical schema.py column names.
_STREAM_KEY_MAP = {
    "src_ip": "src_ip", "dest_ip": "dest_ip",
    "src_port": "src_port", "dest_port": "dest_port",
    "transport": "transport", "protocol_stack": "protocol",
    "bytes": "bytes", "bytes_in": "bytes_in", "bytes_out": "bytes_out",
    "packets_in": "packets_in", "packets_out": "packets_out",
    "http_method": "http_method", "http_status": "http_status",
    "http_user_agent": "http_user_agent", "http_referrer": "http_referrer",
    "http_content_type": "http_content_type", "http_content_length": "http_content_length",
    "uri_path": "http_uri", "site": "site",
    "query": "dns_query", "query_type": "dns_qtype", "reply_code": "dns_rcode",
    "app": "app_proto",
}


def parse_stream(raw: str, host: str | None) -> ParsedRow:
    """stream_http / stream_tcp / stream_ip / stream_arp / stream_udp / stream_dns / stream_smb / stream_mysql.

    All Splunk Stream JSON. Network 5-tuple → Socket subject/object;
    HTTP rows are reshaped to (Host)-[ACCESS]->(Url) since that's the
    semantically meaningful triple for web traffic.
    """
    if not raw:
        return EMPTY
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return EMPTY

    fields: dict = {}
    for k, canon in _STREAM_KEY_MAP.items():
        v = d.get(k)
        if isinstance(v, list):
            v = v[0] if v else None
        if v is None:
            continue
        if canon in _NUMERIC_SET:
            iv = _to_int(v)
            if iv is not None:
                fields[canon] = iv
        else:
            fields[canon] = v

    src_ip = d.get("src_ip")
    dest_ip = d.get("dest_ip")
    src_port = d.get("src_port")
    dest_port = d.get("dest_port")
    transport = d.get("transport") or d.get("protocol_stack") or "tcp"

    # HTTP rows: subject = host, object = url. Web traffic doesn't fit
    # cleanly into socket-to-socket; this matches the rule-engine's
    # ACCESS edge semantics.
    site = d.get("site")
    uri = d.get("uri_path")
    if site or uri:
        return ParsedRow(
            subject_type=S.NodeType.HOST,
            subject_id=S.host_id(host),
            subject_name=host,
            object_type=S.NodeType.URL,
            object_id=S.url_id(site, uri),
            object_name=f"{site or ''}{uri or ''}",
            edge_type=S.EdgeType.ACCESS,
            src_ip=src_ip,
            dest_ip=dest_ip,
            fields=fields,
        )

    # Non-HTTP stream: socket-to-socket
    return ParsedRow(
        subject_type=S.NodeType.SOCKET,
        subject_id=S.socket_id(src_ip, src_port, None, None, transport),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=S.NodeType.SOCKET,
        object_id=S.socket_id(None, None, dest_ip, dest_port, transport),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=S.EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: suricata
# ──────────────────────────────────────────────────────────────────────────

def parse_suricata(raw: str, host: str | None) -> ParsedRow:
    """Suricata eve.json. Multiple event_types (alert/flow/http/dns/fileinfo).

    All map to a socket-to-socket CONNECT (with content fields varying by type).
    The suricata_event_type/category/severity capture the IDS verdict.
    """
    if not raw:
        return EMPTY
    try:
        d = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return EMPTY

    fields: dict = {}
    for k_in, k_out in [
        ("src_ip", "src_ip"), ("dest_ip", "dest_ip"),
        ("src_port", "src_port"), ("dest_port", "dest_port"),
        ("proto", "transport"), ("app_proto", "app_proto"),
        ("event_type", "suricata_event_type"),
    ]:
        v = d.get(k_in)
        if v is not None:
            if k_out in _NUMERIC_SET:
                iv = _to_int(v)
                if iv is not None:
                    fields[k_out] = iv
            else:
                fields[k_out] = v

    flow = d.get("flow") or {}
    if isinstance(flow, dict):
        for k_in, k_out in [
            ("bytes_toserver", "bytes_in"), ("bytes_toclient", "bytes_out"),
            ("pkts_toserver", "packets_in"), ("pkts_toclient", "packets_out"),
        ]:
            iv = _to_int(flow.get(k_in))
            if iv is not None:
                fields[k_out] = iv

    alert = d.get("alert") or {}
    if isinstance(alert, dict):
        cat = alert.get("category")
        sev = _to_int(alert.get("severity"))
        if cat is not None:
            fields["suricata_alert_category"] = cat
        if sev is not None:
            fields["suricata_alert_severity"] = sev

    http = d.get("http") or {}
    if isinstance(http, dict):
        for k_in, k_out in [
            ("http_method", "http_method"), ("status", "http_status"),
            ("url", "http_uri"), ("http_user_agent", "http_user_agent"),
            ("http_refer", "http_referrer"), ("http_content_type", "http_content_type"),
            ("hostname", "site"),
        ]:
            v = http.get(k_in)
            if v is None:
                continue
            if k_out in _NUMERIC_SET:
                iv = _to_int(v)
                if iv is not None:
                    fields[k_out] = iv
            else:
                fields[k_out] = v

    src_ip = d.get("src_ip")
    dest_ip = d.get("dest_ip")
    src_port = d.get("src_port")
    dest_port = d.get("dest_port")
    transport = d.get("proto") or "tcp"

    return ParsedRow(
        subject_type=S.NodeType.SOCKET,
        subject_id=S.socket_id(src_ip, src_port, None, None, transport),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=S.NodeType.SOCKET,
        object_id=S.socket_id(None, None, dest_ip, dest_port, transport),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=S.EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: access_combined (Apache CLF)
# ──────────────────────────────────────────────────────────────────────────

# BOTSv2's access_combined has a 5-prefix variant: ip hostname ident user port [ts] "REQ" status bytes "ref" "ua"
_CLF_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ \S+ \S+(?: \S+)? \[[^\]]+\] '
    r'"(?P<http_method>\S+) (?P<http_uri>\S+)(?: [^"]*)?" '
    r'(?:"[^"]*" )?'
    r'(?P<http_status>\d+) (?P<bytes_out>\S+)'
    r'(?: "(?P<http_referrer>[^"]*)" "(?P<http_user_agent>[^"]*)")?'
)


def parse_access_combined(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    m = _CLF_RE.match(raw)
    if not m:
        return EMPTY
    g = m.groupdict()
    fields: dict = {}
    for k in ("http_method", "http_uri", "http_referrer", "http_user_agent"):
        if g.get(k):
            fields[k] = g[k]
    status = _to_int(g.get("http_status"))
    if status is not None:
        fields["http_status"] = status
    bo = g.get("bytes_out")
    if bo and bo != "-":
        biv = _to_int(bo)
        if biv is not None:
            fields["bytes_out"] = biv

    return ParsedRow(
        subject_type=S.NodeType.HOST,
        subject_id=S.host_id(host),
        subject_name=host,
        object_type=S.NodeType.URL,
        object_id=S.url_id(host, g.get("http_uri")),
        object_name=g.get("http_uri"),
        edge_type=S.EdgeType.ACCESS,
        src_ip=g.get("src_ip"),
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: Sysmon (XmlWinEventLog_Microsoft-Windows-Sysmon_Operational)
# ──────────────────────────────────────────────────────────────────────────

_SYSMON_DATA_RE = re.compile(r"<Data Name='([^']+)'>([^<]*)</Data>")
_SYSMON_EID_RE = re.compile(r"<EventID>(\d+)</EventID>")
_SYSMON_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")

# Sysmon EventID → edge type. Based on Microsoft Sysmon documentation.
_SYSMON_EID_EDGE = {
    1: S.EdgeType.FORK,        # Process creation
    2: S.EdgeType.WRITE,       # File creation time changed
    3: S.EdgeType.CONNECT,     # Network connection
    7: S.EdgeType.LOAD,        # Image loaded
    8: S.EdgeType.MMAP,        # CreateRemoteThread
    10: S.EdgeType.READ,       # ProcessAccess
    11: S.EdgeType.WRITE,      # FileCreate
    12: S.EdgeType.MODIFY_REG, # RegistryEvent (Object create/delete)
    13: S.EdgeType.MODIFY_REG, # RegistryEvent (Value Set)
    14: S.EdgeType.MODIFY_REG, # RegistryEvent (Key/Value rename)
    15: S.EdgeType.WRITE,      # FileCreateStreamHash
    17: S.EdgeType.CONNECT,    # PipeEvent (Pipe Created)
    18: S.EdgeType.CONNECT,    # PipeEvent (Pipe Connected)
    23: S.EdgeType.DELETE,     # FileDelete
    25: S.EdgeType.MMAP,       # ProcessTampering
    26: S.EdgeType.DELETE,     # FileDeleteDetected
}


def parse_sysmon(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    eid_m = _SYSMON_EID_RE.search(raw)
    eid = _to_int(eid_m.group(1)) if eid_m else None
    if eid is None:
        return EMPTY

    # Pull all <Data Name='X'>VAL</Data> pairs into a dict for cheap lookup
    data: dict[str, str] = {}
    for name, val in _SYSMON_DATA_RE.findall(raw):
        if val:
            data[name] = val

    # Computer field for proc id host fallback (Sysmon's Computer field is
    # more reliable than the Splunk-derived host column for cross-host events)
    comp_m = _SYSMON_COMPUTER_RE.search(raw)
    src_host = comp_m.group(1) if comp_m else host

    fields: dict = {"event_id": eid}
    pid = data.get("ProcessId")
    if pid:
        ipid = _to_int(pid)
        if ipid is not None:
            fields["process_id"] = ipid

    image = data.get("Image")
    cmdline = data.get("CommandLine")
    parent_cmdline = data.get("ParentCommandLine")
    user = data.get("User")
    integrity = data.get("IntegrityLevel")
    target = data.get("TargetObject")
    details = data.get("Details")
    target_filename = data.get("TargetFilename")

    if image:
        fields["image"] = image
        fields["process_name"] = image.replace("\\", "/").rsplit("/", 1)[-1]
    if cmdline:
        fields["command_line"] = cmdline
    if parent_cmdline:
        fields["parent_command_line"] = parent_cmdline
    parent_img = data.get("ParentImage")
    if parent_img:
        fields["parent_image"] = parent_img
    if user:
        fields["user"] = user
    if integrity:
        fields["integrity_level"] = integrity
    if target:
        fields["registry_key"] = target
    if details:
        fields["registry_value"] = details

    edge = _SYSMON_EID_EDGE.get(eid, S.EdgeType.EXEC)

    # Subject is always the process emitting the event
    subj_id = S.proc_id(src_host, pid, image)
    subj_name = (
        cmdline if cmdline
        else (image.replace("\\", "/").rsplit("/", 1)[-1] if image else None)
    )

    # Object varies by EventID family
    if eid == 1:  # process create — child process is the object
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=S.proc_id(src_host, data.get("ParentProcessId"), data.get("ParentImage")),
            subject_name=parent_cmdline or data.get("ParentImage"),
            object_type=S.NodeType.PROCESS,
            object_id=subj_id,
            object_name=subj_name,
            edge_type=S.EdgeType.FORK,
            fields=fields,
        )
    if eid in (12, 13, 14):  # registry — object is the registry key
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=S.NodeType.REGISTRY,
            object_id=S.registry_id(src_host, target),
            object_name=target,
            edge_type=S.EdgeType.MODIFY_REG,
            fields=fields,
        )
    if eid in (2, 11, 15, 23, 26):  # file events
        path = target_filename or target
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=S.NodeType.FILE,
            object_id=S.file_id(src_host, path),
            object_name=path,
            edge_type=edge,
            fields=fields,
        )
    if eid == 3:  # network connection
        dst_ip = data.get("DestinationIp")
        dst_port = data.get("DestinationPort")
        src_ip = data.get("SourceIp")
        src_port = data.get("SourcePort")
        proto = (data.get("Protocol") or "tcp").lower()
        if dst_port:
            fields["dest_port"] = _to_int(dst_port)
        if src_port:
            fields["src_port"] = _to_int(src_port)
        if proto:
            fields["transport"] = proto
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=S.NodeType.SOCKET,
            object_id=S.socket_id(src_ip, src_port, dst_ip, dst_port, proto),
            object_name=f"{dst_ip or '?'}:{dst_port or '?'}",
            edge_type=S.EdgeType.CONNECT,
            src_ip=src_ip,
            dest_ip=dst_ip,
            fields=fields,
        )
    if eid == 7:  # image loaded
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=S.NodeType.FILE,
            object_id=S.file_id(src_host, data.get("ImageLoaded")),
            object_name=data.get("ImageLoaded"),
            edge_type=S.EdgeType.LOAD,
            fields=fields,
        )

    # Fallback: process-only event
    return ParsedRow(
        subject_type=S.NodeType.PROCESS,
        subject_id=subj_id,
        subject_name=subj_name,
        edge_type=edge,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: pan_traffic (Palo Alto firewall TRAFFIC log, syslog + position-CSV)
# ──────────────────────────────────────────────────────────────────────────

# Field positions documented in the AutoGluon-experiment archive. 0% parse-fail
# observed under Ablation B.
_PAN_FIELDS = [
    None, None, None, None, None, None, None,         # 0-6
    "src_ip", "dest_ip",                              # 7, 8
    None, None, None,                                 # 9-11
    "user",                                           # 12
    None,                                             # 13
    "app_proto",                                      # 14
    None, None, None, None, None, None, None, None, None,  # 15-23
    "src_port", "dest_port",                          # 24, 25
    None, None, None,                                 # 26-28
    "transport",                                      # 29
    None,                                             # 30 (action)
    "bytes", "bytes_out", "bytes_in", "packets_in",   # 31-34
    None,                                             # 35
    "duration",                                       # 36
]


def parse_pan_traffic(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    csv_start = raw.find(" 1,")
    if csv_start < 0:
        return EMPTY
    body = raw[csv_start + 1:]
    parts = body.split(",")
    fields: dict = {}
    src_ip = dest_ip = src_port = dest_port = transport = None
    for i, name in enumerate(_PAN_FIELDS):
        if name is None or i >= len(parts):
            continue
        val = parts[i].strip()
        if not val:
            continue
        if name == "src_ip":
            src_ip = val
        elif name == "dest_ip":
            dest_ip = val
        elif name == "src_port":
            src_port = val
            iv = _to_int(val)
            if iv is not None:
                fields["src_port"] = iv
        elif name == "dest_port":
            dest_port = val
            iv = _to_int(val)
            if iv is not None:
                fields["dest_port"] = iv
        elif name == "transport":
            transport = val
            fields["transport"] = val
        elif name in _NUMERIC_SET:
            iv = _to_int(val)
            if iv is not None:
                fields[name] = iv
        else:
            fields[name] = val

    return ParsedRow(
        subject_type=S.NodeType.SOCKET,
        subject_id=S.socket_id(src_ip, src_port, None, None, transport or "tcp"),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=S.NodeType.SOCKET,
        object_id=S.socket_id(None, None, dest_ip, dest_port, transport or "tcp"),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=S.EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: mysql_server_stats / mysql_transaction_details
# ──────────────────────────────────────────────────────────────────────────

# KV with quoted values: hostname="gacrux", port="3306", EVENT_ID="423", ...
_MYSQL_KV_RE = re.compile(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"')


def parse_mysql_kv(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    kv = dict(_MYSQL_KV_RE.findall(raw))
    if not kv:
        return EMPTY
    fields: dict = {}
    db_user = kv.get("user") or kv.get("USER")
    if db_user:
        fields["user"] = db_user
    if "EVENT_ID" in kv:
        eid = _to_int(kv["EVENT_ID"])
        if eid is not None:
            fields["event_id"] = eid
    if "Duration" in kv:
        # Duration is float seconds; coerce to milliseconds-as-int for the
        # numeric duration column (LightGBM doesn't care about unit).
        try:
            fields["duration"] = int(float(kv["Duration"]) * 1000)
        except ValueError:
            pass
    sql = kv.get("SQL_TEXT") or kv.get("sql_text")
    if sql:
        fields["command_line"] = sql  # SQL is the closest analog to a command
    db = kv.get("database_name") or kv.get("database")
    if db:
        fields["site"] = db  # repurpose `site` for db name (string categorical)
    port = kv.get("port")
    if port:
        iv = _to_int(port)
        if iv is not None:
            fields["dest_port"] = iv

    db_host = kv.get("hostname") or host

    if not db_user and not db_host:
        return EMPTY

    return ParsedRow(
        subject_type=S.NodeType.USER if db_user else S.NodeType.HOST,
        subject_id=S.user_id(db_host, db_user) if db_user else S.host_id(db_host),
        subject_name=db_user or db_host,
        object_type=S.NodeType.HOST,
        object_id=S.host_id(db_host),
        object_name=db_host,
        edge_type=S.EdgeType.ACCESS,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: WinHostMon
# ──────────────────────────────────────────────────────────────────────────

# WinHostMon is multi-line KV from Splunk's WinHostMon stanza. Lines look like
# `key=value` or `key="value with spaces"`. We pull a small allowlist.
_WHM_KV_RE = re.compile(r'^(\w+)\s*=\s*(?:"([^"]*)"|(\S.*?))\s*$', re.MULTILINE)


def parse_winhostmon(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    kv: dict[str, str] = {}
    for k, qv, uv in _WHM_KV_RE.findall(raw):
        v = qv if qv else uv
        if v and k not in kv:
            kv[k] = v
    if not kv:
        return EMPTY
    fields: dict = {}
    image = kv.get("Path") or kv.get("ProcessImage")
    pid = kv.get("ProcessId") or kv.get("PID")
    name = kv.get("Name")
    cmd = kv.get("CommandLine")
    port = kv.get("LocalPort")
    proto = kv.get("Protocol") or kv.get("transport")
    if image:
        fields["image"] = image
        fields["process_name"] = image.replace("\\", "/").rsplit("/", 1)[-1]
    elif name:
        fields["process_name"] = name
    if cmd:
        fields["command_line"] = cmd
    if port:
        iv = _to_int(port)
        if iv is not None:
            fields["dest_port"] = iv
    if proto:
        fields["transport"] = proto

    if port:
        # Listening process — model as (Process)-[CONNECT]->(Socket *:port/proto)
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=S.proc_id(host, pid, image or name),
            subject_name=cmd or image or name,
            object_type=S.NodeType.SOCKET,
            object_id=f"sock:*:{port}/{(proto or 'tcp').lower()}",
            object_name=f"*:{port}",
            edge_type=S.EdgeType.CONNECT,
            fields=fields,
        )
    # No port → bare process observation; no edge.
    return ParsedRow(
        subject_type=S.NodeType.PROCESS,
        subject_id=S.proc_id(host, pid, image or name),
        subject_name=cmd or image or name,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: linux_audit / auditd
# ──────────────────────────────────────────────────────────────────────────

# Audit log: type=SYSCALL msg=audit(...): ... key=value pairs
_AUDIT_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_audit(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    kv: dict[str, str] = {}
    for k, qv, uv in _AUDIT_KV_RE.findall(raw):
        v = qv if qv else uv
        if v and k not in kv:
            kv[k] = v
    if not kv:
        return EMPTY
    fields: dict = {}
    pid = kv.get("pid")
    exe = kv.get("exe") or kv.get("comm")
    cmd = kv.get("proctitle")
    user = kv.get("uid") or kv.get("auid")
    syscall = kv.get("syscall")
    name = kv.get("name")  # usually a file path
    if exe:
        fields["image"] = exe
        fields["process_name"] = exe.replace("\\", "/").rsplit("/", 1)[-1]
    if cmd:
        fields["command_line"] = cmd
    if user:
        fields["user"] = user
    if pid:
        iv = _to_int(pid)
        if iv is not None:
            fields["process_id"] = iv

    subj_id = S.proc_id(host, pid, exe)
    subj_name = cmd or exe

    # Map syscall family to edge — coarse but signal-bearing
    if syscall in ("execve", "execveat"):
        edge = S.EdgeType.EXEC
    elif syscall in ("open", "openat", "read", "readv", "pread64"):
        edge = S.EdgeType.READ
    elif syscall in ("write", "writev", "pwrite64", "creat"):
        edge = S.EdgeType.WRITE
    elif syscall in ("unlink", "unlinkat", "rmdir"):
        edge = S.EdgeType.DELETE
    elif syscall in ("rename", "renameat", "renameat2"):
        edge = S.EdgeType.RENAME
    elif syscall in ("connect", "sendto", "send"):
        edge = S.EdgeType.CONNECT
    elif syscall in ("clone", "fork", "vfork"):
        edge = S.EdgeType.FORK
    else:
        edge = None

    if name and edge in (S.EdgeType.READ, S.EdgeType.WRITE, S.EdgeType.DELETE,
                          S.EdgeType.RENAME, S.EdgeType.EXEC):
        return ParsedRow(
            subject_type=S.NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=S.NodeType.FILE,
            object_id=S.file_id(host, name),
            object_name=name,
            edge_type=edge,
            fields=fields,
        )
    return ParsedRow(
        subject_type=S.NodeType.PROCESS,
        subject_id=subj_id,
        subject_name=subj_name,
        edge_type=edge,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: WinRegistry (Splunk multi-line KV)
# ──────────────────────────────────────────────────────────────────────────

# WinRegistry is multi-line; each event has key_path, process_image, etc on
# separate lines. We use the same KV regex but allowlist a small set.
def parse_winregistry(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    kv: dict[str, str] = {}
    for k, qv, uv in _AUDIT_KV_RE.findall(raw):
        v = qv if qv else uv
        if v and k not in kv:
            kv[k] = v
    if not kv:
        return EMPTY
    fields: dict = {}
    image = kv.get("process_image")
    pid = kv.get("pid")
    key_path = kv.get("key_path")
    data = kv.get("data")
    reg_type = kv.get("registry_type")
    user = kv.get("user")

    if image:
        fields["image"] = image
        fields["process_name"] = image.replace("\\", "/").rsplit("/", 1)[-1]
    if user:
        fields["user"] = user
    if key_path:
        fields["registry_key"] = key_path
    # Use registry_type as the value when actual data is missing/binary
    if data and len(data) < 200:
        fields["registry_value"] = data
    elif reg_type:
        fields["registry_value"] = reg_type
    if pid:
        iv = _to_int(pid)
        if iv is not None:
            fields["process_id"] = iv

    return ParsedRow(
        subject_type=S.NodeType.PROCESS,
        subject_id=S.proc_id(host, pid, image),
        subject_name=image,
        object_type=S.NodeType.REGISTRY,
        object_id=S.registry_id(host, key_path),
        object_name=key_path,
        edge_type=S.EdgeType.MODIFY_REG,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: stub (Perfmon family etc — no usable graph triple)
# ──────────────────────────────────────────────────────────────────────────

def parse_stub(raw: str, host: str | None) -> ParsedRow:
    """No-op parser. Row gets identity + label + sourcetype only."""
    return EMPTY


# ──────────────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────────────

def get_parser(sourcetype: str) -> Callable[[str, str | None], ParsedRow]:
    if sourcetype.startswith("stream_"):
        return parse_stream
    if sourcetype == "suricata":
        return parse_suricata
    if sourcetype == "access_combined":
        return parse_access_combined
    if sourcetype.startswith("XmlWinEventLog") and "Sysmon" in sourcetype:
        return parse_sysmon
    if sourcetype == "mordor_sysmon":
        # Mordor JSON converted by _mordor-to-labeled-parquet.py emits Sysmon
        # XML in _raw using the same schema as BOTSv2 Sysmon → reuse parser.
        return parse_sysmon
    if sourcetype == "pan_traffic":
        return parse_pan_traffic
    if sourcetype.startswith("mysql_"):
        return parse_mysql_kv
    if sourcetype == "WinHostMon":
        return parse_winhostmon
    if sourcetype == "WinRegistry":
        return parse_winregistry
    if sourcetype in ("linux_audit", "auditd"):
        return parse_audit
    # Stub everything else (Perfmon_*, collectd, web_ping, who, ActiveDirectory...).
    # These are either numeric-counter telemetry or low-yield categorical.
    return parse_stub


# ──────────────────────────────────────────────────────────────────────────
# Framework: process a partition
# ──────────────────────────────────────────────────────────────────────────

# Pyarrow schema for the output Parquet — built once, used for every partition
# so concat is straightforward.
def _build_arrow_schema() -> pa.Schema:
    fields = []
    # identity
    fields.append(pa.field("_time", pa.int64()))
    fields.append(pa.field("source", pa.string()))
    fields.append(pa.field("host", pa.string()))
    fields.append(pa.field("sourcetype", pa.string()))
    fields.append(pa.field("label", pa.int8()))
    fields.append(pa.field("scenario", pa.string()))
    # graph
    for c in S.GRAPH_COLS:
        fields.append(pa.field(c, pa.string()))
    # net id — skip cols that are already in CATEGORICAL_FEATURES (after the
    # 2026-05 refactor src_ip/dest_ip moved into CATEGORICAL_FEATURES but
    # NETWORK_ID_COLS still lists them; emitting both creates duplicate Arrow
    # fields and breaks pl.DataFrame construction).
    _cat_set = set(S.CATEGORICAL_FEATURES)
    for c in S.NETWORK_ID_COLS:
        if c in _cat_set:
            continue
        fields.append(pa.field(c, pa.string()))
    # numeric (int64 is safe for all numeric features; LightGBM handles)
    for c in S.NUMERIC_FEATURES:
        fields.append(pa.field(c, pa.int64()))
    # categorical (string)
    for c in S.CATEGORICAL_FEATURES:
        fields.append(pa.field(c, pa.string()))
    return pa.schema(fields)


ARROW_SCHEMA = _build_arrow_schema()


def featurize_batch(batch: pl.DataFrame, sourcetype: str, parser) -> pl.DataFrame:
    """Apply the parser to every row, return a DataFrame matching ARROW_SCHEMA."""
    raws = batch["_raw"].to_list()
    hosts = batch["host"].to_list()
    parsed: list[ParsedRow] = [parser(r or "", h) for r, h in zip(raws, hosts)]

    out: dict[str, list] = {}
    out["_time"] = batch["_time"].to_list()
    out["source"] = batch["source"].to_list()
    out["host"] = hosts
    out["sourcetype"] = [sourcetype] * batch.height
    out["label"] = batch["label"].to_list()
    out["scenario"] = batch["scenario"].to_list()

    # Graph cols
    out["subject_type"] = [p.subject_type for p in parsed]
    out["object_type"] = [p.object_type for p in parsed]
    out["edge_type"] = [p.edge_type for p in parsed]
    out["subject_name"] = [_trunc(p.subject_name) for p in parsed]
    out["object_name"] = [_trunc(p.object_name) for p in parsed]
    out["subject_id"] = [_trunc(p.subject_id) for p in parsed]
    out["object_id"] = [_trunc(p.object_id) for p in parsed]
    # Net ids
    out["src_ip"] = [p.src_ip for p in parsed]
    out["dest_ip"] = [p.dest_ip for p in parsed]

    # Content fields
    for c in S.NUMERIC_FEATURES:
        out[c] = [p.fields.get(c) for p in parsed]
    for c in S.CATEGORICAL_FEATURES:
        out[c] = [_trunc(p.fields.get(c)) for p in parsed]

    # Derived content features (FILE objects only — applying these to
    # Socket / Url / Process objects pollutes the vocab with values like
    # ".100:443" or ".1 (x64 en-us)" that drown the real file extensions).
    out["object_name_ext"] = [
        _ext(p.object_name) if p.object_type == S.NodeType.FILE else None
        for p in parsed
    ]
    out["object_basename"] = [
        _trunc(_basename(p.object_name)) if p.object_type == S.NodeType.FILE else None
        for p in parsed
    ]
    out["target_dir"] = [
        _trunc(_parent_dir(p.object_name)) if p.object_type == S.NodeType.FILE else None
        for p in parsed
    ]
    # image_basename is always meaningful — Process subjects carry image even
    # when the edge object is not a File (e.g. CONNECT/MODIFY_REG/LOAD).
    out["image_basename"]  = [_trunc(_basename(p.fields.get("image"))) for p in parsed]

    # Engineered MITRE-derived boolean features. Use the same compute()
    # function as ml-edge-scorer/feature_row.py — single source of truth.
    import sys as _s
    from pathlib import Path as _P
    _server = _P(__file__).resolve().parents[2]
    if str(_server) not in _s.path:
        _s.path.insert(0, str(_server))
    from botsv2_parsers.engineered_features import compute as _eng_compute, FEATURE_NAMES as _eng_names
    eng_rows: list[dict] = []
    for p in parsed:
        target = p.object_name if p.object_type == S.NodeType.FILE else None
        registry_key = p.fields.get("registry_key")
        eng_rows.append(_eng_compute(
            image=p.fields.get("image"),
            parent_image=p.fields.get("parent_image"),
            command_line=p.fields.get("command_line"),
            target=target,
            registry_key=registry_key,
            http_uri=p.fields.get("http_uri"),
        ))
    for name in _eng_names:
        out[name] = [row[name] for row in eng_rows]

    # Build a polars DataFrame in the ARROW_SCHEMA column order
    cols = []
    for field in ARROW_SCHEMA:
        name = field.name
        vals = out[name]
        if pa.types.is_int64(field.type):
            s = pl.Series(name, vals, dtype=pl.Int64, strict=False)
        elif pa.types.is_int8(field.type):
            s = pl.Series(name, vals, dtype=pl.Int8, strict=False)
        else:
            s = pl.Series(name, [None if v is None else str(v) for v in vals], dtype=pl.String)
        cols.append(s)
    return pl.DataFrame(cols)


def featurize_partition(in_file: Path, sourcetype: str, out_file: Path) -> dict:
    """Read labeled partition in batches, parse, write featured Parquet."""
    parser = get_parser(sourcetype)
    total = pl.scan_parquet(in_file).select(pl.len()).collect().item()
    if total == 0:
        empty = pl.DataFrame(
            {f.name: [] for f in ARROW_SCHEMA},
        )
        empty.write_parquet(out_file, compression="zstd", compression_level=3)
        return {"sourcetype": sourcetype, "rows": 0, "malicious_in": 0, "malicious_out": 0,
                "graph_filled": 0, "graph_filled_rate": 0.0}

    writer = pq.ParquetWriter(out_file, ARROW_SCHEMA, compression="zstd")
    rows_out = 0
    mal_out = 0
    graph_filled = 0
    offset = 0
    while offset < total:
        batch = pl.scan_parquet(in_file).slice(offset, BATCH_ROWS).collect()
        feat = featurize_batch(batch, sourcetype, parser)
        # Stats
        rows_out += feat.height
        mal_out += int((feat["label"] == 1).sum())
        # Count rows where all three graph type cols are non-null
        triple_filled = feat.filter(
            pl.col("subject_type").is_not_null()
            & pl.col("object_type").is_not_null()
            & pl.col("edge_type").is_not_null()
        ).height
        graph_filled += triple_filled
        writer.write_table(feat.to_arrow().cast(ARROW_SCHEMA))
        offset += BATCH_ROWS
        del batch, feat
        gc.collect()
    writer.close()

    mal_in = pl.scan_parquet(in_file).filter(pl.col("label") == 1).select(pl.len()).collect().item()

    return {
        "sourcetype": sourcetype,
        "rows": rows_out,
        "malicious_in": mal_in,
        "malicious_out": mal_out,
        "graph_filled": graph_filled,
        "graph_filled_rate": graph_filled / max(rows_out, 1),
    }


def log(msg: str = "") -> None:
    print(msg, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="Run only this sourcetype (for iteration)")
    ap.add_argument("--validate", action="store_true",
                    help="Re-run validation gates against existing _v2 output")
    args = ap.parse_args()

    if not IN_DIR.exists():
        log(f"FATAL: {IN_DIR} missing")
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    partitions = sorted(IN_DIR.glob("sourcetype=*"))
    if args.only:
        partitions = [p for p in partitions if p.name == f"sourcetype={args.only}"]
        if not partitions:
            log(f"FATAL: no partition matches --only={args.only}")
            return 1

    log(f"Featurizing {len(partitions)} partitions -> {OUT_DIR}")

    stats: list[dict] = []
    started = time.time()
    pbar = tqdm(partitions, unit="part")
    for pdir in pbar:
        st_name = pdir.name.replace("sourcetype=", "")
        out_pdir = OUT_DIR / pdir.name
        out_pdir.mkdir(parents=True, exist_ok=True)
        out_file = out_pdir / "featured.parquet"
        if out_file.exists() and not args.only:
            # Resume guard. Re-read the existing parquet for stats so the
            # final summary reflects the entire dataset, not just this run's
            # newly-written partitions.
            mal = pl.scan_parquet(out_file).filter(pl.col("label") == 1).select(pl.len()).collect().item()
            n = pl.scan_parquet(out_file).select(pl.len()).collect().item()
            tf = (
                pl.scan_parquet(out_file)
                .filter(
                    pl.col("subject_type").is_not_null()
                    & pl.col("object_type").is_not_null()
                    & pl.col("edge_type").is_not_null()
                )
                .select(pl.len())
                .collect()
                .item()
            )
            stats.append({
                "sourcetype": st_name, "rows": n,
                "malicious_in": mal, "malicious_out": mal,
                "graph_filled": tf, "graph_filled_rate": tf / max(n, 1),
                "skipped": True,
            })
            pbar.set_postfix(skip=st_name[:20])
            continue
        in_file = pdir / "labeled.parquet"
        if not in_file.exists():
            continue
        try:
            s = featurize_partition(in_file, st_name, out_file)
        except Exception as e:
            log(f"\nFAILED on {st_name}: {e}")
            raise
        stats.append(s)
        pbar.set_postfix(rows=f"{s['rows']:,}", mal=f"{s['malicious_out']:,}",
                         st=st_name[:20])

    elapsed = time.time() - started
    log(f"\nDone in {elapsed/60:.1f} min")

    # Aggregate
    total_rows = sum(s.get("rows", 0) for s in stats)
    total_mal_in = sum(s.get("malicious_in", 0) for s in stats if "malicious_in" in s)
    total_mal_out = sum(s.get("malicious_out", 0) for s in stats if "malicious_out" in s)
    total_graph_filled = sum(s.get("graph_filled", 0) for s in stats if "graph_filled" in s)

    log(f"  total rows         : {total_rows:,}")
    log(f"  total malicious in : {total_mal_in:,}")
    log(f"  total malicious out: {total_mal_out:,}   delta {total_mal_out - total_mal_in:+,}")
    log(f"  graph triple filled: {total_graph_filled:,} "
        f"({100*total_graph_filled/max(total_rows,1):.2f}%)")

    log("\n  per-sourcetype graph fill rate (top 15 by rows):")
    sorted_stats = sorted([s for s in stats if "rows" in s and "graph_filled" in s],
                          key=lambda s: -s["rows"])
    for s in sorted_stats[:15]:
        log(f"    {s['sourcetype']:40s} rows={s['rows']:>12,}  "
            f"mal={s.get('malicious_out',0):>8,}  "
            f"graph={100*s.get('graph_filled_rate',0):.2f}%")

    summary_path = OUT_DIR / "_features_summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "elapsed_min": round(elapsed / 60, 2),
            "total_rows": total_rows,
            "total_malicious_in": total_mal_in,
            "total_malicious_out": total_mal_out,
            "total_graph_filled": total_graph_filled,
            "graph_filled_rate": total_graph_filled / max(total_rows, 1),
            "per_partition": stats,
        }, f, indent=2)
    log(f"\nWrote summary: {summary_path}")

    # Validation gates
    log("\n" + "=" * 60)
    log("Validation gates")
    log("=" * 60)
    gate_rows = total_rows == total_mal_in + (total_rows - total_mal_in)  # tautology, replaced below
    # Real gate: featured rows == labeled rows for the run scope
    # (compare against IN_DIR if not --only)
    if not args.only:
        in_total = 0
        for pdir in partitions:
            f = pdir / "labeled.parquet"
            if f.exists():
                in_total += pl.scan_parquet(f).select(pl.len()).collect().item()
        gate_rows_match = in_total == total_rows
        log(f"  [{'OK' if gate_rows_match else 'FAIL'}] featured rows == labeled rows  "
            f"({total_rows:,} vs {in_total:,})")
    gate_mal_match = total_mal_in == total_mal_out
    log(f"  [{'OK' if gate_mal_match else 'FAIL'}] malicious rows preserved          "
        f"({total_mal_out:,} vs {total_mal_in:,})")
    gate_graph = total_graph_filled / max(total_rows, 1) >= 0.80 if not args.only else True
    log(f"  [{'OK' if gate_graph else 'WARN'}] >=80% graph triple non-null        "
        f"({100*total_graph_filled/max(total_rows,1):.2f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
