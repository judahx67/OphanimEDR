"""
Splunk BOTSv2 per-sourcetype raw-event parsers.

Extracted from server/ml-engine/botsv2/extract_features.py.
All Polars / parquet / IO dependencies removed — this module is pure Python
and safe to import in any container (ingest, ml-edge-scorer, etc.).

ParsedRow mirrors the featured-schema graph triple + content fields defined
in server/ml-engine/botsv2/schema.py but has no dependency on that module,
so it can be imported without the ml-engine extras (polars, lightgbm, etc.).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable


# ──────────────────────────────────────────────────────────────────────────
# Schema constants (mirrors botsv2/schema.py — kept in sync manually)
# ──────────────────────────────────────────────────────────────────────────

MAX_STR_LEN = 100


class NodeType:
    PROCESS = "Process"
    FILE = "File"
    SOCKET = "Socket"
    REGISTRY = "Registry"
    PIPE = "Pipe"
    MEMORY = "Memory"
    HOST = "Host"
    USER = "User"
    URL = "Url"


class EdgeType:
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


NUMERIC_FEATURES = [
    "src_port", "dest_port",
    "http_status", "http_content_length",
    "bytes", "bytes_in", "bytes_out",
    "packets_in", "packets_out",
    "duration",
    "event_id",
    "process_id",
    "suricata_alert_severity",
]

CATEGORICAL_FEATURES = [
    # Network identity — kept in sync with ml-engine/botsv2/schema.py
    "external_ip", "src_ip", "dest_ip",
    "transport", "protocol", "app_proto",
    "http_method", "http_uri", "http_user_agent", "http_referrer",
    "http_content_type", "site",
    "dns_query", "dns_qtype", "dns_rcode",
    "process_name", "image", "command_line", "parent_command_line",
    "parent_image",
    "user", "integrity_level", "registry_key", "registry_value",
    "suricata_event_type", "suricata_alert_category",
    # Derived content features (2026-05-24) — see ml-engine/botsv2/schema.py.
    # Filled by feature_row.py / extract_features.py from object_name + image,
    # NOT by parsers themselves.
    "object_name_ext", "object_basename", "image_basename", "target_dir",
]

_NUMERIC_SET = set(NUMERIC_FEATURES)
_CATEGORICAL_SET = set(CATEGORICAL_FEATURES)


# ──────────────────────────────────────────────────────────────────────────
# ID derivation helpers (mirrors botsv2/schema.py)
# ──────────────────────────────────────────────────────────────────────────

def proc_id(host: str | None, pid: str | int | None, image: str | None) -> str | None:
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
    return f"file:{host or '?'}:{path.lower()}"[:200]


def socket_id(
    src_ip: str | None, src_port: str | int | None,
    dest_ip: str | None, dest_port: str | int | None,
    transport: str | None,
) -> str | None:
    if not (src_ip or dest_ip):
        return None
    t = (transport or "?").lower()
    return f"sock:{src_ip or '?'}:{src_port or '?'}->{dest_ip or '?'}:{dest_port or '?'}/{t}"


def registry_id(host: str | None, key: str | None) -> str | None:
    if not key:
        return None
    return f"reg:{host or '?'}:{key.lower()}"[:200]


def url_id(site: str | None, uri: str | None) -> str | None:
    if not (site or uri):
        return None
    return f"url:{site or ''}{uri or ''}"[:200]


def host_id(host: str | None) -> str | None:
    return f"host:{host}" if host else None


def user_id(host: str | None, user: str | None) -> str | None:
    if not user:
        return None
    return f"user:{host or '?'}:{user.lower()}"


# ──────────────────────────────────────────────────────────────────────────
# Parser return type
# ──────────────────────────────────────────────────────────────────────────

@dataclass
class ParsedRow:
    subject_type: str | None = None
    subject_id: str | None = None
    subject_name: str | None = None
    object_type: str | None = None
    object_id: str | None = None
    object_name: str | None = None
    edge_type: str | None = None
    src_ip: str | None = None
    dest_ip: str | None = None
    fields: dict = field(default_factory=dict)

    @property
    def has_graph_triple(self) -> bool:
        return bool(self.subject_type and self.object_type and self.edge_type)


EMPTY = ParsedRow()


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _to_int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _trunc(v) -> str | None:
    if v is None:
        return None
    s = str(v)
    return s[:MAX_STR_LEN] if len(s) > MAX_STR_LEN else s


# ──────────────────────────────────────────────────────────────────────────
# Parser: stream_* (Splunk Stream JSON)
# ──────────────────────────────────────────────────────────────────────────

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

    site = d.get("site")
    uri = d.get("uri_path")
    if site or uri:
        return ParsedRow(
            subject_type=NodeType.HOST,
            subject_id=host_id(host),
            subject_name=host,
            object_type=NodeType.URL,
            object_id=url_id(site, uri),
            object_name=f"{site or ''}{uri or ''}",
            edge_type=EdgeType.ACCESS,
            src_ip=src_ip,
            dest_ip=dest_ip,
            fields=fields,
        )

    return ParsedRow(
        subject_type=NodeType.SOCKET,
        subject_id=socket_id(src_ip, src_port, None, None, transport),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=NodeType.SOCKET,
        object_id=socket_id(None, None, dest_ip, dest_port, transport),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: suricata
# ──────────────────────────────────────────────────────────────────────────

def parse_suricata(raw: str, host: str | None) -> ParsedRow:
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
        subject_type=NodeType.SOCKET,
        subject_id=socket_id(src_ip, src_port, None, None, transport),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=NodeType.SOCKET,
        object_id=socket_id(None, None, dest_ip, dest_port, transport),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: access_combined (Apache CLF)
# ──────────────────────────────────────────────────────────────────────────

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
        subject_type=NodeType.HOST,
        subject_id=host_id(host),
        subject_name=host,
        object_type=NodeType.URL,
        object_id=url_id(host, g.get("http_uri")),
        object_name=g.get("http_uri"),
        edge_type=EdgeType.ACCESS,
        src_ip=g.get("src_ip"),
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: Sysmon (XmlWinEventLog_Microsoft-Windows-Sysmon_Operational)
# ──────────────────────────────────────────────────────────────────────────

_SYSMON_DATA_RE = re.compile(r"<Data Name='([^']+)'>([^<]*)</Data>")
_SYSMON_EID_RE = re.compile(r"<EventID>(\d+)</EventID>")
_SYSMON_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")

_SYSMON_EID_EDGE = {
    1: EdgeType.FORK,
    2: EdgeType.WRITE,
    3: EdgeType.CONNECT,
    7: EdgeType.LOAD,
    8: EdgeType.MMAP,
    10: EdgeType.READ,
    11: EdgeType.WRITE,
    12: EdgeType.MODIFY_REG,
    13: EdgeType.MODIFY_REG,
    14: EdgeType.MODIFY_REG,
    15: EdgeType.WRITE,
    17: EdgeType.CONNECT,
    18: EdgeType.CONNECT,
    23: EdgeType.DELETE,
    25: EdgeType.MMAP,
    26: EdgeType.DELETE,
}


def parse_sysmon(raw: str, host: str | None) -> ParsedRow:
    if not raw:
        return EMPTY
    eid_m = _SYSMON_EID_RE.search(raw)
    eid = _to_int(eid_m.group(1)) if eid_m else None
    if eid is None:
        return EMPTY

    data: dict[str, str] = {}
    for name, val in _SYSMON_DATA_RE.findall(raw):
        if val:
            data[name] = val

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

    edge = _SYSMON_EID_EDGE.get(eid, EdgeType.EXEC)

    subj_id = proc_id(src_host, pid, image)
    subj_name = (
        cmdline if cmdline
        else (image.replace("\\", "/").rsplit("/", 1)[-1] if image else None)
    )

    if eid == 1:
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=proc_id(src_host, data.get("ParentProcessId"), data.get("ParentImage")),
            subject_name=parent_cmdline or data.get("ParentImage"),
            object_type=NodeType.PROCESS,
            object_id=subj_id,
            object_name=subj_name,
            edge_type=EdgeType.FORK,
            fields=fields,
        )
    if eid in (12, 13, 14):
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=NodeType.REGISTRY,
            object_id=registry_id(src_host, target),
            object_name=target,
            edge_type=EdgeType.MODIFY_REG,
            fields=fields,
        )
    if eid in (2, 11, 15, 23, 26):
        path = target_filename or target
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=NodeType.FILE,
            object_id=file_id(src_host, path),
            object_name=path,
            edge_type=edge,
            fields=fields,
        )
    if eid == 3:
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
            subject_type=NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=NodeType.SOCKET,
            object_id=socket_id(src_ip, src_port, dst_ip, dst_port, proto),
            object_name=f"{dst_ip or '?'}:{dst_port or '?'}",
            edge_type=EdgeType.CONNECT,
            src_ip=src_ip,
            dest_ip=dst_ip,
            fields=fields,
        )
    if eid == 7:
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=NodeType.FILE,
            object_id=file_id(src_host, data.get("ImageLoaded")),
            object_name=data.get("ImageLoaded"),
            edge_type=EdgeType.LOAD,
            fields=fields,
        )

    return ParsedRow(
        subject_type=NodeType.PROCESS,
        subject_id=subj_id,
        subject_name=subj_name,
        edge_type=edge,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: pan_traffic
# ──────────────────────────────────────────────────────────────────────────

_PAN_FIELDS = [
    None, None, None, None, None, None, None,
    "src_ip", "dest_ip",
    None, None, None,
    "user",
    None,
    "app_proto",
    None, None, None, None, None, None, None, None, None,
    "src_port", "dest_port",
    None, None, None,
    "transport",
    None,
    "bytes", "bytes_out", "bytes_in", "packets_in",
    None,
    "duration",
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
        subject_type=NodeType.SOCKET,
        subject_id=socket_id(src_ip, src_port, None, None, transport or "tcp"),
        subject_name=f"{src_ip or '?'}:{src_port or '?'}",
        object_type=NodeType.SOCKET,
        object_id=socket_id(None, None, dest_ip, dest_port, transport or "tcp"),
        object_name=f"{dest_ip or '?'}:{dest_port or '?'}",
        edge_type=EdgeType.CONNECT,
        src_ip=src_ip,
        dest_ip=dest_ip,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: mysql_server_stats / mysql_transaction_details
# ──────────────────────────────────────────────────────────────────────────

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
        try:
            fields["duration"] = int(float(kv["Duration"]) * 1000)
        except ValueError:
            pass
    sql = kv.get("SQL_TEXT") or kv.get("sql_text")
    if sql:
        fields["command_line"] = sql
    db = kv.get("database_name") or kv.get("database")
    if db:
        fields["site"] = db
    port = kv.get("port")
    if port:
        iv = _to_int(port)
        if iv is not None:
            fields["dest_port"] = iv

    db_host = kv.get("hostname") or host

    # Need both a user and a host to form a meaningful USER -ACCESS-> HOST edge.
    # Without a user, the edge would collapse into a HOST -> HOST self-loop
    # carrying no causal signal — drop it instead of inflating the graph.
    if not db_user or not db_host:
        return EMPTY

    return ParsedRow(
        subject_type=NodeType.USER,
        subject_id=user_id(db_host, db_user),
        subject_name=db_user,
        object_type=NodeType.HOST,
        object_id=host_id(db_host),
        object_name=db_host,
        edge_type=EdgeType.ACCESS,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: WinHostMon
# ──────────────────────────────────────────────────────────────────────────

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
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=proc_id(host, pid, image or name),
            subject_name=cmd or image or name,
            object_type=NodeType.SOCKET,
            object_id=f"sock:*:{port}/{(proto or 'tcp').lower()}",
            object_name=f"*:{port}",
            edge_type=EdgeType.CONNECT,
            fields=fields,
        )
    return ParsedRow(
        subject_type=NodeType.PROCESS,
        subject_id=proc_id(host, pid, image or name),
        subject_name=cmd or image or name,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: linux_audit / auditd
# ──────────────────────────────────────────────────────────────────────────

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
    name = kv.get("name")
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

    subj_id = proc_id(host, pid, exe)
    subj_name = cmd or exe

    if syscall in ("execve", "execveat"):
        edge = EdgeType.EXEC
    elif syscall in ("open", "openat", "read", "readv", "pread64"):
        edge = EdgeType.READ
    elif syscall in ("write", "writev", "pwrite64", "creat"):
        edge = EdgeType.WRITE
    elif syscall in ("unlink", "unlinkat", "rmdir"):
        edge = EdgeType.DELETE
    elif syscall in ("rename", "renameat", "renameat2"):
        edge = EdgeType.RENAME
    elif syscall in ("connect", "sendto", "send"):
        edge = EdgeType.CONNECT
    elif syscall in ("clone", "fork", "vfork"):
        edge = EdgeType.FORK
    else:
        edge = None

    if name and edge in (EdgeType.READ, EdgeType.WRITE, EdgeType.DELETE,
                         EdgeType.RENAME, EdgeType.EXEC):
        return ParsedRow(
            subject_type=NodeType.PROCESS,
            subject_id=subj_id,
            subject_name=subj_name,
            object_type=NodeType.FILE,
            object_id=file_id(host, name),
            object_name=name,
            edge_type=edge,
            fields=fields,
        )
    return ParsedRow(
        subject_type=NodeType.PROCESS,
        subject_id=subj_id,
        subject_name=subj_name,
        edge_type=edge,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Parser: WinRegistry
# ──────────────────────────────────────────────────────────────────────────

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
    if data and len(data) < 200:
        fields["registry_value"] = data
    elif reg_type:
        fields["registry_value"] = reg_type
    if pid:
        iv = _to_int(pid)
        if iv is not None:
            fields["process_id"] = iv

    return ParsedRow(
        subject_type=NodeType.PROCESS,
        subject_id=proc_id(host, pid, image),
        subject_name=image,
        object_type=NodeType.REGISTRY,
        object_id=registry_id(host, key_path),
        object_name=key_path,
        edge_type=EdgeType.MODIFY_REG,
        fields=fields,
    )


# ──────────────────────────────────────────────────────────────────────────
# Stub
# ──────────────────────────────────────────────────────────────────────────

def parse_stub(raw: str, host: str | None) -> ParsedRow:
    return EMPTY


# ──────────────────────────────────────────────────────────────────────────
# Dispatch
# ──────────────────────────────────────────────────────────────────────────

def get_parser(sourcetype: str) -> Callable[[str, str | None], ParsedRow]:
    if sourcetype.startswith("stream_"):
        return parse_stream
    if sourcetype == "suricata":
        return parse_suricata
    if sourcetype in ("access_combined", "WebLogic_Access_Combined"):
        return parse_access_combined
    if sourcetype.startswith("XmlWinEventLog") and "Sysmon" in sourcetype:
        return parse_sysmon
    if sourcetype == "mordor_sysmon":
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
    return parse_stub
