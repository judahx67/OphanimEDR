"""
Feature extraction for per-Process MITRE-tactic classification.

Pulls per-Process graph features from Neo4j and builds multi-label
tactic vectors from rule-engine Incidents.

Features (~25 dims) — all derived from each Process node's edges in
the THEIA-derived provenance graph:

    Topology:
        out_degree, in_degree, distinct_edge_types,
        unique_object_count

    Edge-type counts:
        write_count, read_count, delete_count, rename_count,
        connect_count, send_count, recv_count,
        fork_count, exec_count,
        mmap_count, load_count, modify_reg_count

    Ratios (heavy-tailed → log1p applied later):
        write_read_ratio, connect_fork_ratio, send_recv_ratio

    Target-class flags (THEIA-aware):
        writes_to_tmp, writes_to_etc, writes_to_home, writes_to_var_log,
        reads_credentials, has_external_socket, has_short_lived_child

    Temporal:
        time_span_seconds, event_burstiness  (events / (1 + span))

Labels: multi-label across 11 MITRE tactics. A process gets tactic T
if ANY Incident touching its UUID came from a rule tagged with T.
Rule tags are loaded from /app/rules/*.yml at extraction time.
"""

import json
import logging
import os
import re
from pathlib import Path

import yaml

log = logging.getLogger("ml-engine.features")


# ── 11 MITRE tactic labels (must match attack.* tags in rule YAMLs) ──
TACTICS = [
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


# ── Feature query — per-Process graph stats ────────────────────────────
#
# Single Cypher pass, no APOC required. The IP-regex lives client-side
# so we don't push string parsing into Cypher.
FEATURE_QUERY = """
MATCH (p:Process)
OPTIONAL MATCH (p)-[out]->(o)
WITH p,
     collect({type: type(out), obj_uuid: o.uuid, obj_name: coalesce(o.name, ''),
              obj_label: labels(o)[0], ts: out.timestamp}) AS outs
OPTIONAL MATCH ()-[in_]->(p)
WITH p, outs, count(in_) AS in_degree
RETURN
    p.uuid AS uuid,
    coalesce(p.name, '') AS name,
    in_degree,
    outs
"""


LABEL_QUERY = """
MATCH (i:Incident)
RETURN i.rule_id AS rule_id, i.matched_nodes AS matched_nodes
"""


# ── Path / IP heuristics for THEIA-aware features ──────────────────────

CRED_PATH_RE = re.compile(r"(?i)(/etc/(shadow|passwd|sudoers)|\.ssh/|\.aws/|\.netrc)")
TMP_PATH_RE = re.compile(r"(?i)^/tmp/|^/var/tmp/|^/dev/shm/")
ETC_PATH_RE = re.compile(r"(?i)^/etc/")
HOME_PATH_RE = re.compile(r"(?i)^/home/|^/root/")
LOG_PATH_RE = re.compile(r"(?i)^/var/log/")

# IPv4 dotted quad with port, e.g. "1.2.3.4:443"
SOCKET_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$")


def _is_external_ip(ip: str) -> bool:
    """True if the IP is plausibly a public address."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return False
    if a == 127:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 0:
        return False
    return True


# ── Rule → tactic-set lookup, loaded once at startup ────────────────────

def _load_rule_tactics(rules_dir: str) -> dict[str, set[str]]:
    """Map rule_id → set of MITRE tactics from each rule's `tags:` block."""
    rule_tactics: dict[str, set[str]] = {}
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        log.warning("Rules dir not found: %s — tactic labels will be empty", rules_dir)
        return rule_tactics

    for f in rules_path.glob("*.yml"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        except Exception as exc:
            log.warning("Failed to load %s: %s", f, exc)
            continue
        rule_id = raw.get("id")
        tags = raw.get("tags") or []
        tactics: set[str] = set()
        for t in tags:
            if not isinstance(t, str):
                continue
            if not t.startswith("attack."):
                continue
            stripped = t[len("attack."):]
            if stripped in TACTICS:
                tactics.add(stripped)
        if rule_id and tactics:
            rule_tactics[rule_id] = tactics

    log.info("Loaded tactics for %d rules", len(rule_tactics))
    return rule_tactics


# ── Per-process feature computation ─────────────────────────────────────

FEATURE_NAMES = [
    "out_degree",
    "in_degree",
    "distinct_edge_types",
    "unique_object_count",
    "write_count",
    "read_count",
    "delete_count",
    "rename_count",
    "connect_count",
    "send_count",
    "recv_count",
    "fork_count",
    "exec_count",
    "mmap_count",
    "load_count",
    "modify_reg_count",
    "write_read_ratio",
    "connect_fork_ratio",
    "send_recv_ratio",
    "writes_to_tmp",
    "writes_to_etc",
    "writes_to_home",
    "writes_to_var_log",
    "reads_credentials",
    "has_external_socket",
    "time_span_seconds",
    "event_burstiness",
]


def _compute_features(outs: list[dict], in_degree: int) -> dict[str, float]:
    """Reduce a process's outgoing edges into a feature vector."""
    edge_counts: dict[str, int] = {}
    obj_uuids: set[str] = set()
    timestamps: list[int] = []

    writes_to_tmp = writes_to_etc = writes_to_home = writes_to_var_log = 0
    reads_credentials = 0
    has_external_socket = 0

    for e in outs:
        et = e.get("type")
        if not et:
            continue
        edge_counts[et] = edge_counts.get(et, 0) + 1

        oid = e.get("obj_uuid")
        if oid:
            obj_uuids.add(oid)

        ts = e.get("ts")
        if isinstance(ts, (int, float)) and ts > 0:
            timestamps.append(int(ts))

        oname = (e.get("obj_name") or "").strip()
        olabel = e.get("obj_label")

        if et == "WRITE" and oname:
            if TMP_PATH_RE.search(oname):
                writes_to_tmp = 1
            if ETC_PATH_RE.search(oname):
                writes_to_etc = 1
            if HOME_PATH_RE.search(oname):
                writes_to_home = 1
            if LOG_PATH_RE.search(oname):
                writes_to_var_log = 1

        if et == "READ" and oname and CRED_PATH_RE.search(oname):
            reads_credentials = 1

        if et in ("CONNECT", "SEND", "RECEIVE") and olabel == "Socket":
            m = SOCKET_RE.match(oname)
            if m and _is_external_ip(m.group(1)):
                has_external_socket = 1

    def c(name: str) -> int:
        return edge_counts.get(name, 0)

    out_degree = sum(edge_counts.values())
    write_c, read_c = c("WRITE"), c("READ")
    connect_c, fork_c = c("CONNECT"), c("FORK")
    send_c, recv_c = c("SEND"), c("RECEIVE")

    if timestamps:
        span_ns = max(timestamps) - min(timestamps)
        # THEIA timestamps are nanoseconds
        time_span = span_ns / 1e9
    else:
        time_span = 0.0
    burstiness = out_degree / (1.0 + time_span)

    return {
        "out_degree": out_degree,
        "in_degree": in_degree,
        "distinct_edge_types": len(edge_counts),
        "unique_object_count": len(obj_uuids),
        "write_count": write_c,
        "read_count": read_c,
        "delete_count": c("DELETE"),
        "rename_count": c("RENAME"),
        "connect_count": connect_c,
        "send_count": send_c,
        "recv_count": recv_c,
        "fork_count": fork_c,
        "exec_count": c("EXEC"),
        "mmap_count": c("MMAP"),
        "load_count": c("LOAD"),
        "modify_reg_count": c("MODIFY_REG"),
        "write_read_ratio": write_c / (1.0 + read_c),
        "connect_fork_ratio": connect_c / (1.0 + fork_c),
        "send_recv_ratio": send_c / (1.0 + recv_c),
        "writes_to_tmp": writes_to_tmp,
        "writes_to_etc": writes_to_etc,
        "writes_to_home": writes_to_home,
        "writes_to_var_log": writes_to_var_log,
        "reads_credentials": reads_credentials,
        "has_external_socket": has_external_socket,
        "time_span_seconds": time_span,
        "event_burstiness": burstiness,
    }


# ── Public entry point ──────────────────────────────────────────────────

def extract(driver, rules_dir: str = "/app/rules") -> list[dict]:
    """
    Returns one row per Process:
        {
            uuid, name,
            features: {feature_name: float, ...},
            labels: {tactic: 0/1, ...},   # 11 binary tactic labels
        }
    """
    rule_tactics = _load_rule_tactics(rules_dir)

    with driver.session() as s:
        rows = []
        for record in s.run(FEATURE_QUERY):
            outs = [o for o in record["outs"] if o and o.get("type")]
            features = _compute_features(outs, record["in_degree"] or 0)
            rows.append({
                "uuid": record["uuid"],
                "name": record["name"],
                "features": features,
                "labels": {t: 0 for t in TACTICS},
            })

        # Build uuid → tactics map from incidents.
        # NOTE: rule-engine writes matched_nodes as a JSON string of
        # [{id,type,name}, ...] objects, not a flat UUID array.
        uuid_tactics: dict[str, set[str]] = {}
        for r in s.run(LABEL_QUERY):
            rid = r["rule_id"]
            matched_raw = r["matched_nodes"]
            tactics = rule_tactics.get(rid, set())
            if not tactics or not matched_raw:
                continue

            # matched_raw can be a JSON string OR an already-parsed list
            # depending on driver/version. Handle both.
            if isinstance(matched_raw, str):
                try:
                    matched = json.loads(matched_raw)
                except Exception:
                    continue
            else:
                matched = matched_raw

            if not isinstance(matched, list):
                continue
            for entry in matched:
                if isinstance(entry, dict):
                    # Only label PROCESS nodes — features are per-Process
                    if entry.get("type") and entry["type"] != "PROCESS":
                        continue
                    node_id = entry.get("id")
                elif isinstance(entry, str):
                    node_id = entry
                else:
                    continue
                if node_id:
                    uuid_tactics.setdefault(node_id, set()).update(tactics)

    n_pos = 0
    for row in rows:
        tactics = uuid_tactics.get(row["uuid"], set())
        if tactics:
            n_pos += 1
            for t in tactics:
                if t in row["labels"]:
                    row["labels"][t] = 1

    log.info(
        "Extracted %d processes; %d carry at least one tactic label",
        len(rows),
        n_pos,
    )
    # Per-tactic counts for visibility
    counts = {t: sum(r["labels"][t] for r in rows) for t in TACTICS}
    log.info("Per-tactic positive counts: %s",
             {k: v for k, v in counts.items() if v > 0})

    return rows
