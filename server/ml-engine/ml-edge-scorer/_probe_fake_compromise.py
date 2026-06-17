r"""One-off probe — score fabricated compromise events against the production
honest model. Run from server/ to pick up botsv2_parsers on sys.path.

Goal: verify post-refactor that the honest-only pipeline scores plausible
APT-style telemetry as ALERT (>= 0.85) and a benign Word save as -.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # for botsv2_parsers

from model_loader import load_models
from feature_row import build_feature_row

MODELS_DIR = Path("J:/THESIS-EDR/server/ml-engine/botsv2/models")

ms = load_models(MODELS_DIR)
model_name = next(iter(ms))
m = ms[model_name]
THR = m.threshold
print(f"Loaded model: {model_name}   threshold={THR}\n")


def sysmon_eid11(host, image, target):
    return (
        f"<Event><System><EventID>11</EventID><Computer>{host}</Computer></System>"
        f"<EventData>"
        f"<Data Name='ProcessId'>8821</Data>"
        f"<Data Name='Image'>{image}</Data>"
        f"<Data Name='CommandLine'>{image}</Data>"
        f"<Data Name='TargetFilename'>{target}</Data>"
        f"<Data Name='User'>CORP\\jdoe</Data>"
        f"</EventData></Event>"
    )


# ── Fabricated COMPROMISE: malware drops winsys32.dll into System32 ─────────
# Same content shape as the real Taedonggang APT, but on a victim host the
# training set has NEVER seen (corp-laptop-027 ≠ wrk-btun/klagerf/venus).
# If the honest model truly learned content rather than host names, it must fire.
COMPROMISE = {
    "event_id": "fake-compromise-001",
    "raw_event": sysmon_eid11(
        "corp-laptop-027",
        r"C:\Users\jdoe\AppData\Local\Temp\invoice.zip.exe",
        r"C:\Windows\System32\winsys32.dll",
    ),
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "edge_type": "WRITE",
    "subject": {"node_type": "PROCESS"},
    "object":  {"node_type": "FILE"},
    "endpoint_id": "corp-laptop-027",
    "properties": {},
}

# ── BENIGN baseline: same host, same sourcetype, harmless Word doc ─────────
BENIGN = {
    "event_id": "fake-benign-001",
    "raw_event": sysmon_eid11(
        "corp-laptop-027",
        r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        r"C:\Users\jdoe\Documents\meeting-notes.docx",
    ),
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "edge_type": "WRITE",
    "subject": {"node_type": "PROCESS"},
    "object":  {"node_type": "FILE"},
    "endpoint_id": "corp-laptop-027",
    "properties": {},
}

# ── COMPROMISE 2: ransomware .crypt extension on different victim ───────────
CRYPT = {
    "event_id": "fake-crypt-001",
    "raw_event": sysmon_eid11(
        "finance-pc-04",
        r"C:\Users\acct\Downloads\not_a_virus.exe",
        r"C:\Users\acct\Documents\Q3_payroll.xlsx.crypt",
    ),
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "edge_type": "WRITE",
    "subject": {"node_type": "PROCESS"},
    "object":  {"node_type": "FILE"},
    "endpoint_id": "finance-pc-04",
    "properties": {},
}

# ── COMPROMISE 3: stream:smtp with s400 phishing password 912345678 ─────────
SMTP_PHISH = {
    "event_id": "fake-smtp-001",
    "raw_event": json.dumps({
        "src_ip": "203.0.113.55", "dest_ip": "10.0.0.7",
        "src_port": 51234, "dest_port": 25, "transport": "tcp",
        "protocol_stack": "smtp",
        "bytes_in": 4810, "bytes_out": 312,
        "body": "Please find invoice attached. Password to open: 912345678",
    }),
    "sourcetype": "stream:smtp",
    "edge_type": "CONNECT",
    "subject": {"node_type": "SOCKET"},
    "object":  {"node_type": "SOCKET"},
    "endpoint_id": "mail-relay-prod",
    "properties": {"botsv2_fields": {
        "src_ip": "203.0.113.55", "dest_ip": "10.0.0.7", "dest_port": 25}},
}

CASES = [
    ("COMPROMISE: winsys32.dll dropped (new host)",  COMPROMISE),
    ("BENIGN:     Word saving meeting-notes.docx",   BENIGN),
    ("COMPROMISE: .crypt ransomware write",          CRYPT),
    ("COMPROMISE: SMTP w/ 912345678 phishing pwd",   SMTP_PHISH),
]

print(f"{'case':<52} {'quality':<10} {'score':>8} {'verdict':>10}")
print("-" * 84)
for label, ev in CASES:
    row, q = build_feature_row(ev)
    s = m.predict_proba(row)
    verdict = "ALERT" if s >= THR else "benign"
    print(f"{label:<52} {q:<10} {s:>8.4f} {verdict:>10}")

print("\nFeature row the model sees for the winsys32.dll compromise:")
row, _ = build_feature_row(COMPROMISE)
for k, v in row.items():
    if v is not None:
        print(f"  {k:<25} = {str(v)[:70]!r}")
