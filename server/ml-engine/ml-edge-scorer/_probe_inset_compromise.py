r"""Score events using ONLY string values that appear in the training set.
Tests whether the model can recognise attack-like content when categorical
tokens are guaranteed to be in-vocabulary.
"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model_loader import load_models
from feature_row import build_feature_row

ms = load_models(Path("J:/THESIS-EDR/server/ml-engine/botsv2/models"))
m = ms["lgbm_xt_temporal_no_st"]
print(f"threshold={m.threshold}\n")


def sysmon(host, image, target, user, cmd=None, eid=11):
    cmd = cmd or image
    return ("<Event><System><EventID>{eid}</EventID>"
            "<Computer>{host}</Computer></System><EventData>"
            "<Data Name='ProcessId'>8821</Data>"
            "<Data Name='Image'>{image}</Data>"
            "<Data Name='CommandLine'>{cmd}</Data>"
            "<Data Name='TargetFilename'>{target}</Data>"
            "<Data Name='User'>{user}</Data>"
            "</EventData></Event>").format(eid=eid, host=host, image=image, cmd=cmd, target=target, user=user)


def mk(raw, src_type="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
       et="WRITE", obj="FILE", src_ip=None, dst_ip=None):
    return {
        "raw_event": raw, "sourcetype": src_type, "edge_type": et,
        "subject": {"node_type": "PROCESS" if obj != "SOCKET" else "SOCKET"},
        "object":  {"node_type": obj},
        "endpoint_id": "live", "properties": {
            "botsv2_fields": {"src_ip": src_ip, "dest_ip": dst_ip, "dest_port": 25 if src_type=="stream:smtp" else None}
        } if src_ip else {},
    }


SPLUNK_TRAIN_VALUES = {
    "host":  "wrk-klagerf",
    "image": r"C:\Program Files\SplunkUniversalForwarder\bin\splunk-winhostinfo.exe",
    "target":r"C:\Program Files\SplunkUniversalForwarder\bin\splunk-winhostinfo.exe",
    "user":  "NT AUTHORITY\\SYSTEM",
}
WMI_TRAIN_VALUES = {
    "host":  "wrk-klagerf",
    "image": r"C:\Windows\System32\wbem\WmiPrvSE.exe",
    "target":r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
    "cmd":   r"C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding",
    "user":  "NT AUTHORITY\\NETWORK SERVICE",
}

# In-vocab smtp values from training (the entire positive class is this 1 tuple)
SMTP_IN_VOCAB = {"src_ip": "104.47.41.54", "dst_ip": "172.31.38.181"}
SMTP_OUT = {"src_ip": "203.0.113.55",  "dst_ip": "10.0.0.7"}

stream_smtp_raw = json.dumps({
    "src_ip": "104.47.41.54", "dest_ip": "172.31.38.181",
    "src_port": 2080, "dest_port": 25, "transport": "tcp",
})

stream_smtp_novel_raw = json.dumps({
    "src_ip": "203.0.113.55", "dest_ip": "10.0.0.7",
    "src_port": 51234, "dest_port": 25, "transport": "tcp",
})

cases = [
    ("Sysmon: training-clone splunk-winhostinfo on wrk-klagerf",
        mk(sysmon(**SPLUNK_TRAIN_VALUES))),
    ("Sysmon: training-clone WmiPrvSE on wrk-klagerf",
        mk(sysmon(**WMI_TRAIN_VALUES))),
    ("Sysmon: training image+user but novel host",
        mk(sysmon(host="corp-pc-99", **{k:v for k,v in SPLUNK_TRAIN_VALUES.items() if k!='host'}))),
    ("Sysmon: training-clone img/user but TARGET=winsys32.dll (attack-shaped)",
        mk(sysmon(host=SPLUNK_TRAIN_VALUES['host'], image=SPLUNK_TRAIN_VALUES['image'],
                  user=SPLUNK_TRAIN_VALUES['user'],
                  target=r"C:\Windows\System32\winsys32.dll"))),
    ("Sysmon: ALL fields = same training-clone Splunk values",
        mk(sysmon(**SPLUNK_TRAIN_VALUES))),
    ("Sysmon: training-clone Splunk image + .crypt target",
        mk(sysmon(host=SPLUNK_TRAIN_VALUES['host'], image=SPLUNK_TRAIN_VALUES['image'],
                  user=SPLUNK_TRAIN_VALUES['user'],
                  target=r"C:\Users\bob\Documents\file.docx.crypt"))),
    ("stream:smtp IN-vocab pair (104.47.41.54 -> 172.31.38.181)",
        mk(stream_smtp_raw, src_type="stream:smtp", et="CONNECT", obj="SOCKET", **SMTP_IN_VOCAB)),
    ("stream:smtp NOVEL ip pair",
        mk(stream_smtp_novel_raw, src_type="stream:smtp", et="CONNECT", obj="SOCKET", **SMTP_OUT)),
]

print(f"{'case':<70} {'qual':<10} {'score':>8} {'verdict':>10}")
print("-" * 102)
for label, ev in cases:
    row, q = build_feature_row(ev)
    s = m.predict_proba(row)
    v = "ALERT" if s >= m.threshold else "benign"
    print(f"{label:<70} {q:<10} {s:>8.4f} {v:>10}")
