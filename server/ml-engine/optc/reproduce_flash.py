"""Reproduce FLASH's published OpTC numbers as a known-good FLOOR, scored with
our HONEST harness: report RAW (no 2-hop) AND 2-hop-adjusted side by side.

Pipeline (OpTC.ipynb eval cells 28/32/34/36): per attack host ->
  load events -> transform -> featurize (w2v + positional) -> stack GNN
  embedding from emb_store.json (jaccard==1 gate) -> XGBoost predict ->
  flag misclassified&low-conf nodes -> compare to GT (optc.txt).

FLASH publishes per-host precision/recall/fscore via helper() (2-hop). We add the
RAW line the paper never prints (same critique as THEIA _verify_gnn.py).

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/reproduce_flash.py
"""
from __future__ import annotations
import json, os, pickle, time
from pathlib import Path
import numpy as np
import torch
from gensim.models import Word2Vec
from torch_geometric import utils
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("OPTC_DATA", CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "_optc_gt"))
FLASH = CODE_ROOT.parents[2] / "external" / "Flash-IDS"
W2V = DATA / "w2v_optc.model"
XGB = FLASH / "trained_weights" / "optc" / "xgb.pkl"
EMB_STORE = FLASH / "data_files" / "emb_store.json"
GT_TXT = FLASH / "data_files" / "optc.txt"

# (host, confidence_threshold) per notebook eval cells
HOSTS = [("0051", 0.6), ("0201", 0.0), ("0501", 0.98)]


def get_adjacent(ids, mapp, edges, hops):
    if hops == 0:
        return set()
    nb = set()
    for s, t in zip(edges[0], edges[1]):
        if mapp[s] in ids or mapp[t] in ids:
            nb.add(mapp[s]); nb.add(mapp[t])
    if hops > 1:
        nb |= get_adjacent(nb, mapp, edges, hops - 1)
    return nb


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f = 2 * p * r / (p + r) if p + r else 0
    return p, r, f


def load_features_test(df, w2v, enc, gnn_map, sim_threshold=1):
    nodes, y, edges, mapp, lbl, nemap = fc.featurize(df, w2v, enc)
    X = []
    for i, nid in enumerate(mapp):
        emb = np.zeros(fc.VECTOR_SIZE)
        label = lbl[nid]
        if label in gnn_map:
            stored_emb, stored_set = gnn_map[label]
            cur = nemap[nid]
            union = cur | set(stored_set)
            jac = len(cur & set(stored_set)) / len(union) if union else 0
            if jac >= sim_threshold:
                emb = np.array(stored_emb)
        X.append(np.hstack((nodes[i], emb)))
    return np.array(X), y, edges, mapp


def run_host(host, conf_th, w2v, enc, gnn_map, xgb, GT_ALL, log):
    path = DATA / f"SysClient{host}.systemia.com.txt"
    t0 = time.time()
    events = fc.load_events(path)
    ent = {e["actorID"] for e in events} | {e["objectID"] for e in events}
    gt = {g for g in GT_ALL if g in ent}
    df = fc.transform(events)
    X, y, edges, mapp = load_features_test(df, w2v, enc, gnn_map)
    pred = xgb.predict(X)
    proba = xgb.predict_proba(X)
    sp = np.sort(proba, axis=1)
    conf = (sp[:, -1] - sp[:, -2]) / sp[:, -1]
    conf = (conf - conf.min()) / conf.max()
    ok = (pred == y) & (conf > conf_th)
    flag = ~torch.tensor(ok)
    idx = utils.mask_to_index(flag).tolist()
    alert = {mapp[i] for i in idx}

    TP = alert & gt; FP = alert - gt; FN = gt - alert
    p, r, f = prf(len(TP), len(FP), len(FN))
    two_gp = get_adjacent(gt, mapp, edges, 2)
    two_tp = get_adjacent(TP, mapp, edges, 2)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FNa = FN - two_tp
    p2, r2, f2 = prf(len(TPL), len(FPL), len(FNa))

    log.append(f"\n=== host {host} (conf>{conf_th}) ===")
    log.append(f"  events={len(events):,} nodes={len(mapp):,} GT-in-host={len(gt)} "
               f"alerts={len(alert)} ({time.time()-t0:.0f}s)")
    log.append(f"  (RAW   no-2hop) TP={len(TP)} FP={len(FP)} FN={len(FN)}  "
               f"P={p:.4f} R={r:.4f} F1={f:.4f}")
    log.append(f"  (2-HOP adjust ) TP={len(TPL)} FP={len(FPL)} FN={len(FNa)}  "
               f"P={p2:.4f} R={r2:.4f} F1={f2:.4f}  "
               f"<- forgave {len(FP)-len(FPL)} FP, promoted {len(TPL)-len(TP)} FN->TP")
    return (host, p, r, f, p2, r2, f2)


def main():
    import xgboost  # noqa: ensure available
    enc = fc.PositionalEncoder()
    print("loading w2v + xgb + emb_store ...", flush=True)
    w2v = Word2Vec.load(str(W2V))
    xgb = pickle.load(open(XGB, "rb"))
    gnn_map = json.load(open(EMB_STORE, encoding="utf-8"))
    GT_ALL = set(open(GT_TXT, encoding="utf-8").read().split())
    print(f"  w2v vocab={len(w2v.wv):,}  gnn_map keys={len(gnn_map):,}  GT={len(GT_ALL)}", flush=True)

    log = []
    for host, cth in HOSTS:
        try:
            run_host(host, cth, w2v, enc, gnn_map, xgb, GT_ALL, log)
            print("\n".join(log), flush=True); log = []
        except Exception as e:
            print(f"host {host} FAILED: {e!r}", flush=True)
            import traceback; traceback.print_exc()
    out = CODE_ROOT / "_reproduce_flash.log"
    print("done; see", out, flush=True)


if __name__ == "__main__":
    main()
