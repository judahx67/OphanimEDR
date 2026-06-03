"""Reproduce FLASH-on-OpTC FLOOR using FLASH's pretrained GraphSAGE directly
(gnn_temp.pth), bypassing the dead xgboost-0.90 xgb.pkl (unreadable by xgboost
3.x). The GNN has a 4-class node-type head; detection = node-type
misclassification / low-confidence, the same explain-away idea as our THEIA
harness. We report RAW (no 2-hop) AND 2-hop-adjusted per attack host.

This is "FLASH's pretrained GNN + our honest harness" — the known-good floor to
beat with our own trained weights. NOT the decoupled XGBoost variant (its pickle
is version-locked); the GNN is the same model family and directly comparable to
our THEIA GraphSAGE results.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/reproduce_flash_gnn.py
"""
from __future__ import annotations
import json, os, time  # noqa: F401  (time used in run_host)
from pathlib import Path
import numpy as np
import torch
from gensim.models import Word2Vec
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("OPTC_DATA", CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "_optc_gt"))
FLASH = CODE_ROOT.parents[2] / "external" / "Flash-IDS"
W2V = DATA / "w2v_optc.model"
GNN = FLASH / "trained_weights" / "optc" / "gnn_temp.pth"
GT_TXT = FLASH / "data_files" / "optc.txt"
CONF = 0.0   # FLASH OpTC uses per-host conf thresholds; floor reported at conf=0 (pure misclassification) + swept
device = torch.device("cpu")
HOSTS = ["0051", "0201", "0501"]


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


def run_host(host, w2v, enc, model, GT_ALL, log):
    t0 = time.time()
    events = fc.load_events(DATA / f"SysClient{host}.systemia.com.txt")
    ent = {e["actorID"] for e in events} | {e["objectID"] for e in events}
    gt = {g for g in GT_ALL if g in ent}
    df = fc.transform(events)
    feats, y, edges, mapp, _, _ = fc.featurize(df, w2v, enc)
    X = np.array(feats, dtype=np.float32)

    g = Data(x=torch.tensor(X), y=torch.tensor(y, dtype=torch.long),
             edge_index=torch.tensor(edges, dtype=torch.long))
    g.n_id = torch.arange(g.num_nodes)
    pred = torch.zeros(g.num_nodes, dtype=torch.long)
    conf = torch.zeros(g.num_nodes)
    model.eval()
    for sub in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        with torch.no_grad():
            out = model(sub.x, sub.edge_index)          # softmax over 4 types
        s, ind = out.sort(dim=1, descending=True)
        c = (s[:, 0] - s[:, 1]) / s[:, 0]
        pred[sub.n_id] = ind[:, 0].cpu()
        conf[sub.n_id] = c.cpu()
    cmin, cmax = conf.min(), conf.max()
    conf = (conf - cmin) / (cmax - cmin + 1e-9)
    type_acc = (pred.numpy() == y).mean()

    def metrics_at(th):
        ok = (pred == torch.tensor(y)) & (conf > th)
        flag = ~ok
        alert = {mapp[i] for i in utils.mask_to_index(flag).tolist()}
        TP = alert & gt; FP = alert - gt; FN = gt - alert
        p, r, f = prf(len(TP), len(FP), len(FN))
        two_gp = get_adjacent(gt, mapp, edges, 2)
        two_tp = get_adjacent(TP, mapp, edges, 2)
        FPL = FP - two_gp; TPL = TP | (FN & two_tp); FNa = FN - two_tp
        p2, r2, f2 = prf(len(TPL), len(FPL), len(FNa))
        return (len(TP), len(FP), len(FN), p, r, f,
                len(TPL), len(FPL), len(FNa), p2, r2, f2, len(alert))

    log.append(f"\n=== host {host} ===")
    log.append(f"  events={len(events):,} nodes={len(mapp):,} GT-in-host={len(gt)} "
               f"node-type-acc={type_acc:.4f} ({time.time()-t0:.0f}s)")
    for th in (0.0, 0.6, 0.9, 0.98):
        (tp, fp, fn, p, r, f, tpl, fpl, fna, p2, r2, f2, na) = metrics_at(th)
        log.append(f"  conf>{th:<4}: alerts={na:<6} "
                   f"RAW TP={tp} FP={fp} FN={fn} P={p:.3f} R={r:.3f} F1={f:.3f}  |  "
                   f"2HOP TP={tpl} FP={fpl} FN={fna} P={p2:.3f} R={r2:.3f} F1={f2:.3f}")


def main():
    enc = fc.PositionalEncoder()
    print("loading w2v + gnn ...", flush=True)
    w2v = Word2Vec.load(str(W2V))
    model = fc.GCN().to(device)
    model.load_state_dict(torch.load(GNN, map_location=device, weights_only=True))
    GT_ALL = set(open(GT_TXT, encoding="utf-8").read().split())
    print(f"  w2v vocab={len(w2v.wv):,}  GT={len(GT_ALL)}", flush=True)
    log = []
    for host in HOSTS:
        try:
            run_host(host, w2v, enc, model, GT_ALL, log)
            print("\n".join(log), flush=True)
            (CODE_ROOT / "_reproduce_flash_gnn.log").write_text("\n".join(log), encoding="utf-8")
        except Exception as e:
            import traceback; log.append(f"host {host} FAILED: {e!r}"); traceback.print_exc()
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
