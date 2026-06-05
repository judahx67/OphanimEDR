"""OpTC half of the cross-dataset denominator figure (THEIA half = _verify_gnn_deblob.py).

Decomposes FLASH's OpTC GNN flags (gnn_temp.pth, our honest harness) BY NODE TYPE and
re-scores under collapsed GT denominators, per host. Shows the process-detection floor:
- GT type composition (the OpTC analogue of THEIA's 99.7% netflow blob).
- RAW recall per type (process recall ~0 expected) at the conf=0 floor.
- F1 under full / no_flow / proc_file / proc_only denominators.
- What 2-hop forgiveness promotes (the trick), per type.

Inference (featurize + 20-shard GNN) is cached per host to `_deblob_optc_{host}.pkl` so
re-analysis is cheap; 0501 featurize is ~17 min on first run.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/gnn_denominator_optc.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np, torch
from gensim.models import Word2Vec
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
import optc_flash_common as fc
from reproduce_flash_gnn import get_adjacent, prf, DATA, W2V, GNN, GT_TXT, HOSTS

CODE_ROOT = Path(__file__).resolve().parent
device = torch.device("cpu")
TYPES = {0: "process", 1: "flow", 2: "file", 3: "module"}


def infer_host(host, w2v, enc, model):
    cache = CODE_ROOT / f"_deblob_optc_{host}.pkl"
    if cache.exists():
        return pickle.load(open(cache, "rb"))
    t0 = time.time()
    events = fc.load_events(DATA / f"SysClient{host}.systemia.com.txt")
    ent = {e["actorID"] for e in events} | {e["objectID"] for e in events}
    GT_ALL = set(open(GT_TXT, encoding="utf-8").read().split())
    gt = {g for g in GT_ALL if g in ent}
    feats, y, edges, mapp, _, _ = fc.featurize(fc.transform(events), w2v, enc)
    X = np.array(feats, dtype=np.float32)
    g = Data(x=torch.tensor(X), y=torch.tensor(y, dtype=torch.long),
             edge_index=torch.tensor(edges, dtype=torch.long))
    g.n_id = torch.arange(g.num_nodes)
    pred = torch.zeros(g.num_nodes, dtype=torch.long); conf = torch.zeros(g.num_nodes)
    model.eval()
    for sub in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        with torch.no_grad():
            out = model(sub.x, sub.edge_index)
        s, ind = out.sort(dim=1, descending=True)
        c = (s[:, 0] - s[:, 1]) / s[:, 0]
        pred[sub.n_id] = ind[:, 0].cpu(); conf[sub.n_id] = c.cpu()
    conf = (conf - conf.min()) / (conf.max() - conf.min() + 1e-9)
    out = {"pred": pred.numpy(), "conf": conf.numpy(), "y": np.array(y),
           "edges": edges, "mapp": mapp, "gt": gt, "secs": time.time() - t0}
    pickle.dump(out, open(cache, "wb"))
    return out


def analyze(host, d, log):
    pred, conf, y, edges, mapp, gt = d["pred"], d["conf"], d["y"], d["edges"], d["mapp"], d["gt"]
    uuid_type = {mapp[i]: int(y[i]) for i in range(len(mapp))}
    gt_t = {t: {u for u in gt if uuid_type.get(u) == t} for t in TYPES}
    comp = "  ".join(f"{TYPES[t]}={len(gt_t[t])}" for t in TYPES)
    log.append(f"\n=== host {host} ===  GT={len(gt)}  [{comp}]  ({d['secs']:.0f}s featurize)")

    ok = (pred == y) & (conf > 0.0)            # FLASH explain-away floor
    alert = {mapp[i] for i in utils.mask_to_index(torch.tensor(~ok)).tolist()}
    a_comp = "  ".join(f"{TYPES[t]}={sum(1 for u in alert if uuid_type.get(u)==t)}" for t in TYPES)
    log.append(f"  flagged={len(alert)}  [{a_comp}]")

    log.append("  per-type RAW recall (flagged / GT-of-type):")
    for t in TYPES:
        if gt_t[t]:
            rec = len(alert & gt_t[t]) / len(gt_t[t])
            log.append(f"    {TYPES[t]:<8} {len(alert & gt_t[t])}/{len(gt_t[t])} = {rec:.3f}")

    def score(sub, tag):
        tp = alert & sub; fp = alert - sub; fn = sub - alert
        p, r, f = prf(len(tp), len(fp), len(fn))
        log.append(f"    {tag:<11} |GT|={len(sub):>5} TP={len(tp):>4} FP={len(fp):>6} "
                   f"P={p:.4f} R={r:.4f} F1={f:.4f}")
    log.append("  RAW F1 under collapsing denominators:")
    score(gt, "full")
    score(gt - gt_t[1], "no_flow")
    score(gt_t[0] | gt_t[2], "proc_file")
    score(gt_t[0], "proc_only")

    # what does 2-hop forgiveness promote, by type
    tp = alert & gt; fn = gt - alert
    two_tp = get_adjacent(tp, mapp, edges, 2)
    promoted = fn & two_tp
    pr_comp = "  ".join(f"{TYPES[t]}={sum(1 for u in promoted if uuid_type.get(u)==t)}" for t in TYPES)
    log.append(f"  2-hop promotes {len(promoted)} FN->TP  [{pr_comp}]  "
               f"(proc promoted: {sum(1 for u in promoted if uuid_type.get(u)==0)}/{len(gt_t[0])})")


def main():
    enc = fc.PositionalEncoder()
    print("loading w2v + gnn ...", flush=True)
    w2v = Word2Vec.load(str(W2V))
    model = fc.GCN().to(device)
    model.load_state_dict(torch.load(GNN, map_location=device, weights_only=True))
    log = []
    for host in HOSTS:
        d = infer_host(host, w2v, enc, model)
        analyze(host, d, log)
        print("\n".join(log), flush=True)
        (CODE_ROOT / "_gnn_denominator_optc.log").write_text("\n".join(log), encoding="utf-8")
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
