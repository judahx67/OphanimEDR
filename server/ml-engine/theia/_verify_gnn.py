"""Skeptic's verification of the THEIA FLASH **GNN** result (mirror of
_verify_lgbm.py, but for the GraphSAGE+Word2Vec model in theia_ours_v3).

Runs the exact production inference (20-shard explain-away, evaluate.py /
theia-gnn-scorer) on the held-out 6r.8 graph and reports, side by side:
  (a) node-TYPE classification accuracy (shard 0)  -- the task it was trained on
  (b) RAW flagged-vs-GT precision/recall/F1         -- no 2-hop forgiveness
  (c) 2-HOP ADJUSTED precision/recall/F1            -- reproduces evaluate.py headline

So the GNN gets the same honest RAW measurement the LGBM already has, making the
"both FLASH clones collapse without 2-hop" claim airtight.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_verify_gnn.py
"""
from __future__ import annotations
import json, os, pickle, time
from pathlib import Path
import numpy as np, pandas as pd, torch
from gensim.models import Word2Vec
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
WEIGHTS = CODE_ROOT / os.environ.get("THEIA_WEIGHTS", "trained_weights/theia_ours_v3")
CACHE = DATA_ROOT / "_verify_gnn_feats.pkl"
CONF = 0.53
device = torch.device("cpu")


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


def featurize():
    if CACHE.exists():
        print(f"reusing feature cache {CACHE}", flush=True)
        return pickle.load(open(CACHE, "rb"))
    w2v = Word2Vec.load(str(WEIGHTS / "word2vec_theia_E3.model")); enc = fc.PositionalEncoder()
    fc.parse_split(TEST_BASE, TEST_SPLIT, str(DATA_ROOT / "theia_test.txt"))
    rows = [l.split("\t") for l in (DATA_ROOT / "theia_test.txt").read_text(
        encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID", "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    df = fc.add_attributes(df, TEST_SPLIT)
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    X = np.array([fc.infer(p, w2v, enc) for p in phrases]).astype(np.float32)
    all_ids = set(df["actorID"]) | set(df["objectID"])
    out = (X, np.array(labels), edges, mapp, all_ids)
    pickle.dump(out, open(CACHE, "wb"))
    return out


def main():
    t0 = time.time()
    X, yte, edges, mapp, all_ids = featurize()
    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    print(f"test nodes={len(yte):,}  GT malicious={len(GT):,}  (featurize {time.time()-t0:.0f}s)", flush=True)

    g = Data(x=torch.tensor(X, dtype=torch.float).to(device),
             y=torch.tensor(yte, dtype=torch.long).to(device),
             edge_index=torch.tensor(edges, dtype=torch.long).to(device))
    g.n_id = torch.arange(g.num_nodes)
    flag = torch.ones(g.num_nodes, dtype=torch.bool)
    model = fc.GCN(fc.VECTOR_SIZE, 5).to(device)
    s0_pred = None
    for m_n in range(20):
        sd = torch.load(WEIGHTS / f"lword2vec_gnn_theia{m_n}_E3.pth", map_location=device, weights_only=True)
        model.load_state_dict(sd); model.eval()
        for subg in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
            with torch.no_grad():
                out = model(subg.x, subg.edge_index)
            s, ind = out.sort(dim=1, descending=True)
            conf = (s[:, 0] - s[:, 1]) / s[:, 0]
            conf = (conf - conf.min()) / conf.max()
            cond = (ind[:, 0] == subg.y) & (conf > CONF)
            flag[subg.n_id[cond]] = False
            if m_n == 0:
                if s0_pred is None:
                    s0_pred = torch.zeros(g.num_nodes, dtype=torch.long)
                s0_pred[subg.n_id] = ind[:, 0].cpu()
        print(f"  shard {m_n}: {int(flag.sum().item())} nodes still flagged", flush=True)

    # (a) node-TYPE accuracy of the real model (shard 0)
    type_acc = (s0_pred.numpy() == yte).mean()
    print(f"\n(a) NODE-TYPE classification accuracy (shard0): {type_acc:.4f}  "
          f"-- this is the task the GNN was actually trained on")

    idx = utils.mask_to_index(flag).tolist()
    alert_ids = {mapp[x] for x in idx}

    # (b) RAW, no 2-hop forgiveness
    TP = alert_ids & GT; FP = alert_ids - GT; FN = GT - alert_ids
    TN = all_ids - (GT | alert_ids)
    p, r, f = prf(len(TP), len(FP), len(FN))
    print(f"\n(b) RAW (no 2-hop):      TP={len(TP)} FP={len(FP)} FN={len(FN)} TN={len(TN)}  "
          f"precision={p:.4f} recall={r:.4f} F1={f:.4f}")

    # (c) 2-hop adjusted (reproduces evaluate.py headline)
    two_gp = get_adjacent(GT, mapp, edges, 2)
    two_tp = get_adjacent(TP, mapp, edges, 2)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FNa = FN - two_tp
    p2, r2, f2 = prf(len(TPL), len(FPL), len(FNa))
    print(f"(c) 2-HOP ADJUSTED:      TP={len(TPL)} FP={len(FPL)} FN={len(FNa)}  "
          f"precision={p2:.4f} recall={r2:.4f} F1={f2:.4f}  "
          f"<- forgave {len(FP)-len(FPL)} FPs, promoted {len(TPL)-len(TP)} FNs->TP")


if __name__ == "__main__":
    main()
