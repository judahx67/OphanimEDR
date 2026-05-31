"""FLASH evaluation on DARPA TC E3 THEIA test split (6r.json.8).

Faithful port of Theia.ipynb eval path (cells 19-23). Shared parse/graph/model
code lives in theia_flash_common. Set THEIA_WEIGHTS to point at a weights dir
under this package (default trained_weights/theia_ours_v2, our trained model).

Raw DARPA data is read from THEIA_DATA_ROOT (default: <repo>/external/Flash-IDS).

  THEIA_WEIGHTS=trained_weights/theia_ours_v2 python evaluate.py
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import numpy as np
import torch
from gensim.models import Word2Vec
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader

import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT",
                                CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
WEIGHTS = CODE_ROOT / os.environ.get("THEIA_WEIGHTS", "trained_weights/theia_ours_v3")


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


def helper(MP, all_ids, GP, edges, mapp):
    TP, FP, FN = MP & GP, MP - GP, GP - MP
    TN = all_ids - (GP | MP)
    two_gp = get_adjacent(GP, mapp, edges, 2)
    two_tp = get_adjacent(TP, mapp, edges, 2)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FN = FN - two_tp
    tp, fp, fn, tn = len(TPL), len(FPL), len(FN), len(TN)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print("\n=== METRICS (2-hop adjusted) ===")
    print(f"  weights: {WEIGHTS}")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  precision={prec:.4f}  recall={rec:.4f}  F1={f1:.4f}  FPR={fpr:.4f}")
    print("  paper headline (THEIA E3): precision ~0.90+, recall ~0.99")


def main():
    test_txt = DATA_ROOT / "theia_test.txt"
    fc.parse_split(TEST_BASE, TEST_SPLIT, str(test_txt))

    import pandas as pd
    data = [l.split("\t") for l in test_txt.read_text(encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(data, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    print(f"test edges: {len(df):,}", flush=True)
    df = fc.add_attributes(df, TEST_SPLIT)
    print(f"after attribute merge: {len(df):,}", flush=True)

    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    w2v = Word2Vec.load(str(WEIGHTS / "word2vec_theia_E3.model"))
    enc = fc.PositionalEncoder()
    nodes = np.array([fc.infer(p, w2v, enc) for p in phrases])
    all_ids = set(df["actorID"]) | set(df["objectID"])
    print(f"nodes: {len(nodes):,}  GT malicious: {len(GT):,}", flush=True)

    g = Data(x=torch.tensor(nodes, dtype=torch.float).to(device),
             y=torch.tensor(labels, dtype=torch.long).to(device),
             edge_index=torch.tensor(edges, dtype=torch.long).to(device))
    g.n_id = torch.arange(g.num_nodes)
    flag = torch.ones(g.num_nodes, dtype=torch.bool)
    model = fc.GCN(fc.VECTOR_SIZE, 5).to(device)
    for m_n in range(20):
        sd = torch.load(WEIGHTS / f"lword2vec_gnn_theia{m_n}_E3.pth",
                        map_location=device, weights_only=True)
        model.load_state_dict(sd)
        model.eval()
        for subg in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
            out = model(subg.x, subg.edge_index)
            s, ind = out.sort(dim=1, descending=True)
            conf = (s[:, 0] - s[:, 1]) / s[:, 0]
            conf = (conf - conf.min()) / conf.max()
            cond = (ind[:, 0] == subg.y) & (conf > 0.53)
            flag[subg.n_id[cond]] = False
        print(f"  shard {m_n}: {flag.sum().item()} nodes still flagged", flush=True)

    idx = utils.mask_to_index(flag).tolist()
    alert_ids = {mapp[x] for x in idx}
    helper(alert_ids, all_ids, GT, edges, mapp)


if __name__ == "__main__":
    main()
