"""Train OUR OWN FLASH model on DARPA TC E3 THEIA (Train=True path of
Theia.ipynb, cells 14-18). Self-supervised node-type prediction with the
20-shard iterative explain-away loop. Saves to trained_weights/theia_ours/
so the shipped weights (theia_ours_v2, the reproduction floor) are never
overwritten.

Train graph = edges of 1r base split, node types resolved over all 1r splits.
No attack labels needed (labels are node TYPES).

Raw DARPA data is read from THEIA_DATA_ROOT (default: <repo>/external/Flash-IDS).
Weights are written under this package's trained_weights/.
"""
from __future__ import annotations

import os
import random
import time
from pathlib import Path

import numpy as np
import torch
from gensim.models import Word2Vec
from sklearn.utils import class_weight
from torch.nn import CrossEntropyLoss
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader

import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT",
                                CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TRAIN_BASE = str(DATA_ROOT / "ta1-theia-e3-official-1r.json")
OUT_DIR = CODE_ROOT / os.environ.get("THEIA_OUT", "trained_weights/theia_ours")
# Tuning knobs (defaults = faithful notebook recipe):
SEED = int(os.environ.get("THEIA_SEED", "42"))
EPOCHS_PER_SHARD = int(os.environ.get("EPOCHS_PER_SHARD", "1"))
W2V_EPOCHS = int(os.environ.get("W2V_EPOCHS", "300"))
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
print(f"device: {device}  seed: {SEED}  epochs/shard: {EPOCHS_PER_SHARD}", flush=True)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    train_txt = fc.parse_split(TRAIN_BASE, TRAIN_BASE, str(DATA_ROOT / "theia_train.txt"))

    import pandas as pd
    rows = [l.split("\t") for l in
            Path(train_txt).read_text(encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    print(f"train edges: {len(df):,}", flush=True)
    df = fc.add_attributes(df, TRAIN_BASE)
    print(f"after attribute merge: {len(df):,}", flush=True)

    phrases, labels, edges, _ = fc.prepare_graph(df)
    print(f"nodes: {len(phrases):,}  (parse+graph {time.time()-t0:.0f}s)", flush=True)

    w2v_path = OUT_DIR / "word2vec_theia_E3.model"
    if w2v_path.exists():
        w2v = Word2Vec.load(str(w2v_path))
        print(f"reusing word2vec at {w2v_path}, vocab={len(w2v.wv)}", flush=True)
    else:
        print(f"training word2vec (vector_size=30, epochs={W2V_EPOCHS})...", flush=True)
        tw = time.time()
        w2v = Word2Vec(sentences=phrases, vector_size=fc.VECTOR_SIZE, window=5,
                       min_count=1, workers=8, epochs=W2V_EPOCHS, seed=SEED)
        w2v.save(str(w2v_path))
        print(f"  word2vec done in {time.time()-tw:.0f}s, vocab={len(w2v.wv)}", flush=True)

    enc = fc.PositionalEncoder()
    nodes = np.array([fc.infer(p, w2v, enc) for p in phrases])

    y = np.array(labels)
    cw = class_weight.compute_class_weight("balanced", classes=np.unique(y), y=y)
    cw = torch.tensor(cw, dtype=torch.float).to(device)
    criterion = CrossEntropyLoss(weight=cw, reduction="mean")

    g = Data(x=torch.tensor(nodes, dtype=torch.float).to(device),
             y=torch.tensor(labels, dtype=torch.long).to(device),
             edge_index=torch.tensor(edges, dtype=torch.long).to(device))
    g.n_id = torch.arange(g.num_nodes)
    mask = torch.ones(g.num_nodes, dtype=torch.bool)

    # model + optimizer created once (cell 15), persisted across all 20 shards:
    # continued training, snapshotting weights each round.
    net = fc.GCN(fc.VECTOR_SIZE, 5).to(device)
    opt = torch.optim.Adam(net.parameters(), lr=0.01, weight_decay=5e-4)
    print("starting 20-shard iterative training...", flush=True)
    for m_n in range(20):
        tit = time.time()
        remaining_before = int(mask.sum().item())
        total = 0.0
        for _ep in range(EPOCHS_PER_SHARD):
            total = 0.0
            for subg in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000, input_nodes=mask):
                net.train()
                opt.zero_grad()
                loss = criterion(net(subg.x, subg.edge_index), subg.y)
                loss.backward()
                opt.step()
                total += loss.item() * subg.batch_size

        for subg in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000, input_nodes=mask):
            net.eval()
            out = net(subg.x, subg.edge_index)
            s, ind = out.sort(dim=1, descending=True)
            conf = (s[:, 0] - s[:, 1]) / s[:, 0]
            conf = (conf - conf.min()) / conf.max()
            cond = (ind[:, 0] == subg.y) | (conf >= 0.9)
            mask[subg.n_id[cond]] = False

        torch.save(net.state_dict(), OUT_DIR / f"lword2vec_gnn_theia{m_n}_E3.pth")
        print(f"  shard {m_n}: loss={total/max(remaining_before,1):.4f}  "
              f"{int(mask.sum().item())} nodes still hard  ({time.time()-tit:.0f}s)", flush=True)

    print(f"DONE in {time.time()-t0:.0f}s. Weights in {OUT_DIR}", flush=True)


if __name__ == "__main__":
    main()
