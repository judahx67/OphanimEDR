"""MODEL B — supervised GraphSAGE on OpTC (the contribution that beats the 2-hop
trick honestly).

Unlike FLASH's self-supervised node-typing, this trains a BINARY malicious-vs-benign
head directly on GT labels, in a leave-one-host-out split (train on 2 attack
scenarios, test on the held-out third = honest unseen-scenario detection). The
THEIA analog (supervised LGBM) reached real PR-AUC 0.99 with no 2-hop trick; this
tests whether a supervised GraphSAGE does the same on OpTC at RAW node level.

Headline = RAW node-level PR-AUC / ROC-AUC on the held-out host (base rate is
tiny, so PR-AUC is the honest metric). Also reports RAW P/R/F1 at the
precision-recall break-even threshold + the 2-hop-adjusted numbers for comparison
with the FLASH floor.

  GNN_EPOCHS=100 RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/train_gnn_supervised.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, roc_auc_score
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
from torch_geometric.nn import SAGEConv
import optc_flash_common as fc
import optc_eval as ev

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
OUT = CODE_ROOT / "trained_weights" / "optc_ours"
OUT.mkdir(parents=True, exist_ok=True)
TAG = os.environ.get("FEAT_TAG", "ours")
EPOCHS = int(os.environ.get("GNN_EPOCHS", "100"))
HOSTS = ["0051", "0201", "0501"]
device = torch.device("cpu")
torch.manual_seed(42)
np.random.seed(42)


class SupSAGE(nn.Module):
    """Same encoder as fc.GCN (SAGEConv 20->32->20) + binary head."""
    def __init__(self):
        super().__init__()
        self.conv1 = SAGEConv(fc.VECTOR_SIZE, 32, normalize=True)
        self.conv2 = SAGEConv(32, fc.VECTOR_SIZE, normalize=True)
        self.head = nn.Linear(fc.VECTOR_SIZE, 2)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.conv2(x, edge_index)
        return self.head(x)


def load_host(host, gt_all):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    X = np.load(CODE_ROOT / f"_feat_{host}_{TAG}.npz")["X"]
    mapp = c["mapp"]
    ybin = np.array([1 if u in gt_all else 0 for u in mapp], dtype=np.int64)
    g = Data(x=torch.tensor(X), y=torch.tensor(ybin, dtype=torch.long),
             edge_index=torch.tensor(c["edges"], dtype=torch.long))
    g.n_id = torch.arange(g.num_nodes)
    return c, g, ybin


def train(graphs):
    model = SupSAGE().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    pos = sum(int(g.y.sum()) for g in graphs)
    neg = sum(g.num_nodes for g in graphs) - pos
    w = torch.tensor([1.0, neg / max(pos, 1)], dtype=torch.float).to(device)
    crit = nn.CrossEntropyLoss(weight=w)
    for ep in range(EPOCHS):
        model.train(); tot = 0.0
        for g in graphs:
            for b in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000, shuffle=True):
                opt.zero_grad()
                loss = crit(model(b.x, b.edge_index), b.y)
                loss.backward(); opt.step(); tot += loss.item()
        if ep % 20 == 0 or ep == EPOCHS - 1:
            print(f"    epoch {ep}: loss={tot:.3f}", flush=True)
    return model


@torch.no_grad()
def proba(model, g):
    model.eval()
    out = torch.zeros(g.num_nodes)
    for b in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        p = F.softmax(model(b.x, b.edge_index), dim=1)[:, 1]
        out[b.n_id] = p.cpu()
    return out.numpy()


def main():
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    cache = {h: load_host(h, gt_all) for h in HOSTS}
    log = [f"=== MODEL B (supervised GraphSAGE, leave-one-host-out, our w2v) epochs={EPOCHS} ==="]
    for test_h in HOSTS:
        train_hs = [h for h in HOSTS if h != test_h]
        graphs = [cache[h][1] for h in train_hs]
        print(f"\n[fold] test={test_h} train={train_hs}", flush=True)
        t0 = time.time()
        model = train(graphs)
        c, g, ybin = cache[test_h]
        scores = proba(model, g)
        prauc = average_precision_score(ybin, scores) if ybin.sum() else float("nan")
        rocauc = roc_auc_score(ybin, scores) if ybin.sum() else float("nan")
        base = ybin.mean()
        # threshold at top-K = number of GT positives (precision/recall break-even-ish)
        k = int(ybin.sum())
        thr_idx = np.argsort(scores)[::-1][:k]
        alert = {c["mapp"][i] for i in thr_idx}
        mapp_set = set(c["mapp"]); gt = set(c["gt"]) & mapp_set
        adj = ev.build_adjacency(c["edges"], c["mapp"])
        s = ev.score(alert, gt, mapp_set, adj)
        block = (f"\n[fold test={test_h}] nodes={g.num_nodes:,} GT={int(ybin.sum())} "
                 f"base_rate={base:.5f}  PR-AUC={prauc:.4f} ROC-AUC={rocauc:.4f} "
                 f"lift={prauc/base if base else 0:.1f}x ({time.time()-t0:.0f}s)\n"
                 f"  @top-{k} (=#GT): " + ev.fmt(test_h, g.num_nodes, len(gt), len(alert), s))
        log.append(block); print(block, flush=True)
        torch.save(model.state_dict(), OUT / f"gnn_supervised_test{test_h}.pth")
    (CODE_ROOT / "_train_gnn_supervised.log").write_text("\n".join(log), encoding="utf-8")
    print("\nDONE", flush=True)


if __name__ == "__main__":
    main()
