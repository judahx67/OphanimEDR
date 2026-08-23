"""MODEL A — our own self-supervised GraphSAGE on OpTC (FLASH-style replica).

Trains fc.GCN to predict node TYPE (PROCESS/FLOW/FILE/MODULE) on the benign-rich
training host(s), then detects on each host via the explain-away rule (node
misclassified or low-confidence => alert). This is the apples-to-apples "we
trained our own weights" counterpart to the FLASH floor (reproduce_flash_gnn.py).

Train/eval split: FLASH trains its OpTC GNN on benign data and evaluates per
attack host. Here we train on the union of the three hosts' BENIGN-typed graph
(node-type is self-supervised, GT labels never used in training) with class
weights, then evaluate each host. Honest RAW + 2-hop via optc_eval.

  GNN_EPOCHS=100 RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/train_gnn_selfsup.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np
import torch
from sklearn.utils import class_weight
from torch.nn import CrossEntropyLoss
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
from torch_geometric import utils
import optc_flash_common as fc
import optc_eval as ev

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
OUT = CODE_ROOT / "trained_weights" / "optc_ours"
OUT.mkdir(parents=True, exist_ok=True)
TAG = os.environ.get("FEAT_TAG", "ours")
EPOCHS = int(os.environ.get("GNN_EPOCHS", "100"))
CONF = float(os.environ.get("CONF", "0.0"))
TRAIN_HOSTS = os.environ.get("TRAIN_HOSTS", "0201").split(",")  # one host as the GNN train graph
EVAL_HOSTS = ["0051", "0201", "0501"]
device = torch.device("cpu")
torch.manual_seed(42)


def load_host(host):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    f = np.load(CODE_ROOT / f"_feat_{host}_{TAG}.npz")
    return c, f["X"], f["y"]


def train(graphs):
    model = fc.GCN().to(device)
    opt = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
    ally = np.concatenate([g.y.numpy() for g in graphs])
    cw = class_weight.compute_class_weight("balanced", classes=np.unique(ally), y=ally)
    crit = CrossEntropyLoss(weight=torch.tensor(cw, dtype=torch.float).to(device))
    for ep in range(EPOCHS):
        model.train(); tot = 0.0
        for g in graphs:
            for batch in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000, shuffle=True):
                opt.zero_grad()
                out = model(batch.x, batch.edge_index)
                loss = crit(out, batch.y)
                loss.backward(); opt.step(); tot += loss.item()
        if ep % 10 == 0 or ep == EPOCHS - 1:
            print(f"  epoch {ep}: loss={tot:.3f}", flush=True)
    return model


def detect(model, c, X, gt_all, log):
    g = Data(x=torch.tensor(X), y=torch.tensor(c["labels"], dtype=torch.long),
             edge_index=torch.tensor(c["edges"], dtype=torch.long))
    g.n_id = torch.arange(g.num_nodes)
    pred = torch.zeros(g.num_nodes, dtype=torch.long)
    conf = torch.zeros(g.num_nodes)
    model.eval()
    for sub in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        with torch.no_grad():
            out = model(sub.x, sub.edge_index)
        s, ind = out.sort(dim=1, descending=True)
        pred[sub.n_id] = ind[:, 0].cpu()
        conf[sub.n_id] = ((s[:, 0] - s[:, 1]) / s[:, 0]).cpu()
    conf = (conf - conf.min()) / (conf.max() - conf.min() + 1e-9)
    type_acc = (pred.numpy() == c["labels"]).mean()
    ok = (pred == torch.tensor(c["labels"], dtype=torch.long)) & (conf > CONF)
    alert = {c["mapp"][i] for i in utils.mask_to_index(~ok).tolist()}
    mapp_set = set(c["mapp"]); gt = set(c["gt"]) & mapp_set
    adj = ev.build_adjacency(c["edges"], c["mapp"])
    s = ev.score(alert, gt, mapp_set, adj)
    log.append(ev.fmt("?", len(c["mapp"]), len(gt), len(alert), s,
                      extra=f"type-acc={type_acc:.4f}"))
    return log


def main():
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    graphs = []
    for h in TRAIN_HOSTS:
        c, X, y = load_host(h)
        graphs.append(Data(x=torch.tensor(X), y=torch.tensor(y, dtype=torch.long),
                           edge_index=torch.tensor(c["edges"], dtype=torch.long)))
    print(f"training self-sup GNN on hosts={TRAIN_HOSTS} epochs={EPOCHS}", flush=True)
    t0 = time.time()
    model = train(graphs)
    torch.save(model.state_dict(), OUT / "gnn_selfsup_optc.pth")
    print(f"trained ({time.time()-t0:.0f}s) -> {OUT/'gnn_selfsup_optc.pth'}", flush=True)
    log = [f"=== MODEL A (self-sup GraphSAGE, our w2v, train={TRAIN_HOSTS}, conf>{CONF}) ==="]
    for h in EVAL_HOSTS:
        c, X, y = load_host(h)
        log2 = detect(model, c, X, gt_all, [])
        log.append(f"\n[host {h}]\n" + "\n".join(log2))
        print(log[-1], flush=True)
    (CODE_ROOT / "_train_gnn_selfsup.log").write_text("\n".join(log), encoding="utf-8")
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
