"""Our-own Orthrus-style detector for THEIA E3 — same substrate as FLASH.

Faithful to the Orthrus approach (Jiang et al., USENIX Sec'25) but our own code:
  - GAT encoder produces node embeddings from the SAME Word2Vec node features
    FLASH uses (theia_flash_common.infer / word2vec_theia_E3.model).
  - Edge-reconstruction decoder predicts each edge's action type from the
    embeddings of its two endpoints; per-node anomaly = mean reconstruction loss.
  - Detection threshold = max per-node loss over a benign validation graph
    (`max_val_loss`): a node fires only if it is harder to reconstruct than
    EVERY benign node => precise, near-zero FP. This is the precision mechanism
    that FLASH (fixed explain-away threshold) lacks.

Deliberately reuses FLASH's prepare_graph + w2v features so the ONLY difference
vs FLASH is the model + objective + threshold — isolating *why* FLASH floods the
abundant node type while Orthrus does not. Not a port of the upstream repo.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from torch_geometric.nn import GATConv

import theia_flash_common as fc

EMB_DIM = 32
HID_DIM = 64
HEADS = 2

# Edge-txt columns written by theia_flash_common.write_edges:
#   subjectID, subject_type, objectID, object_type, action(etype), timestamp
EDGE_COLS = ["actorID", "actor_type", "objectID", "object", "action", "timestamp"]


# ---- model ----------------------------------------------------------------

class OrthrusEncoder(torch.nn.Module):
    """2-layer graph-attention encoder -> node embeddings."""

    def __init__(self, in_dim: int, hid: int = HID_DIM, out: int = EMB_DIM, heads: int = HEADS):
        super().__init__()
        self.g1 = GATConv(in_dim, hid, heads=heads, concat=True)
        self.g2 = GATConv(hid * heads, out, heads=1, concat=True)

    def forward(self, x, edge_index):
        x = F.elu(self.g1(x, edge_index))
        x = F.dropout(x, p=0.3, training=self.training)
        return self.g2(x, edge_index)


class EdgeActionDecoder(torch.nn.Module):
    """Reconstruct an edge's action type from its endpoint embeddings."""

    def __init__(self, emb: int, n_actions: int, hid: int = HID_DIM):
        super().__init__()
        self.mlp = torch.nn.Sequential(
            torch.nn.Linear(emb * 2, hid),
            torch.nn.ReLU(),
            torch.nn.Linear(hid, n_actions),
        )

    def forward(self, h, edge_index):
        return self.mlp(torch.cat([h[edge_index[0]], h[edge_index[1]]], dim=1))


# ---- graph construction (reuses FLASH features) ---------------------------

def build_graph(df: pd.DataFrame, w2v, enc, action2id: dict, device):
    """df (EDGE_COLS, exec/path optional) -> (x, edge_index, edge_actions, labels, mapp).

    Node features are the SAME mean-w2v vectors FLASH uses. `edge_actions` are
    the decoder targets (action-type id per edge), aligned to edge_index columns.
    Unknown actions map to id 0 (a reserved <unk>/dominant class) so scoring never
    crashes on an action unseen at train time.
    """
    df = df.copy()
    if "exec" not in df.columns:
        df["exec"] = ""
    if "path" not in df.columns:
        df["path"] = ""
    df = df.astype(str)

    feats, flabels, eidx, mapp = fc.prepare_graph(df)
    x = np.empty((len(feats), fc.VECTOR_SIZE), dtype=np.float32)
    for i, doc in enumerate(feats):
        x[i] = fc.infer(doc, w2v, enc).astype(np.float32)

    edge_actions = [action2id.get(a, 0) for a in df["action"].tolist()]

    return (
        torch.tensor(x, dtype=torch.float).to(device),
        torch.tensor(eidx, dtype=torch.long).to(device),
        torch.tensor(edge_actions, dtype=torch.long).to(device),
        torch.tensor(flabels, dtype=torch.long).to(device),
        mapp,
    )


# ---- anomaly scoring ------------------------------------------------------

def per_node_loss(h, edge_index, edge_actions, decoder) -> torch.Tensor:
    """Mean edge-reconstruction loss aggregated onto each node (src and dst)."""
    logits = decoder(h, edge_index)
    per_edge = F.cross_entropy(logits, edge_actions, reduction="none")
    n = h.size(0)
    loss_sum = torch.zeros(n, device=h.device)
    cnt = torch.zeros(n, device=h.device)
    ones = torch.ones_like(per_edge)
    for end in (edge_index[0], edge_index[1]):
        loss_sum.index_add_(0, end, per_edge)
        cnt.index_add_(0, end, ones)
    return loss_sum / cnt.clamp(min=1)


def read_edge_txt(path: str, limit: int) -> pd.DataFrame:
    """Stream the first `limit` edges of a FLASH theia_*.txt into a df."""
    rows = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            rows.append(parts[:6])
            if len(rows) >= limit:
                break
    return pd.DataFrame(rows, columns=EDGE_COLS)
