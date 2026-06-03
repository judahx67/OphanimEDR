"""Shared PCSA building blocks (Sprint 1 pilot + Sprint 2 scorer).

Frozen FLASH GraphSAGE node embeddings, k=2 capped causal subgraph assembly,
mean pooling, LOHO novelty seed-scorer, prototype open-set scoring. Pooling is
mean-only: the pilot showed anomaly-weighting adds nothing (0.954 vs 0.955).
"""
from __future__ import annotations
import os, pickle
from collections import deque
from pathlib import Path
import numpy as np
import torch
from lightgbm import LGBMClassifier
from sklearn.cluster import KMeans
from sklearn.metrics import roc_auc_score
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
TAG = os.environ.get("FEAT_TAG", "ours")
HOSTS = ["0051", "0201", "0501"]
HOPS = 2
NEI_CAP = int(os.environ.get("NEI_CAP", "40"))
MAX_NODES = int(os.environ.get("MAX_NODES", "150"))
N_PROTO = int(os.environ.get("N_PROTO", "8"))
TYPES = {v: k for k, v in fc.DUMMIES.items()}


def gt_set():
    return set(GT_TXT.read_text(encoding="utf-8").split())


def load_host(host, gt_all):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    X = np.load(CODE_ROOT / f"_feat_{host}_{TAG}.npz")["X"].astype(np.float32)
    mapp = c["mapp"]
    return {
        "X": X, "labels": np.array(c["labels"]), "edges": c["edges"], "mapp": mapp,
        "gt_mask": np.array([u in gt_all for u in mapp]), "n": len(mapp),
    }


def frozen_node_embeddings(X, edges):
    """GraphSAGE encode() with frozen self-sup weights (never saw attacks) -> [N,20]."""
    sd = torch.load(CODE_ROOT / "trained_weights" / f"optc_{TAG}" /
                    "gnn_selfsup_optc.pth", map_location="cpu")
    m = fc.GCN(); m.load_state_dict(sd); m.eval()
    with torch.no_grad():
        return m.encode(torch.tensor(X, dtype=torch.float),
                        torch.tensor(np.array(edges), dtype=torch.long)).cpu().numpy()


def novelty_scorer(train_hosts, gt_all, rng):
    """LGBM real-benign(0) vs uniform-background(1) on train_hosts benign.
    Returns a fn X->score (high = background-like = anomalous)."""
    Xb = np.vstack([load_host(h, gt_all)["X"][~load_host(h, gt_all)["gt_mask"]]
                    for h in train_hosts])
    lo, hi = Xb.min(0), Xb.max(0)
    Xbg = rng.uniform(lo, hi, size=Xb.shape).astype(np.float32)
    clf = LGBMClassifier(boosting_type="gbdt", extra_trees=True, n_estimators=300,
                         learning_rate=0.05, num_leaves=31, min_child_samples=20,
                         n_jobs=-1, verbose=-1)
    clf.fit(np.vstack([Xb, Xbg]), np.r_[np.zeros(len(Xb)), np.ones(len(Xb))])
    return lambda X: clf.predict_proba(X)[:, 1]


def build_adj(edges, n):
    adj = [[] for _ in range(n)]
    for s, t in zip(edges[0], edges[1]):
        adj[s].append(t); adj[t].append(s)   # undirected = back+forward
    return adj


def assemble(seed, adj):
    """k=2 BFS, neighbour-capped by node index (anomaly-agnostic), total-capped."""
    seen = {seed}; frontier = deque([(seed, 0)])
    while frontier:
        nid, d = frontier.popleft()
        if d >= HOPS:
            continue
        for nb in sorted(adj[nid])[:NEI_CAP]:
            if nb not in seen:
                seen.add(nb); frontier.append((nb, d + 1))
                if len(seen) >= MAX_NODES:
                    return seen
    return seen


def mean_pool(seeds, adj, Z):
    """Assemble each seed's subgraph, return (pooled embeddings [S,20], subs list)."""
    subs = [assemble(int(s), adj) for s in seeds]
    emb = np.array([Z[list(m)].mean(0) for m in subs])
    return emb, subs


def composition_vec(subs, labels):
    """Per-subgraph 4-d node-type fraction vector (the honest separability floor)."""
    return np.array([[(labels[list(s)] == t).mean() for t in sorted(TYPES)]
                     for s in subs])


def proto_score(proto_emb, query_emb, kmeans=True):
    """-min distance from each query to a prototype. k-means centroids (PCSA) or
    raw points (kNN baseline)."""
    if kmeans:
        k = min(N_PROTO, len(proto_emb))
        km = KMeans(n_clusters=k, n_init=10, random_state=0).fit(proto_emb)
        return -km.transform(query_emb).min(1)
    from scipy.spatial.distance import cdist
    return -cdist(query_emb, proto_emb).min(1)


def auroc(proto_emb, query_emb, query_y, kmeans=True):
    return roc_auc_score(query_y, proto_score(proto_emb, query_emb, kmeans))


def type_match_benign(seed_types, labels, gt_mask, rng):
    """Sample non-GT seeds matching the node-type histogram of the given seeds."""
    pools = {t: np.where((labels == t) & (~gt_mask))[0] for t in np.unique(seed_types)}
    return np.array([int(rng.choice(pools[t])) for t in seed_types])
