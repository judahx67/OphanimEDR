"""PCSA PILOT GATE (Sprint 1) — de-risk the model contribution BEFORE building it.

Question: do causally-assembled subgraphs around ATTACK seeds separate from
subgraphs around BENIGN seeds in the frozen FLASH embedding space? If they do
not separate even with oracle (GT) seeds, learned prototype alignment cannot
work and PCSA is killed here (pre-committed, no goalpost-moving).

Host: OpTC 0501 (best honest signal: novelty node PR-AUC 0.227, lift 168x).
Encoder: FROZEN FLASH GraphSAGE (self-sup, node-type only — never saw attacks)
         over our w2v node features. No GPU training.
Seeds:   attack = GT-malicious nodes; benign = node-type-MATCHED non-GT sample
         (matching kills the trivial "attack seeds are a different type" cue).
Assembly: k=2 back+forward (undirected) causal traversal, per-node neighbour cap
         + total node cap (FLOW hubs explode otherwise). Assembly is anomaly-
         agnostic (capped by node index) so the mean-pool path is independent of
         the anomaly detector.
Pooling: (a) mean, (b) anomaly-weighted (softmax of novelty score over members).
Metrics: silhouette of the two TRUE groups; open-set AUROC (k-means attack
         prototypes on a train-half, score held-out attack + benign by nearest-
         prototype distance), 3 split seeds -> mean+/-std.
Guards:  node-type composition + mean size per group (review 2b: separation must
         be behavioural, not netflow/size volume).
GATE:    silhouette>0.2 AND AUROC>0.7 -> GO. elif anomaly-pool >0.15/0.65 ->
         FINE-TUNE (contrastive). else NO-GO (S3 -> heuristic alignment).

  PYTHONPATH=server/ml-engine/optc python server/ml-engine/optc/pcsa_pilot.py
"""
from __future__ import annotations
import os, pickle, time
from collections import deque
from pathlib import Path
import numpy as np
import torch
from lightgbm import LGBMClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score, roc_auc_score
import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
TAG = os.environ.get("FEAT_TAG", "ours")
HOST = os.environ.get("PILOT_HOST", "0501")
TRAIN_HOSTS = [h for h in ("0051", "0201", "0501") if h != HOST]
HOPS = 2
NEI_CAP = int(os.environ.get("NEI_CAP", "40"))     # max neighbours expanded per node
MAX_NODES = int(os.environ.get("MAX_NODES", "150"))  # subgraph node cap
N_PROTO = int(os.environ.get("N_PROTO", "8"))      # k-means attack prototypes
SPLIT_SEEDS = [0, 1, 2]
rng = np.random.default_rng(42)
TYPES = {v: k for k, v in fc.DUMMIES.items()}


def frozen_node_embeddings(X, edges):
    """GraphSAGE encode(x, edge_index) with frozen self-sup weights -> [N,20]."""
    sd = torch.load(CODE_ROOT / "trained_weights" / f"optc_{TAG}" /
                    "gnn_selfsup_optc.pth", map_location="cpu")
    m = fc.GCN(); m.load_state_dict(sd); m.eval()
    x = torch.tensor(X, dtype=torch.float)
    ei = torch.tensor(np.array(edges), dtype=torch.long)
    with torch.no_grad():
        return m.encode(x, ei).cpu().numpy()


def novelty_scores(host_X):
    """Per-node anomaly: LGBM real-benign(0) vs uniform-background(1), trained LOHO
    on other hosts' benign, scoring this host. High = background-like = anomalous."""
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    Xb_parts = []
    for h in TRAIN_HOSTS:
        c = pickle.load(open(CODE_ROOT / f"_cache_{h}.pkl", "rb"))
        Xh = np.load(CODE_ROOT / f"_feat_{h}_{TAG}.npz")["X"].astype(np.float32)
        ben = np.array([u not in gt_all for u in c["mapp"]])
        Xb_parts.append(Xh[ben])
    Xb = np.vstack(Xb_parts)
    lo, hi = Xb.min(0), Xb.max(0)
    Xbg = rng.uniform(lo, hi, size=Xb.shape).astype(np.float32)
    clf = LGBMClassifier(boosting_type="gbdt", extra_trees=True, n_estimators=300,
                         learning_rate=0.05, num_leaves=31, min_child_samples=20,
                         n_jobs=-1, verbose=-1)
    clf.fit(np.vstack([Xb, Xbg]), np.r_[np.zeros(len(Xb)), np.ones(len(Xb))])
    return clf.predict_proba(host_X)[:, 1]


def build_adj(edges, n):
    adj = [[] for _ in range(n)]
    for s, t in zip(edges[0], edges[1]):
        adj[s].append(t); adj[t].append(s)   # undirected = back+forward
    return adj


def assemble(seed, adj):
    """k=2 BFS, neighbour-capped (by node index, anomaly-agnostic), total-capped."""
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


def pool(members, Z, anom):
    idx = list(members)
    zm = Z[idx].mean(0)
    w = anom[idx]; w = np.exp(w - w.max()); w /= w.sum()
    za = (Z[idx] * w[:, None]).sum(0)
    return zm, za


def type_match_benign(seed_types, labels, gt_mask, k_per_seed=1):
    """Sample non-GT seeds matching the node-type histogram of attack seeds."""
    pool_by_t = {t: np.where((labels == t) & (~gt_mask))[0] for t in np.unique(seed_types)}
    out = []
    for t in seed_types:
        cand = pool_by_t[t]
        out.append(int(rng.choice(cand)))
    return np.array(out)


def auroc_openset(emb, y, split_seed):
    """k-means attack prototypes on train-half attack; score test (held-out attack
    + all benign) by -min distance to a prototype. AUROC of attack-likeness."""
    r = np.random.default_rng(split_seed)
    atk = np.where(y == 1)[0]; ben = np.where(y == 0)[0]
    r.shuffle(atk)
    half = len(atk) // 2
    proto_idx, test_atk = atk[:half], atk[half:]
    k = min(N_PROTO, len(proto_idx))
    km = KMeans(n_clusters=k, n_init=10, random_state=split_seed).fit(emb[proto_idx])
    test = np.r_[test_atk, ben]
    ytest = np.r_[np.ones(len(test_atk)), np.zeros(len(ben))]
    d = km.transform(emb[test]).min(1)        # dist to nearest prototype
    return roc_auc_score(ytest, -d)


def main():
    t0 = time.time(); L = []

    def log(s): L.append(s); print(s, flush=True)

    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    c = pickle.load(open(CODE_ROOT / f"_cache_{HOST}.pkl", "rb"))
    X = np.load(CODE_ROOT / f"_feat_{HOST}_{TAG}.npz")["X"].astype(np.float32)
    labels = np.array(c["labels"]); mapp = c["mapp"]; n = len(mapp)
    gt_mask = np.array([u in gt_all for u in mapp])
    log(f"=== PCSA PILOT host={HOST} nodes={n:,} edges={len(c['edges'][0]):,} "
        f"GT={int(gt_mask.sum())} HOPS={HOPS} NEI_CAP={NEI_CAP} MAX_NODES={MAX_NODES} ===")

    log("[1/4] frozen GraphSAGE node embeddings ..."); Z = frozen_node_embeddings(X, c["edges"])
    log("[2/4] LOHO novelty per-node anomaly ..."); anom = novelty_scores(X)
    adj = build_adj(c["edges"], n)

    atk_seeds = np.where(gt_mask)[0]
    ben_seeds = type_match_benign(labels[atk_seeds], labels, gt_mask)
    log(f"[3/4] assembling {len(atk_seeds)} attack + {len(ben_seeds)} type-matched benign subgraphs ...")
    seeds = np.r_[atk_seeds, ben_seeds]
    y = np.r_[np.ones(len(atk_seeds)), np.zeros(len(ben_seeds))].astype(int)
    subs = [assemble(int(s), adj) for s in seeds]
    Em = np.array([pool(m, Z, anom)[0] for m in subs])   # mean pool
    Ea = np.array([pool(m, Z, anom)[1] for m in subs])   # anomaly-weighted pool

    # guard: node-type composition + size, attack vs benign
    log("\n--- node-type-ratio guard (mean fraction per subgraph; behaviour not volume) ---")
    for grp, name in ((y == 1, "ATTACK"), (y == 0, "BENIGN")):
        comp = {}
        for sub in (np.array(subs, dtype=object)[grp]):
            idx = list(sub); tot = len(idx)
            for t in TYPES:
                comp.setdefault(TYPES[t], []).append((labels[idx] == t).mean())
        sizes = [len(s) for s in np.array(subs, dtype=object)[grp]]
        frac = " ".join(f"{k}={np.mean(v):.2f}" for k, v in comp.items())
        log(f"  {name}: size={np.mean(sizes):.0f}+/-{np.std(sizes):.0f}  {frac}")

    # composition baseline: per-subgraph 4-d node-type fraction vector. If this
    # matches the embedding AUROC, the embedding adds nothing beyond composition.
    Ec = np.array([[ (labels[list(sub)] == t).mean() for t in sorted(TYPES) ]
                   for sub in subs])

    log("\n--- separability (StandardScaled, euclidean) ---")
    verdict_inputs = {}
    for emb, name in ((Em, "mean-pool"), (Ea, "anomaly-pool"), (Ec, "type-hist-BASELINE")):
        Es = StandardScaler().fit_transform(emb)
        sil = silhouette_score(Es, y)
        aucs = [auroc_openset(Es, y, s) for s in SPLIT_SEEDS]
        verdict_inputs[name] = (sil, float(np.mean(aucs)))
        log(f"  {name:<13} silhouette={sil:+.3f}  open-set AUROC={np.mean(aucs):.3f}+/-{np.std(aucs):.3f}")

    # GATE
    sil_m, auc_m = verdict_inputs["mean-pool"]
    sil_a, auc_a = verdict_inputs["anomaly-pool"]
    best_sil = max(sil_m, sil_a); best_auc = max(auc_m, auc_a)
    if best_sil > 0.2 and best_auc > 0.7:
        verdict = "GO — build full PCSA"
    elif sil_a > 0.15 and auc_a > 0.65:
        verdict = "FINE-TUNE — contrastive encoder fine-tune then re-gate"
    else:
        verdict = "NO-GO — S3 downgrades to heuristic (ActMiner-style) alignment"
    log(f"\n=== GATE (silh>0.2 AND AUROC>0.7) -> {verdict} ===")
    log(f"    best silhouette={best_sil:+.3f}  best AUROC={best_auc:.3f}  ({time.time()-t0:.0f}s)")

    (CODE_ROOT / f"_pcsa_pilot_{HOST}.log").write_text("\n".join(L), encoding="utf-8")
    print(f"\nDONE -> _pcsa_pilot_{HOST}.log")


if __name__ == "__main__":
    main()
