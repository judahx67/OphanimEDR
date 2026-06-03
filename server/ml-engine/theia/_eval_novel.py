"""Real-performance THEIA evaluation: novel-attack and rare/intermittent detection.

Uses the cached features (_eval_cache.npz) so it is instant. Two honest regimes:

  PART 1 -- UNSUPERVISED / benign-only (NO attack labels touch training):
    the genuine "novel attack" test. Scores every node by anomaly vs the benign
    baseline and compares to GT at node AND process level.
      - emb-norm     : ||w2v embedding||  (all-OOV attack tooling -> ~0 -> anomalous)
      - IF_unsup     : IsolationForest fit on ALL nodes (contaminated, pure unsup)
      - IF_benign    : IsolationForest fit on known-benign only (one-class, no attack labels)

  PART 2 -- FEW-SHOT SUPERVISED (rare / on-and-off attacks):
    temporal split, but train positives capped to k in {1,5,25,100,1000,all}.
    Shows how few attack examples the supervised model needs. node-level PR-AUC.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_eval_novel.py
"""
from __future__ import annotations
import os
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from lightgbm import LGBMClassifier

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
CACHE = DATA_ROOT / "_eval_cache.npz"
SEED = 42


def pr_at_recall(y, score, target_r=0.90):
    """precision when threshold set to reach target recall (analyst-style)."""
    order = np.argsort(-score)
    ys = y[order]
    tp = np.cumsum(ys); fp = np.cumsum(~ys)
    P = y.sum()
    rec = tp / P
    idx = np.searchsorted(rec, target_r)
    if idx >= len(rec):
        return 0.0, 0.0
    prec = tp[idx] / (tp[idx] + fp[idx])
    return prec, tp[idx] / P


def line(tag, y, score):
    apr = average_precision_score(y, score)
    roc = roc_auc_score(y, score)
    p90, _ = pr_at_recall(y, score, 0.90)
    p99, _ = pr_at_recall(y, score, 0.99)
    print(f"  {tag:<26} PR-AUC={apr:.4f} ROC-AUC={roc:.4f} "
          f"prec@90%rec={p90:.3f} prec@99%rec={p99:.3f}")


def main():
    z = np.load(CACHE, allow_pickle=True)
    X, struct, ymal, ts, isproc = z["Xw2v"], z["struct"], z["ymal"], z["ts"], z["isproc"]
    N = len(ymal); P = int(ymal.sum())
    print(f"nodes={N:,}  malicious={P:,} ({P/N*100:.1f}%)  processes={int(isproc.sum()):,} "
          f"malicious-proc={int((ymal&isproc).sum())}")

    # ---------- PART 1: UNSUPERVISED / benign-only (novel attack) ----------
    print("\n=== PART 1: UNSUPERVISED / benign-only  (zero attack labels in training) ===")
    norm = np.linalg.norm(X, axis=1)
    s_norm = -norm  # low norm (all-OOV) = anomalous
    print(f"  all-OOV (||emb||==0) nodes: {(norm == 0).sum():,}  "
          f"of which malicious: {int(ymal[norm == 0].sum()):,}")
    print(" NODE-level:")
    line("emb-norm (no training)", ymal, s_norm)
    rng = np.random.default_rng(SEED)
    ifu = IsolationForest(n_estimators=200, contamination=0.07, random_state=SEED, n_jobs=-1)
    s_ifu = -ifu.fit(X).score_samples(X)
    line("IsolationForest unsup", ymal, s_ifu)
    benign_idx = np.where(~ymal)[0]
    fit_b = rng.choice(benign_idx, size=min(50000, len(benign_idx)), replace=False)
    ifb = IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1)
    ifb.fit(X[fit_b])
    s_ifb = -ifb.score_samples(X)
    line("IsolationForest benign-only", ymal, s_ifb)

    print(" PROCESS-level (universe = process nodes; all 23 mal-proc available):")
    pm = isproc
    for tag, s in (("emb-norm", s_norm), ("IF_unsup", s_ifu), ("IF_benign", s_ifb)):
        line(tag, ymal[pm], s[pm])

    # ---------- PART 2: FEW-SHOT SUPERVISED (rare / intermittent) ----------
    print("\n=== PART 2: FEW-SHOT SUPERVISED  (temporal split; cap train positives) ===")
    cut = np.median(ts[ymal])
    tr, te = ts < cut, ts >= cut
    Xtr_all, ytr_all = X[tr], ymal[tr]
    Xte, yte = X[te], ymal[te]
    pos_tr = np.where(ytr_all)[0]
    neg_tr = np.where(~ytr_all)[0]
    print(f"  test pos={int(yte.sum()):,}  (node-level PR-AUC; netflow-dominated)")
    for k in (1, 5, 25, 100, 1000, len(pos_tr)):
        aprs = []
        seeds = range(5) if k <= 100 else range(1)
        for sd in seeds:
            r = np.random.default_rng(sd)
            sel = r.choice(pos_tr, size=min(k, len(pos_tr)), replace=False)
            idx = np.concatenate([sel, neg_tr])
            clf = LGBMClassifier(extra_trees=True, n_estimators=200, learning_rate=0.05,
                                 num_leaves=31, class_weight="balanced", random_state=sd,
                                 n_jobs=-1, verbose=-1)
            clf.fit(Xtr_all[idx], ytr_all[idx])
            aprs.append(average_precision_score(yte, clf.predict_proba(Xte)[:, 1]))
        lbl = f"k={k}" if k < len(pos_tr) else f"k=all({len(pos_tr)})"
        print(f"  {lbl:<14} test PR-AUC={np.mean(aprs):.4f}" +
              (f" +/-{np.std(aprs):.4f} (5 seeds)" if len(aprs) > 1 else ""))


if __name__ == "__main__":
    main()
