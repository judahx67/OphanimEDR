"""PHASE 1 GO/NO-GO — supervised CONTENT-feature detector on OpTC, PROCESS-level.

The thesis go/no-go (locked 2026-06-02): can a supervised detector on w2v CONTENT
features detect malicious PROCESSES on OpTC, honestly (RAW, no 2-hop), cross-scenario
(leave-one-host-out)? The topology GraphSAGE (train_gnn_supervised.py) was the honest
NEGATIVE at node level. THEIA proved CONTENT+supervision is the real differentiator
(node-level PR-AUC 0.99). This tests whether that carries to OpTC at PROCESS granularity.

Model: LightGBM-XT (extra_trees) on the 20-dim positional-w2v content features already
cached in _feat_<host>_ours.npz. No structural/topology features (we test content signal
in isolation, per the THEIA finding that structure added nothing).

Eval (all RAW, no 2-hop):
  NODE-level    : PR-AUC, ROC-AUC, base rate, F1 @ train-chosen threshold (no oracle).
  PROCESS-level : restrict to PROCESS-type nodes (label==0); rank by score; PR-AUC,
                  ROC-AUC, recall@K(=#mal-proc), recall at a fixed false-process budget.

Pre-committed bar: process-level PR-AUC >> base rate AND recall a majority of the host's
malicious processes at a tolerable false-process rate. Miss => honest negative, fall back
to triage/explainability headline.

  GNN_ESTIMATORS=300 RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/train_content_supervised.py
"""
from __future__ import annotations
import os, pickle
from pathlib import Path
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score, roc_auc_score, f1_score

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
TAG = os.environ.get("FEAT_TAG", "ours")
N_EST = int(os.environ.get("GNN_ESTIMATORS", "300"))
HOSTS = ["0051", "0201", "0501"]
PROCESS = 0  # DUMMIES label for PROCESS-type nodes
np.random.seed(42)


def load_host(host, gt_all):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    X = np.load(CODE_ROOT / f"_feat_{host}_{TAG}.npz")["X"].astype(np.float32)
    mapp = c["mapp"]
    ybin = np.array([1 if u in gt_all else 0 for u in mapp], dtype=np.int64)
    ntype = np.array(c["labels"], dtype=np.int64)
    return X, ybin, ntype


def best_f1_threshold(y, score):
    """Pick threshold maximizing F1 on the TRAINING scores (no test leakage)."""
    if y.sum() == 0:
        return 0.5
    qs = np.quantile(score, np.linspace(0.5, 0.9995, 80))
    best_t, best_f = 0.5, -1.0
    for t in qs:
        f = f1_score(y, (score >= t).astype(int), zero_division=0)
        if f > best_f:
            best_f, best_t = f, t
    return best_t


def metrics(y, score, tag, thr=None):
    base = y.mean()
    prauc = average_precision_score(y, score) if y.sum() else float("nan")
    roc = roc_auc_score(y, score) if 0 < y.sum() < len(y) else float("nan")
    lift = prauc / base if base else float("nan")
    line = (f"  {tag:<8} n={len(y):>6} pos={int(y.sum()):>4} base={base:.5f} "
            f"PR-AUC={prauc:.4f} ROC={roc:.4f} lift={lift:.1f}x")
    if thr is not None:
        pred = (score >= thr).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
        f = 2 * p * r / (p + r) if p + r else 0
        line += f" | @thr={thr:.3f} P={p:.3f} R={r:.3f} F1={f:.3f} (TP{tp}/FP{fp}/FN{fn})"
    # recall at fixed K (=#pos) and at false-positive budgets
    if y.sum():
        order = np.argsort(score)[::-1]
        k = int(y.sum())
        rec_at_k = y[order[:k]].sum() / y.sum()
        line += f" | R@K={rec_at_k:.3f}"
        for fpb in (10, 50, 100):  # recall when we allow this many false positives
            # walk down ranked list until fpb false positives accrued
            fpc = 0; tpc = 0
            for i in order:
                if y[i] == 1: tpc += 1
                else:
                    fpc += 1
                    if fpc > fpb: break
            line += f" R@{fpb}fp={tpc / y.sum():.3f}"
    return line


def main():
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    data = {h: load_host(h, gt_all) for h in HOSTS}
    log = [f"=== PHASE 1 GO/NO-GO: supervised CONTENT LightGBM-XT, leave-one-host-out, "
           f"n_estimators={N_EST}, RAW (no 2-hop) ==="]
    for test_h in HOSTS:
        train_hs = [h for h in HOSTS if h != test_h]
        Xtr = np.vstack([data[h][0] for h in train_hs])
        ytr = np.concatenate([data[h][1] for h in train_hs])
        Xte, yte, ntype_te = data[test_h]
        spw = (ytr == 0).sum() / max((ytr == 1).sum(), 1)
        clf = LGBMClassifier(boosting_type="gbdt", extra_trees=True, n_estimators=N_EST,
                             learning_rate=0.05, num_leaves=31, min_child_samples=20,
                             scale_pos_weight=spw, n_jobs=-1, verbose=-1)
        clf.fit(Xtr, ytr)
        s_tr = clf.predict_proba(Xtr)[:, 1]
        s_te = clf.predict_proba(Xte)[:, 1]
        thr = best_f1_threshold(ytr, s_tr)

        log.append(f"\n[fold test={test_h} train={train_hs}] scale_pos_weight={spw:.1f}")
        # NODE-level (all nodes)
        log.append(metrics(yte, s_te, "NODE", thr))
        # PROCESS-level: restrict to PROCESS-type nodes only
        pmask = ntype_te == PROCESS
        yp, sp = yte[pmask], s_te[pmask]
        log.append(metrics(yp, sp, "PROCESS", thr))
        print("\n".join(log[-3:]), flush=True)

    (CODE_ROOT / "_train_content_supervised.log").write_text("\n".join(log), encoding="utf-8")
    print("\nDONE -> _train_content_supervised.log", flush=True)


if __name__ == "__main__":
    main()
