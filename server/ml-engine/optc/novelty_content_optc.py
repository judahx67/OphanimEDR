"""PHASE 3 — benign-trained NOVELTY detector on OpTC (does benign-only change the cross-host
picture, or inherit the host-specific-identifier problem?).

Phase 1 showed SUPERVISED content detection fails cross-scenario at process level. Novelty has
strictly LESS information (never sees attack), so the prior is it also fails — but we test it to
close the OpTC detection question and to mirror the THEIA novelty path (which got 6.9x node-level
lift via benign-real-vs-uniform-background; column-permutation PU failed at ROC 0.5).

Method (THEIA-proven): train LightGBM-XT to separate REAL benign content nodes (label 0) from
UNIFORM-random background points in the same feature box (label 1). At test, high background-
likeness = low density = anomalous. Benign = non-GT nodes (GT is <0.3% so this is ~all-benign).
LOHO: train on 2 hosts' benign, score held-out host, eval vs GT. RAW, node + process level.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/novelty_content_optc.py
"""
from __future__ import annotations
import os, pickle
from pathlib import Path
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
TAG = os.environ.get("FEAT_TAG", "ours")
# FEAT_MODE=loho: per-fold features tagged loho<test_host>, produced from a w2v
# trained on that fold's two TRAIN hosts only (audit O2 — removes the
# transductive vocabulary). Default "fixed" = single all-hosts w2v (FLASH-faithful).
FEAT_MODE = os.environ.get("FEAT_MODE", "fixed")
N_EST = int(os.environ.get("GNN_ESTIMATORS", "300"))
HOSTS = ["0051", "0201", "0501"]
PROCESS = 0
rng = np.random.default_rng(42)


def load_host(host, gt_all, tag=TAG):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    X = np.load(CODE_ROOT / f"_feat_{host}_{tag}.npz")["X"].astype(np.float32)
    ybin = np.array([1 if u in gt_all else 0 for u in c["mapp"]], dtype=np.int64)
    ntype = np.array(c["labels"], dtype=np.int64)
    return X, ybin, ntype


def background(X, k):
    """Uniform-random points in the per-dim [min,max] box of X."""
    lo, hi = X.min(0), X.max(0)
    return rng.uniform(lo, hi, size=(k, X.shape[1])).astype(np.float32)


def report(y, score, tag):
    base = y.mean()
    prauc = average_precision_score(y, score) if y.sum() else float("nan")
    roc = roc_auc_score(y, score) if 0 < y.sum() < len(y) else float("nan")
    order = np.argsort(score)[::-1]; rec = {}
    for fpb in (10, 50, 100):
        fpc = tpc = 0
        for i in order:
            if y[i] == 1: tpc += 1
            else:
                fpc += 1
                if fpc > fpb: break
        rec[fpb] = tpc / y.sum() if y.sum() else 0
    return (f"  {tag:<10} pos={int(y.sum()):>4}/{len(y):>6} base={base:.4f} "
            f"PR-AUC={prauc:.4f} ROC={roc:.4f} lift={prauc/base if base else 0:.1f}x "
            f"R@10fp={rec[10]:.3f} R@50fp={rec[50]:.3f} R@100fp={rec[100]:.3f}")


def main():
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    log = [f"=== PHASE 3 NOVELTY: benign-real vs uniform-background LightGBM-XT, LOHO, RAW, "
           f"n_estimators={N_EST} feat_mode={FEAT_MODE} ==="]
    if FEAT_MODE != "loho":
        data = {h: load_host(h, gt_all) for h in HOSTS}
    for test_h in HOSTS:
        tr = [h for h in HOSTS if h != test_h]
        if FEAT_MODE == "loho":
            # every host featurized with THIS fold's train-hosts-only w2v
            data = {h: load_host(h, gt_all, tag=f"loho{test_h}") for h in HOSTS}
        Xb = np.vstack([data[h][0][data[h][1] == 0] for h in tr])  # benign-only train
        Xbg = background(Xb, len(Xb))
        Xtr = np.vstack([Xb, Xbg]); ytr = np.r_[np.zeros(len(Xb)), np.ones(len(Xbg))]
        clf = LGBMClassifier(boosting_type="gbdt", extra_trees=True, n_estimators=N_EST,
                             learning_rate=0.05, num_leaves=31, min_child_samples=20,
                             n_jobs=-1, verbose=-1)
        clf.fit(Xtr, ytr)
        Xte, yte, ntype = data[test_h]
        s = clf.predict_proba(Xte)[:, 1]  # high = background-like = anomalous
        pmask = ntype == PROCESS
        log.append(f"\n[test={test_h} train-benign={tr}]")
        log.append(report(yte, s, "NODE"))
        log.append(report(yte[pmask], s[pmask], "PROCESS"))
        print("\n".join(log[-3:]), flush=True)
        # Optional, additive-only dump for thesis figures (gated by DUMP_SCORES).
        if os.environ.get("DUMP_SCORES") and test_h == "0501":
            fd = CODE_ROOT.parents[2] / "thesis-writing-main" / "src" / "figure-scripts" / "figure-data"
            fd.mkdir(parents=True, exist_ok=True)
            np.savez(fd / f"optc-novelty-{test_h}.npz", score=s, y=yte, isproc=pmask)
    suffix = "_loho_w2v" if FEAT_MODE == "loho" else ""
    (CODE_ROOT / f"_novelty_content_optc{suffix}.log").write_text("\n".join(log), encoding="utf-8")
    print(f"\nDONE -> _novelty_content_optc{suffix}.log", flush=True)


if __name__ == "__main__":
    main()
