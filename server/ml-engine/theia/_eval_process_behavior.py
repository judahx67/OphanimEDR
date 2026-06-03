"""Can BEHAVIORAL process features (not content) detect the THEIA backdoor with
ZERO attack labels? The malicious process is an in-memory Firefox implant -- its
cmdline is benign/in-vocab, so content is blind. But it spawns a huge netflow
fan-out + memory injections, which is structurally anomalous even if it happens
once. This is the real "novel / once / intermittent" detection test.

All from the cache (_eval_cache.npz): per-process out-neighbor type histogram.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_eval_process_behavior.py
"""
from __future__ import annotations
import os
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
CACHE = DATA_ROOT / "_eval_cache.npz"
# DUMMIES type codes: 0=process 1=memory 2=file 3=netflow 4/5=principal
TYPE = {0: "proc", 1: "mem", 2: "file", 3: "net", 4: "prin", 5: "prin"}


def pr_at_recall(y, score, target_r):
    order = np.argsort(-score); ys = y[order]
    tp = np.cumsum(ys); fp = np.cumsum(~ys); P = y.sum()
    rec = tp / P; idx = np.searchsorted(rec, target_r)
    if idx >= len(rec): return 0.0
    return tp[idx] / (tp[idx] + fp[idx])


def main():
    z = np.load(CACHE, allow_pickle=True)
    struct, ymal, isproc, edges = z["struct"], z["ymal"], z["isproc"], z["edges"]
    N = len(ymal)
    type_code = struct[:, 4].astype(int)
    src, dst = edges[0].astype(np.int64), edges[1].astype(np.int64)

    # per-node out-neighbor type histogram + in/out degree
    out_by_type = np.zeros((N, 6), dtype=np.int64)
    np.add.at(out_by_type, (src, type_code[dst]), 1)
    in_by_type = np.zeros((N, 6), dtype=np.int64)
    np.add.at(in_by_type, (dst, type_code[src]), 1)
    outd = out_by_type.sum(1); ind = in_by_type.sum(1)

    pm = isproc
    pidx = np.where(pm)[0]
    ymp = ymal[pidx]
    print(f"process nodes={len(pidx):,}  malicious processes={int(ymp.sum())}")

    # behavioral feature matrix for processes (log1p to tame scale)
    feats = np.hstack([
        outd[pidx, None], ind[pidx, None],
        out_by_type[pidx][:, [0, 1, 2, 3]],   # proc/mem/file/net children
        in_by_type[pidx][:, [0, 2, 3]],        # proc/file/net parents
    ]).astype(np.float64)
    Xb = np.log1p(feats)

    # ---- descriptive: do malicious procs stand out by fan-out / memory ops? ----
    print("\nbehavioral profile (median / p99) benign-proc vs malicious-proc:")
    cols = ["out_deg", "in_deg", "net_children", "mem_children", "file_children"]
    colidx = [0, 1, 5, 3, 4]  # into feats: outd,ind,(net at out_by_type[3]=feats col5),mem col3,file col4
    for name, ci in zip(cols, colidx):
        b = feats[~ymp, ci]; m = feats[ymp, ci]
        print(f"  {name:<14} benign med={np.median(b):8.1f} p99={np.percentile(b,99):9.1f}  |  "
              f"MAL med={np.median(m):9.1f} max={m.max():9.0f}")

    # ---- top processes by netflow fan-out, flag GT ----
    net_child = out_by_type[pidx][:, 3]
    top = np.argsort(-net_child)[:12]
    print("\ntop-12 processes by netflow fan-out (MAL? = in GT):")
    for r in top:
        print(f"  net_children={net_child[r]:>6}  out_deg={outd[pidx][r]:>6}  "
              f"mem={out_by_type[pidx][r,1]:>5}  {'MAL' if ymp[r] else 'ben'}")

    # ---- UNSUPERVISED anomaly detection on behavioral features (zero labels) ----
    print("\nUNSUPERVISED (IsolationForest on behavioral features, NO attack labels):")
    for cont in (0.01, 0.05):
        iff = IsolationForest(n_estimators=300, contamination=cont, random_state=42, n_jobs=-1)
        s = -iff.fit(Xb).score_samples(Xb)
        apr = average_precision_score(ymp, s); roc = roc_auc_score(ymp, s)
        print(f"  contamination={cont}: PR-AUC={apr:.4f} ROC-AUC={roc:.4f} "
              f"prec@90%rec={pr_at_recall(ymp,s,0.90):.3f} prec@99%rec={pr_at_recall(ymp,s,0.99):.3f}")

    # single most-interpretable rule: rank by netflow fan-out alone
    apr = average_precision_score(ymp, net_child.astype(float))
    roc = roc_auc_score(ymp, net_child.astype(float))
    print(f"\n  netflow-fanout ALONE (1 feature, no model): PR-AUC={apr:.4f} ROC-AUC={roc:.4f} "
          f"prec@90%rec={pr_at_recall(ymp, net_child.astype(float), 0.90):.3f}")


if __name__ == "__main__":
    main()
