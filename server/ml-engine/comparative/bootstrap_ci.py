"""Bootstrap 95% CI for process-level PR-AUC / ROC-AUC (thesis R4.2).

The process-level positives are tiny (OpTC 0051/0201/0501 = 8/58/33; THEIA = 23),
so a single PR-AUC/AUROC point estimate is an unstable summary. This resamples the
process-level nodes with replacement (B times) and reports the 2.5/97.5 percentile
interval around each metric — no retraining, reads the saved score dumps.

Inputs: the `_score_content_supervised_<host>.npz` dumps with arrays
  y (0/1 label), score (anomaly score), isproc (process-node mask).

Usage:
    python bootstrap_ci.py server/ml-engine/optc/_score_content_supervised_0051.npz
    python bootstrap_ci.py server/ml-engine/optc/*.npz --B 1000 --seed 0
"""
import argparse
import glob
import os

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

PCT_LO, PCT_HI = 2.5, 97.5


def _metrics(y, s):
    """ROC-AUC and PR-AUC; NaN if a resample lost one of the classes."""
    if y.min() == y.max():
        return np.nan, np.nan
    return roc_auc_score(y, s), average_precision_score(y, s)


def bootstrap_ci(y, s, B=1000, seed=0):
    """Point estimate + percentile CI over B resamples-with-replacement."""
    rng = np.random.default_rng(seed)
    n = len(y)
    roc0, pr0 = _metrics(y, s)
    rocs, prs = [], []
    for _ in range(B):
        idx = rng.integers(0, n, n)
        roc, pr = _metrics(y[idx], s[idx])
        if not np.isnan(roc):
            rocs.append(roc)
            prs.append(pr)
    def ci(point, draws):
        draws = np.asarray(draws)
        return point, np.percentile(draws, PCT_LO), np.percentile(draws, PCT_HI)
    return ci(roc0, rocs), ci(pr0, prs), len(rocs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("npz", nargs="+", help="score dump(s); globs ok")
    ap.add_argument("--B", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    files = []
    for p in args.npz:
        files.extend(sorted(glob.glob(p)))

    print(f"# Bootstrap 95% CI (B={args.B}), process-level (isproc=True)\n")
    print("| host | n_proc | n_pos | ROC-AUC [95% CI] | PR-AUC [95% CI] |")
    print("|---|---|---|---|---|")
    for f in files:
        d = np.load(f, allow_pickle=True)
        y, s, isproc = d["y"], d["score"], d["isproc"]
        m = isproc.astype(bool)
        yp = (y[m] != 0).astype(int)
        sp = s[m].astype(float)
        n_pos = int(yp.sum())
        host = os.path.basename(f).replace("_score_content_supervised_", "").replace(".npz", "")
        if n_pos == 0 or n_pos == len(yp):
            print(f"| {host} | {len(yp)} | {n_pos} | n/a (single class) | n/a |")
            continue
        (roc, rlo, rhi), (pr, plo, phi), kept = bootstrap_ci(yp, sp, args.B, args.seed)
        print(f"| {host} | {len(yp)} | {n_pos} "
              f"| {roc:.3f} [{rlo:.3f}, {rhi:.3f}] "
              f"| {pr:.3f} [{plo:.3f}, {phi:.3f}] |")


if __name__ == "__main__":
    main()
