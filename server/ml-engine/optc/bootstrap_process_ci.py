"""Bootstrap 95% CI for process-level PR-AUC and ROC-AUC score dumps.

Expected input npz keys:
  y       : binary ground truth for all nodes
  score   : anomaly or malicious score, higher means more suspicious
  isproc  : boolean mask selecting process nodes

Example:
  python server/ml-engine/optc/bootstrap_process_ci.py \
      server/ml-engine/optc/_score_content_supervised_*.npz
"""
from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def metric_pair(y: np.ndarray, score: np.ndarray) -> tuple[float, float]:
    prauc = average_precision_score(y, score)
    roc = roc_auc_score(y, score)
    return float(prauc), float(roc)


def stratified_bootstrap(
    y: np.ndarray,
    score: np.ndarray,
    *,
    n_boot: int,
    seed: int,
) -> tuple[tuple[float, float], tuple[float, float]]:
    pos = np.flatnonzero(y == 1)
    neg = np.flatnonzero(y == 0)
    if len(pos) == 0 or len(neg) == 0:
        raise ValueError("Need at least one positive and one negative sample")

    rng = np.random.default_rng(seed)
    prauc = np.empty(n_boot, dtype=np.float64)
    roc = np.empty(n_boot, dtype=np.float64)
    for i in range(n_boot):
        sample = np.concatenate(
            [
                rng.choice(pos, size=len(pos), replace=True),
                rng.choice(neg, size=len(neg), replace=True),
            ]
        )
        prauc[i], roc[i] = metric_pair(y[sample], score[sample])

    pr_ci = tuple(np.percentile(prauc, [2.5, 97.5]))
    roc_ci = tuple(np.percentile(roc, [2.5, 97.5]))
    return pr_ci, roc_ci


def load_process_scores(path: Path) -> tuple[np.ndarray, np.ndarray]:
    data = np.load(path)
    y = data["y"].astype(np.int8)
    score = data["score"].astype(np.float64)
    isproc = data["isproc"].astype(bool)
    return y[isproc], score[isproc]


def fmt(value: float) -> str:
    return f"{value:.4f}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("npz", nargs="+", type=Path)
    parser.add_argument("--n-boot", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print("| file | n | pos | base | PR-AUC | 95% CI | ROC-AUC | 95% CI |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")
    for path in args.npz:
        y, score = load_process_scores(path)
        prauc, roc = metric_pair(y, score)
        pr_ci, roc_ci = stratified_bootstrap(
            y, score, n_boot=args.n_boot, seed=args.seed
        )
        print(
            f"| {path.name} | {len(y)} | {int(y.sum())} | {fmt(float(y.mean()))} | "
            f"{fmt(prauc)} | [{fmt(pr_ci[0])}, {fmt(pr_ci[1])}] | "
            f"{fmt(roc)} | [{fmt(roc_ci[0])}, {fmt(roc_ci[1])}] |"
        )


if __name__ == "__main__":
    main()
