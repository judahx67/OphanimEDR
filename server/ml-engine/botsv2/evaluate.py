"""Phase 7: evaluate trained models on test set with visualizations.

Loads each saved model (booster + categories + threshold) and produces:
  - ROC + PR curves
  - Confusion matrix at the chosen threshold
  - Permutation feature importance (the single best leakage detector)
  - Per-scenario recall bar
  - Per-sourcetype recall bar
  - Probability calibration curve + score histogram
  - Test prediction CSV (for manual spot-check)

Output: models/<model_name>/eval/

Permutation importance is the headline diagnostic. If a single feature
explodes its importance ranking, the model is overweighting that feature.
That's the signal we'd see if (e.g.) http_uri were leaking IOC strings.

Usage:
    python evaluate.py --model temporal
    python evaluate.py --model stratified
    python evaluate.py --all
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import lightgbm as lgb
import matplotlib

matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import polars as pl
from sklearn.calibration import calibration_curve
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    auc, confusion_matrix, precision_recall_curve, precision_recall_fscore_support,
    roc_auc_score, roc_curve,
)

import schema as S

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


# ──────────────────────────────────────────────────────────────────────────
# Model loading
# ──────────────────────────────────────────────────────────────────────────

class LoadedModel:
    """Wrap a saved booster + categories so we can predict_proba on new data."""

    def __init__(self, model_dir: Path):
        self.dir = model_dir
        self.booster = lgb.Booster(model_file=str(model_dir / "booster.txt"))
        with open(model_dir / "feature_names.json") as f:
            self.feature_names: list[str] = json.load(f)
        with open(model_dir / "categories.json") as f:
            self.categories: dict[str, list] = json.load(f)
        with open(model_dir / "threshold.json") as f:
            self.threshold = json.load(f)["threshold"]
        with open(model_dir / "run_meta.json") as f:
            self.meta = json.load(f)

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        """Re-align categories from saved dictionary, run prediction."""
        X = df[self.feature_names].copy()
        for c, cats in self.categories.items():
            if c in X.columns:
                X[c] = pd.Categorical(X[c], categories=cats)
        # Numeric coercion for non-categorical columns
        cat_cols = set(self.categories.keys())
        for c in X.columns:
            if c not in cat_cols:
                X[c] = pd.to_numeric(X[c], errors="coerce")
        return self.booster.predict(X)


# ──────────────────────────────────────────────────────────────────────────
# Test data loader (recreates the train.py preprocessing pipeline)
# ──────────────────────────────────────────────────────────────────────────

def load_test(split: str) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """Load test set and return (X_test_meta, y_test, full_test_df).

    full_test_df keeps the leaky cols for grouping (scenario, sourcetype).
    """
    test_pl = pl.read_parquet(DATA_DIR / split / "test.parquet")
    test_df = test_pl.to_pandas()
    y = test_df["label"].astype(np.int8)
    return test_df, y, test_df


# ──────────────────────────────────────────────────────────────────────────
# Plotting
# ──────────────────────────────────────────────────────────────────────────

def plot_roc(y, p_pos, out: Path) -> dict:
    fpr, tpr, _ = roc_curve(y, p_pos)
    auc_v = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(fpr, tpr, label=f"ROC (AUC={auc_v:.4f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return {"roc_auc": float(auc_v)}


def plot_pr(y, p_pos, out: Path) -> dict:
    prec, rec, _ = precision_recall_curve(y, p_pos)
    pr_auc = auc(rec, prec)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(rec, prec, label=f"PR (AUC={pr_auc:.4f})")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall curve")
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return {"pr_auc": float(pr_auc)}


def plot_confusion(y, yhat, out: Path) -> dict:
    cm = confusion_matrix(y, yhat)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i,j]:,}", ha="center", va="center",
                    color="black" if cm[i,j] < cm.max() * 0.6 else "white")
    ax.set_xticks([0, 1], ["pred 0", "pred 1"])
    ax.set_yticks([0, 1], ["actual 0", "actual 1"])
    ax.set_title("Confusion matrix")
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return {"confusion_matrix": cm.tolist()}


def plot_score_hist(y, p_pos, threshold: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(p_pos[y == 0], bins=80, alpha=0.5, label="benign (label=0)", color="steelblue")
    ax.hist(p_pos[y == 1], bins=80, alpha=0.5, label="malicious (label=1)", color="firebrick")
    ax.axvline(threshold, ls="--", color="black", label=f"threshold={threshold:.3f}")
    ax.set_xlabel("Predicted probability of malicious")
    ax.set_ylabel("Count")
    ax.set_title("Score distribution by class")
    ax.set_yscale("log")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def plot_calibration(y, p_pos, out: Path) -> None:
    frac_pos, mean_pred = calibration_curve(y, p_pos, n_bins=20, strategy="quantile")
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(mean_pred, frac_pos, "o-", label="model")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, label="perfectly calibrated")
    ax.set_xlabel("Mean predicted probability (per bin)")
    ax.set_ylabel("Empirical fraction of positives")
    ax.set_title("Calibration curve")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def plot_per_group_recall(y, yhat, group: pd.Series, label: str, out: Path,
                          top_n: int = 12) -> dict:
    """Bar plot of recall per group (e.g., per scenario or per sourcetype)."""
    rows = []
    mal_mask = (y == 1)
    for g in group[mal_mask].dropna().unique():
        mask = (group == g) & mal_mask
        n = int(mask.sum())
        if n == 0:
            continue
        recalled = int((yhat[mask.values] == 1).sum())
        rows.append((str(g), n, recalled / n))
    rows.sort(key=lambda r: -r[1])
    rows = rows[:top_n]
    if not rows:
        return {}
    names, ns, recalls = zip(*rows)
    fig, ax = plt.subplots(figsize=(8, max(3, 0.35 * len(rows) + 1.5)))
    bars = ax.barh(range(len(rows)), recalls, color="steelblue")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{n} (n={c:,})" for n, c in zip(names, ns)])
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Recall on malicious rows")
    ax.set_title(f"Per-{label} recall")
    for i, r in enumerate(recalls):
        ax.text(r + 0.01, i, f"{r:.3f}", va="center", fontsize=9)
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)
    return {n: {"n_malicious": c, "recall": r} for (n, c, r) in rows}


def plot_perm_importance(model: LoadedModel, X_test: pd.DataFrame, y_test: pd.Series,
                         out: Path, n_repeats: int = 3, sample_n: int = 50_000) -> dict:
    """Permutation importance with a sample (full test is slow).

    sklearn's permutation_importance shuffles each column in turn and measures
    the AUC drop. Big drop = model relies heavily on this feature. The single
    best leakage detector: if one feature is dominantly important, that's a
    red flag the model is shortcutting through it.
    """
    print(f"  permutation importance (sample {sample_n}, n_repeats={n_repeats})...")
    rng = np.random.default_rng(42)
    if len(X_test) > sample_n:
        idx = rng.choice(len(X_test), size=sample_n, replace=False)
        Xs = X_test.iloc[idx].copy()
        ys = y_test.iloc[idx].copy() if hasattr(y_test, "iloc") else y_test[idx]
    else:
        Xs = X_test
        ys = y_test

    # Wrap booster in a minimal sklearn-compatible classifier. The
    # `_estimator_type = "classifier"` + `__sklearn_tags__` lets sklearn's
    # is_classifier() check pass so permutation_importance can call
    # predict_proba via the roc_auc scorer.
    from sklearn.base import BaseEstimator, ClassifierMixin

    class _Est(ClassifierMixin, BaseEstimator):
        _estimator_type = "classifier"
        classes_ = np.array([0, 1])
        def fit(self, X, y): return self
        def predict_proba(self, X):
            p = model.predict_proba(X)
            return np.vstack([1 - p, p]).T
        def predict(self, X):
            return (self.predict_proba(X)[:, 1] >= model.threshold).astype(int)
        def __sklearn_is_fitted__(self):
            return True

    est = _Est()
    t0 = time.time()
    result = permutation_importance(
        est, Xs, ys.values if hasattr(ys, "values") else ys,
        scoring="roc_auc", n_repeats=n_repeats, random_state=42, n_jobs=1,
    )
    dt = time.time() - t0
    print(f"    elapsed {dt:.1f}s")

    means = result.importances_mean
    stds = result.importances_std
    feature_names = model.feature_names
    order = np.argsort(means)[::-1]

    # Plot top 20
    fig, ax = plt.subplots(figsize=(9, 7))
    show = order[:20]
    ax.barh(range(len(show)), means[show], xerr=stds[show], color="steelblue")
    ax.set_yticks(range(len(show)))
    ax.set_yticklabels([feature_names[i] for i in show])
    ax.set_xlabel("Mean ROC-AUC drop when feature is shuffled")
    ax.set_title("Permutation feature importance (top 20)\n— a single dominant feature suggests shortcut learning")
    ax.invert_yaxis()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)

    return {
        feature_names[i]: {"mean": float(means[i]), "std": float(stds[i])}
        for i in order
    }


# ──────────────────────────────────────────────────────────────────────────
# Main eval per model
# ──────────────────────────────────────────────────────────────────────────

def evaluate_model(model_name: str) -> dict:
    print(f"\n=== Evaluating model: {model_name} ===")
    model_dir = MODELS_DIR / model_name
    if not model_dir.exists():
        print(f"FATAL: {model_dir} missing")
        return {}
    eval_dir = model_dir / "eval"
    eval_dir.mkdir(exist_ok=True)

    print(f"Loading model from {model_dir}...")
    model = LoadedModel(model_dir)
    split = model.meta["split"]
    print(f"  threshold: {model.threshold:.3f}")
    print(f"  split: {split}")

    print(f"Loading test set for split={split}...")
    test_df, y, full = load_test(split)
    print(f"  test rows: {len(test_df):,}    positive rate: {(y == 1).mean():.4f}")

    print("Predicting...")
    p = model.predict_proba(test_df)
    yhat = (p >= model.threshold).astype(np.int8)

    # Plots
    out = {}
    print("ROC...")
    out.update(plot_roc(y.values, p, eval_dir / "roc.png"))
    print("PR...")
    out.update(plot_pr(y.values, p, eval_dir / "pr.png"))
    print("Confusion...")
    out.update(plot_confusion(y.values, yhat, eval_dir / "confusion.png"))
    print("Score histogram...")
    plot_score_hist(y.values, p, model.threshold, eval_dir / "score_hist.png")
    print("Calibration...")
    plot_calibration(y.values, p, eval_dir / "calibration.png")

    print("Per-scenario recall...")
    out["per_scenario"] = plot_per_group_recall(
        y, yhat, full["scenario"], "scenario", eval_dir / "per_scenario_recall.png"
    )
    print("Per-sourcetype recall...")
    out["per_sourcetype"] = plot_per_group_recall(
        y, yhat, full["sourcetype"], "sourcetype",
        eval_dir / "per_sourcetype_recall.png", top_n=15,
    )

    # Aggregate metrics
    p_metric, r_metric, f_metric, _ = precision_recall_fscore_support(y, yhat, average="binary")
    out["aggregate"] = {
        "test_n": int(len(y)),
        "positive_rate": float((y == 1).mean()),
        "threshold": model.threshold,
        "precision": float(p_metric),
        "recall": float(r_metric),
        "f1": float(f_metric),
    }

    # Permutation importance — the headline diagnostic
    print("Permutation feature importance...")
    X_test_features = test_df[model.feature_names].copy()
    out["permutation_importance"] = plot_perm_importance(
        model, X_test_features, y, eval_dir / "perm_importance.png",
    )

    # A small sample of test predictions for manual eyeball
    sample_n = 200
    rng = np.random.default_rng(42)
    sample_idx = rng.choice(len(test_df), size=min(sample_n, len(test_df)), replace=False)
    sample = test_df.iloc[sample_idx].copy()
    sample["_pred_proba"] = p[sample_idx]
    sample["_pred"] = yhat[sample_idx]
    sample["_correct"] = (sample["_pred"] == sample["label"]).astype(int)
    sample.to_csv(eval_dir / "sample_predictions.csv", index=False)
    print(f"  wrote sample of {sample_n} predictions to sample_predictions.csv")

    # Summary JSON
    with open(eval_dir / "summary.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  -> {eval_dir}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", help="Model dir name under models/, e.g. lgbm_xt_temporal")
    ap.add_argument("--all", action="store_true", help="Evaluate both temporal and stratified")
    args = ap.parse_args()

    targets: list[str] = []
    if args.all:
        targets = ["lgbm_xt_temporal", "lgbm_xt_stratified"]
    elif args.model:
        targets = [args.model if args.model.startswith("lgbm_") else f"lgbm_xt_{args.model}"]
    else:
        print("Pass --model <name> or --all")
        return 1

    for t in targets:
        evaluate_model(t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
