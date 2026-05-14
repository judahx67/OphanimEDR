"""Phase 6: train a single LightGBMXT classifier on the BOTSv2 splits.

Reads train/val/test parquet from data/{temporal,stratified}/, fits LightGBM
with extra_trees=True (the "XT" variant), picks the operating threshold on
val, persists the model + metadata.

What this script ALSO produces (saving a separate evaluate.py from being a
dependency of just-shipping-something): per-scenario recall on test,
ROC-AUC on test, confusion matrix at the chosen threshold. Plotting and
the full evaluation suite live in evaluate.py (Phase 7).

Usage:
    python train.py --split temporal              # headline run
    python train.py --split stratified            # upper-bound anchor
    python train.py --split temporal --no-xt      # vanilla LightGBM A/B
    python train.py --split temporal --smoke 50000  # quick smoke test
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import polars as pl
from sklearn.metrics import (
    confusion_matrix, f1_score, matthews_corrcoef,
    precision_recall_fscore_support, roc_auc_score,
)

import schema as S

DATA_DIR = Path(__file__).parent / "data"
MODELS_DIR = Path(__file__).parent / "models"


# ──────────────────────────────────────────────────────────────────────────
# Data prep
# ──────────────────────────────────────────────────────────────────────────

def load_split(split: str, smoke: int | None = None) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load train/val/test parquet for a split. Returns pandas frames.

    Why pandas: LightGBM's category support is most ergonomic with pandas
    Categorical dtype (where category codes are explicit and alignable
    across splits — see align_categories below). Polars also works but
    requires more conversion code; not worth it for a one-shot trainer.
    """
    base = DATA_DIR / split
    train_pl = pl.read_parquet(base / "train.parquet")
    val_pl = pl.read_parquet(base / "val.parquet")
    test_pl = pl.read_parquet(base / "test.parquet")

    if smoke is not None:
        # Stratified subsample so smoke retains the positive rate
        train_pl = (
            pl.concat([
                train_pl.filter(pl.col("label") == 1).sample(n=smoke // 2, seed=42, with_replacement=True),
                train_pl.filter(pl.col("label") == 0).sample(n=smoke // 2, seed=42),
            ])
            .sample(fraction=1.0, seed=42, shuffle=True)
        )
        val_pl = val_pl.sample(n=min(smoke // 4, val_pl.height), seed=42)
        test_pl = test_pl.sample(n=min(smoke // 4, test_pl.height), seed=42)

    return train_pl.to_pandas(), val_pl.to_pandas(), test_pl.to_pandas()


def prepare_features(
    train: pd.DataFrame, val: pd.DataFrame, test: pd.DataFrame
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series, list[str]]:
    """Drop leaky/low-value/identity columns, align categorical dtypes.

    The category-alignment step is the silent eval-corrupter from the plan:
    LightGBM treats category codes positionally, so val/test must reuse
    train's category set or the codes mean different things across splits.
    """
    feature_cols = S.model_feature_columns()
    cat_cols = S.model_categorical_columns()

    y_train = train["label"].astype(np.int8)
    y_val = val["label"].astype(np.int8)
    y_test = test["label"].astype(np.int8)

    X_train = train[feature_cols].copy()
    X_val = val[feature_cols].copy()
    X_test = test[feature_cols].copy()

    # Categorical alignment: fit categories on train, reuse on val/test.
    # Strings that appear in val/test but not train become NaN (LightGBM
    # treats this correctly as "unknown category").
    for c in cat_cols:
        # Some columns may have come back as object dtype — coerce to str
        # before categorizing so np.nan doesn't get a category code.
        X_train[c] = X_train[c].astype("category")
        train_cats = X_train[c].cat.categories
        X_val[c] = pd.Categorical(X_val[c], categories=train_cats)
        X_test[c] = pd.Categorical(X_test[c], categories=train_cats)

    # Numeric columns may have come back as object dtype if all-null in some
    # rows; coerce to float so LightGBM treats them as numeric (NaN-aware).
    numeric_in_features = [c for c in feature_cols if c not in cat_cols]
    for c in numeric_in_features:
        X_train[c] = pd.to_numeric(X_train[c], errors="coerce")
        X_val[c] = pd.to_numeric(X_val[c], errors="coerce")
        X_test[c] = pd.to_numeric(X_test[c], errors="coerce")

    return X_train, X_val, X_test, y_train, y_val, y_test, cat_cols


# ──────────────────────────────────────────────────────────────────────────
# Train
# ──────────────────────────────────────────────────────────────────────────

def train_lgbm(
    X_train: pd.DataFrame, y_train: pd.Series,
    X_val: pd.DataFrame, y_val: pd.Series,
    cat_cols: list[str],
    extra_trees: bool = True,
) -> lgb.LGBMClassifier:
    """Fit LightGBMXT (or vanilla LightGBM if extra_trees=False).

    Hyperparameters lifted from AutoGluon's medium_quality preset, which
    won the prior experiment's per-model leaderboard. Not re-tuned here —
    this rebuild's job is to match the prior numbers with a single model,
    not to push the frontier.
    """
    clf = lgb.LGBMClassifier(
        extra_trees=extra_trees,
        boosting_type="gbdt",
        objective="binary",
        metric="auc",
        n_estimators=10_000,
        learning_rate=0.05,
        num_leaves=31,
        feature_fraction=1.0,
        min_data_in_leaf=20,
        n_jobs=6,
        random_state=42,
        verbose=-1,
    )
    clf.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        eval_metric="auc",
        callbacks=[lgb.early_stopping(stopping_rounds=200, verbose=False)],
        categorical_feature=cat_cols,
    )
    return clf


def pick_threshold(y_val: pd.Series, p_val: np.ndarray) -> tuple[float, dict]:
    """Pick operating threshold on val that maximizes F1.

    Searches over 100 evenly-spaced thresholds in [0.05, 0.95]. Returns
    threshold and the val metrics at that threshold for diagnostics.
    """
    best_f1 = -1.0
    best_t = 0.5
    for t in np.linspace(0.05, 0.95, 91):
        yhat = (p_val >= t).astype(np.int8)
        f1 = f1_score(y_val, yhat)
        if f1 > best_f1:
            best_f1 = f1
            best_t = float(t)
    yhat = (p_val >= best_t).astype(np.int8)
    p, r, f, _ = precision_recall_fscore_support(y_val, yhat, average="binary")
    return best_t, {
        "metric": "f1",
        "val_f1": float(f),
        "val_precision": float(p),
        "val_recall": float(r),
    }


# ──────────────────────────────────────────────────────────────────────────
# Test eval (lightweight — full plotting in evaluate.py)
# ──────────────────────────────────────────────────────────────────────────

def eval_test(
    clf: lgb.LGBMClassifier,
    X_test: pd.DataFrame, y_test: pd.Series, threshold: float,
    test_meta: pd.DataFrame,
) -> dict:
    """ROC-AUC + confusion + per-scenario recall + per-sourcetype recall.

    test_meta is the original pandas frame (with leaky cols still present,
    used for grouping by scenario/sourcetype during eval). Never used as features.
    """
    p_test = clf.predict_proba(X_test)[:, 1]
    yhat = (p_test >= threshold).astype(np.int8)

    auc = float(roc_auc_score(y_test, p_test))
    p, r, f, _ = precision_recall_fscore_support(y_test, yhat, average="binary")
    mcc = float(matthews_corrcoef(y_test, yhat))
    cm = confusion_matrix(y_test, yhat).tolist()  # [[tn, fp], [fn, tp]]

    # Per-scenario recall (only on malicious-labeled rows that have a scenario)
    per_scenario = {}
    for sid in test_meta["scenario"].dropna().unique():
        mask = (test_meta["scenario"] == sid) & (y_test == 1)
        if mask.sum() == 0:
            continue
        per_scenario[sid] = {
            "n": int(mask.sum()),
            "recall": float((yhat[mask.values] == 1).sum() / mask.sum()),
        }

    # Per-sourcetype recall (top 12 by malicious count)
    st_mal_counts = test_meta.loc[y_test == 1, "sourcetype"].value_counts().head(12)
    per_sourcetype = {}
    for st in st_mal_counts.index:
        mask = (test_meta["sourcetype"] == st) & (y_test == 1)
        per_sourcetype[st] = {
            "n_malicious": int(mask.sum()),
            "recall": float((yhat[mask.values] == 1).sum() / max(mask.sum(), 1)),
        }

    return {
        "test_n": int(len(y_test)),
        "test_positive_rate": float((y_test == 1).mean()),
        "roc_auc": auc,
        "precision": float(p),
        "recall": float(r),
        "f1": float(f),
        "mcc": mcc,
        "confusion_matrix": cm,
        "threshold": threshold,
        "per_scenario_recall": per_scenario,
        "per_sourcetype_recall": per_sourcetype,
    }


# ──────────────────────────────────────────────────────────────────────────
# Persistence
# ──────────────────────────────────────────────────────────────────────────

def persist(
    out_dir: Path,
    clf: lgb.LGBMClassifier,
    X_train: pd.DataFrame, cat_cols: list[str],
    threshold: float, val_metrics: dict, test_metrics: dict,
    fit_time_s: float, run_meta: dict,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Booster
    clf.booster_.save_model(str(out_dir / "booster.txt"))

    # Feature names + dtypes (recovery aid for inference)
    with open(out_dir / "feature_names.json", "w") as f:
        json.dump(list(X_train.columns), f, indent=2)

    # Categorical category lists (so inference can re-align categories)
    cats = {}
    for c in cat_cols:
        if c in X_train.columns:
            cats[c] = list(X_train[c].cat.categories)
    with open(out_dir / "categories.json", "w") as f:
        json.dump(cats, f, indent=2)

    # Threshold + metrics
    with open(out_dir / "threshold.json", "w") as f:
        json.dump({
            "threshold": threshold,
            "metric_used": val_metrics.get("metric", "f1"),
            "val_metrics_at_threshold": val_metrics,
        }, f, indent=2)

    # Test performance
    with open(out_dir / "test_metrics.json", "w") as f:
        json.dump(test_metrics, f, indent=2)

    # Run metadata
    with open(out_dir / "run_meta.json", "w") as f:
        json.dump({
            **run_meta,
            "fit_time_s": fit_time_s,
            "best_iteration": int(clf.best_iteration_) if clf.best_iteration_ else None,
            "n_features": len(X_train.columns),
            "n_categorical": len(cat_cols),
        }, f, indent=2)


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["temporal", "stratified"], required=True)
    ap.add_argument("--no-xt", action="store_true",
                    help="Train vanilla LightGBM (no extra_trees) for cheap A/B")
    ap.add_argument("--smoke", type=int, default=None,
                    help="Subsample size for quick smoke test (e.g. 50000)")
    ap.add_argument("--drop-feature", action="append", default=[],
                    help="Drop a feature column from X (repeat for multiple). "
                         "Used for ablations e.g. --drop-feature sourcetype.")
    ap.add_argument("--tag", default=None,
                    help="Suffix to append to the model directory name")
    args = ap.parse_args()

    print(f"=== Phase 6: train LightGBM{'XT' if not args.no_xt else ''} on {args.split} split ===")
    print(f"  schema check : {len(S.model_feature_columns())} features, "
          f"{len(S.model_categorical_columns())} categorical")

    t0 = time.time()
    print(f"\nLoading {args.split} split...")
    train_df, val_df, test_df = load_split(args.split, smoke=args.smoke)
    print(f"  train: {len(train_df):,}   val: {len(val_df):,}   test: {len(test_df):,}")
    print(f"  train positive rate: {(train_df['label'] == 1).mean():.4f}")
    print(f"  val   positive rate: {(val_df['label'] == 1).mean():.4f}")
    print(f"  test  positive rate: {(test_df['label'] == 1).mean():.4f}")

    print("\nPreparing features (drop leaky, align categories)...")
    X_train, X_val, X_test, y_train, y_val, y_test, cat_cols = prepare_features(
        train_df, val_df, test_df
    )
    if args.drop_feature:
        for col in args.drop_feature:
            if col in X_train.columns:
                X_train = X_train.drop(columns=[col])
                X_val = X_val.drop(columns=[col])
                X_test = X_test.drop(columns=[col])
                if col in cat_cols:
                    cat_cols = [c for c in cat_cols if c != col]
                print(f"  ablation: dropped feature `{col}`")
            else:
                print(f"  ablation: WARN `{col}` not in feature set, skipping")
    print(f"  features kept    : {X_train.shape[1]}")
    print(f"  categorical cols : {len(cat_cols)}")

    print(f"\nFitting LightGBM{'XT' if not args.no_xt else ''}...")
    fit_t0 = time.time()
    clf = train_lgbm(X_train, y_train, X_val, y_val, cat_cols, extra_trees=not args.no_xt)
    fit_time = time.time() - fit_t0
    print(f"  fit time      : {fit_time:.1f}s")
    print(f"  best iteration: {clf.best_iteration_}")

    print("\nPicking threshold on val (max F1)...")
    p_val = clf.predict_proba(X_val)[:, 1]
    threshold, val_metrics = pick_threshold(y_val, p_val)
    print(f"  threshold     : {threshold:.3f}")
    print(f"  val F1 / P / R: {val_metrics['val_f1']:.4f} / "
          f"{val_metrics['val_precision']:.4f} / {val_metrics['val_recall']:.4f}")

    print("\nEvaluating on test...")
    test_metrics = eval_test(clf, X_test, y_test, threshold, test_df)
    print(f"  ROC-AUC : {test_metrics['roc_auc']:.4f}")
    print(f"  F1      : {test_metrics['f1']:.4f}")
    print(f"  P / R   : {test_metrics['precision']:.4f} / {test_metrics['recall']:.4f}")
    print(f"  MCC     : {test_metrics['mcc']:.4f}")
    print(f"  CM (tn fp / fn tp): {test_metrics['confusion_matrix']}")
    if test_metrics["per_scenario_recall"]:
        print("  per-scenario recall:")
        for sid, d in sorted(test_metrics["per_scenario_recall"].items()):
            print(f"    {sid:30s} n={d['n']:>6,}   recall={d['recall']:.4f}")
    if test_metrics["per_sourcetype_recall"]:
        print("  per-sourcetype recall (top 12):")
        for st, d in sorted(
            test_metrics["per_sourcetype_recall"].items(),
            key=lambda x: -x[1]["n_malicious"],
        ):
            print(f"    {st:40s} n={d['n_malicious']:>6,}   recall={d['recall']:.4f}")

    print("\nPersisting model...")
    suffix = "_vanilla" if args.no_xt else ""
    smoke_suffix = f"_smoke{args.smoke}" if args.smoke else ""
    tag_suffix = f"_{args.tag}" if args.tag else ""
    out_dir = MODELS_DIR / f"lgbm_xt_{args.split}{suffix}{smoke_suffix}{tag_suffix}"
    persist(
        out_dir, clf, X_train, cat_cols,
        threshold, val_metrics, test_metrics,
        fit_time,
        run_meta={
            "split": args.split,
            "extra_trees": not args.no_xt,
            "smoke": args.smoke,
            "dropped_features": args.drop_feature,
        },
    )
    print(f"  -> {out_dir}")

    print(f"\nTotal wall time: {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
