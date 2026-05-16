"""
Derive deployment thresholds from the val split.

For each model (temporal, temporal_no_st):
  - Load val.parquet → predict_proba
  - Sweep thresholds, find min threshold achieving target precision
  - Append a 'deployment' key to threshold.json

Usage:
  python threshold-calibration.py                        # default: 0.99 precision
  python threshold-calibration.py --precision 0.95
"""

import argparse
import json
import os
import sys

import numpy as np  # noqa: F401 — used in threshold sweep
import pandas as pd
import lightgbm as lgb

HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, "data", "temporal")
MODELS_DIR = os.path.join(HERE, "models")

MODELS = {
    "lgbm_xt_temporal":       True,   # True = include sourcetype
    "lgbm_xt_temporal_no_st": False,
}


def load_model_and_categories(model_dir: str):
    booster = lgb.Booster(model_file=os.path.join(model_dir, "booster.txt"))
    with open(os.path.join(model_dir, "categories.json")) as f:
        categories = json.load(f)
    with open(os.path.join(model_dir, "feature_names.json")) as f:
        feature_names = json.load(f)
    return booster, categories, feature_names


def align_categories(df: pd.DataFrame, categories: dict, feature_names: list[str]) -> pd.DataFrame:
    for col, cats in categories.items():
        if col in df.columns:
            df[col] = pd.Categorical(df[col], categories=cats)
    df = df.reindex(columns=feature_names, fill_value=np.nan)
    return df


def _add_external_ip(df: pd.DataFrame) -> pd.DataFrame:
    _PRIVATE = ("10.", "192.168.", "127.", "0.", "")

    def _is_private(s: pd.Series) -> pd.Series:
        mask = s.isna() | (s == "")
        for p in _PRIVATE:
            mask = mask | s.str.startswith(p, na=True)
        mask = mask | s.str.match(r"^172\.(1[6-9]|2\d|3[01])\.", na=True)
        return mask

    src = df.get("src_ip", pd.Series("", index=df.index)).fillna("").astype(str)
    dst = df.get("dest_ip", pd.Series("", index=df.index)).fillna("").astype(str)
    src_private = _is_private(src)
    dst_private = _is_private(dst)
    df["external_ip"] = src.where(~src_private, dst)
    df["external_ip"] = df["external_ip"].where(~(src_private & dst_private), "")
    return df


def calibrate(model_name: str, target_precision: float):
    model_dir = os.path.join(MODELS_DIR, model_name)
    threshold_path = os.path.join(model_dir, "threshold.json")

    print(f"\n{'='*60}")
    print(f"Model: {model_name}")
    print(f"Target precision: {target_precision:.2%}")

    booster, categories, feature_names = load_model_and_categories(model_dir)

    print("Loading val split...")
    val = pd.read_parquet(os.path.join(DATA_DIR, "val.parquet"))
    y_val = val["label"].astype(int)

    val = _add_external_ip(val)
    X_val = align_categories(val, categories, feature_names)

    print(f"Val rows: {len(X_val):,}  positives: {y_val.sum():,}")

    print("Scoring val split...")
    scores = booster.predict(X_val)

    # Sweep thresholds 0..1 in 1000 steps
    thresholds = np.linspace(0.0, 1.0, 1001)
    results = []
    for t in thresholds:
        pred = (scores >= t).astype(int)
        tp = int(((pred == 1) & (y_val == 1)).sum())
        fp = int(((pred == 1) & (y_val == 0)).sum())
        fn = int(((pred == 0) & (y_val == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        results.append((t, precision, recall, tp, fp))

    # Find minimum threshold achieving target precision
    candidates = [(t, p, r) for t, p, r, tp, fp in results if p >= target_precision]
    if not candidates:
        print(f"  WARNING: No threshold achieves {target_precision:.0%} precision!")
        print(f"  Max achievable precision: {max(r[1] for r in results):.4f}")
        deployment_threshold = 1.0
        dep_precision = 1.0
        dep_recall = 0.0
    else:
        deployment_threshold, dep_precision, dep_recall = candidates[0]

    print(f"  Deployment threshold: {deployment_threshold:.4f}")
    print(f"  Val precision at threshold: {dep_precision:.4f}")
    print(f"  Val recall at threshold:    {dep_recall:.4f}")
    print(f"  Alert rate: {sum(scores >= deployment_threshold):,} / {len(scores):,} val events flagged")

    # Update threshold.json
    with open(threshold_path) as f:
        threshold_data = json.load(f)

    threshold_data["deployment"] = {
        "threshold": float(deployment_threshold),
        "precision_target": target_precision,
        "val_precision": float(dep_precision),
        "val_recall": float(dep_recall),
        "val_alert_rate": float((scores >= deployment_threshold).mean()),
    }

    with open(threshold_path, "w") as f:
        json.dump(threshold_data, f, indent=2)

    print(f"  Updated: {threshold_path}")
    return deployment_threshold, dep_precision, dep_recall


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--precision", type=float, default=0.99,
                        help="Target val precision (default 0.99)")
    args = parser.parse_args()

    results = {}
    for model_name in MODELS:
        model_dir = os.path.join(MODELS_DIR, model_name)
        if not os.path.exists(model_dir):
            print(f"Skipping {model_name} — model directory not found")
            continue
        t, p, r = calibrate(model_name, args.precision)
        results[model_name] = {"threshold": t, "precision": p, "recall": r}

    print("\n" + "="*60)
    print("SUMMARY")
    for name, m in results.items():
        print(f"  {name}: t={m['threshold']:.4f}  P={m['precision']:.4f}  R={m['recall']:.4f}")


if __name__ == "__main__":
    main()
