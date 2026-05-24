"""Forensic audit of the Sysmon-balanced model. Investigates why AUC=1.0.

Checks for, in order:
  1. Row duplication across train / val / test
  2. Per-feature class separability — if (image, command_line) values are
     wholly disjoint between Mordor-positive and BOTSv2-benign, the
     model isn't generalising, just memorising vocabularies.
  3. Leak proxy: train a tiny LightGBM to predict is_mordor (1 if row
     came from Mordor, 0 if from BOTSv2) using ONLY the features the
     production model sees. If that AUC is also ~1.0, the production
     model is detecting "Mordor distribution," not attacks.
  4. Score distribution shape — bimodal (memorisation) vs sigmoid (real)
  5. Sensitivity: how much does dropping the top-3 features hurt?
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
import polars as pl
from sklearn.metrics import roc_auc_score

import schema as S

MODEL_DIR = Path(__file__).parent / "models" / "lgbm_xt_stratified_vanilla_sysmon_balanced"
DATA_DIR = Path(__file__).parent / "data" / "sysmon_balanced"


def log(m): print(f"\n=== {m} ===", flush=True)


def main() -> int:
    t0 = time.time()
    train = pl.read_parquet(DATA_DIR / "train.parquet")
    val = pl.read_parquet(DATA_DIR / "val.parquet")
    test = pl.read_parquet(DATA_DIR / "test.parquet")
    print(f"loaded train={train.height:,} val={val.height:,} test={test.height:,}",
          flush=True)

    # ──────────────────────────────────────────────────────────────────
    log("(1) Duplicate-row leak check")
    # ──────────────────────────────────────────────────────────────────
    # Hash on the content fields the model sees.
    feat_cols = S.model_feature_columns()
    feat_cols = [c for c in feat_cols if c in train.columns and c not in
                 {"sourcetype", "event_id"}]
    print(f"  hashing on {len(feat_cols)} features")

    def hash_rows(df: pl.DataFrame) -> pl.Series:
        # Concat as string, then hash via Polars
        cols = [pl.col(c).cast(pl.String).fill_null("").alias(c) for c in feat_cols]
        return df.select(pl.concat_str(cols, separator="|")).to_series().hash().alias("h")

    h_train = set(hash_rows(train).to_list())
    h_val = set(hash_rows(val).to_list())
    h_test = set(hash_rows(test).to_list())
    print(f"  unique train hashes: {len(h_train):,}")
    print(f"  unique val   hashes: {len(h_val):,}")
    print(f"  unique test  hashes: {len(h_test):,}")
    print(f"  test rows whose hash exists in train: "
          f"{len(h_test & h_train):,} ({100*len(h_test & h_train)/len(h_test):.2f}%)")
    print(f"  val  rows whose hash exists in train: "
          f"{len(h_val & h_train):,} ({100*len(h_val & h_train)/len(h_val):.2f}%)")

    # ──────────────────────────────────────────────────────────────────
    log("(2) Source-distribution proxy: is row from Mordor vs BOTSv2?")
    # ──────────────────────────────────────────────────────────────────
    # We need to know each row's source. The downsample pipeline lost the
    # source flag, but we can recover via host or by re-reading the
    # featured Parquets. Use a heuristic: host names ending in numeric
    # FROTHLY-shape (e.g. wrk-btun, MACLORY-AIR13) are BOTSv2, Mordor
    # hosts are MORDORDC, MORDORCLIENT, IT001, HR001, WORKSTATION6, etc.
    # Simpler: use scenario column. Mordor scenarios start with "mordor_".
    for split, name in [(train, "train"), (val, "val"), (test, "test")]:
        n_mordor_pos = split.filter(
            (pl.col("label") == 1) & pl.col("scenario").str.starts_with("mordor_")
        ).height
        n_bots_pos = split.filter(
            (pl.col("label") == 1) & ~pl.col("scenario").str.starts_with("mordor_")
        ).height
        n_neg = (split["label"] == 0).sum()
        n_neg_mordor = split.filter(
            (pl.col("label") == 0) & pl.col("scenario").str.starts_with("mordor_")
        ).height if split.filter(pl.col("label") == 0).height else 0
        print(f"  {name}: pos_mordor={n_mordor_pos:,} pos_bots={n_bots_pos:,} "
              f"neg={n_neg:,} (neg_mordor={n_neg_mordor:,})")

    # ──────────────────────────────────────────────────────────────────
    log("(3) Leak proxy classifier: predict is_mordor from features")
    # ──────────────────────────────────────────────────────────────────
    # If a model trained to predict is_mordor (instead of label) achieves
    # similar AUC, then the production model is just memorising
    # 'this is a Mordor row.'

    # Add is_mordor flag derived from scenario
    def add_is_mordor(df):
        return df.with_columns(
            pl.col("scenario").fill_null("").str.starts_with("mordor_")
              .cast(pl.Int8).alias("is_mordor")
        )

    train_m = add_is_mordor(train).to_pandas()
    test_m = add_is_mordor(test).to_pandas()

    cat_cols = [c for c in S.model_categorical_columns()
                if c in feat_cols]
    num_cols = [c for c in feat_cols if c not in cat_cols]

    X_tr = train_m[feat_cols].copy()
    X_te = test_m[feat_cols].copy()
    for c in cat_cols:
        X_tr[c] = X_tr[c].astype("category")
        X_te[c] = pd.Categorical(X_te[c], categories=X_tr[c].cat.categories)
    for c in num_cols:
        X_tr[c] = pd.to_numeric(X_tr[c], errors="coerce")
        X_te[c] = pd.to_numeric(X_te[c], errors="coerce")

    y_tr_mord = train_m["is_mordor"]
    y_te_mord = test_m["is_mordor"]
    y_tr_lab = train_m["label"]
    y_te_lab = test_m["label"]

    print(f"  train: is_mordor positive rate = {y_tr_mord.mean():.4f}")
    print(f"  train: label    positive rate = {y_tr_lab.mean():.4f}")
    print(f"  Pearson(label, is_mordor) = "
          f"{pd.Series(y_tr_lab).corr(pd.Series(y_tr_mord)):.4f}")

    clf_m = lgb.LGBMClassifier(
        n_estimators=200, learning_rate=0.1, num_leaves=31,
        is_unbalance=True, verbose=-1, random_state=42, n_jobs=6,
    )
    clf_m.fit(X_tr, y_tr_mord, categorical_feature=cat_cols)
    p_te_mord = clf_m.predict_proba(X_te)[:, 1]
    auc_mord = roc_auc_score(y_te_mord, p_te_mord)
    print(f"  --> AUC of is_mordor classifier on test: {auc_mord:.6f}")
    print(f"      (if this is ~1.0, the production model has the same leak)")

    # ──────────────────────────────────────────────────────────────────
    log("(4) Score distribution of production model on test")
    # ──────────────────────────────────────────────────────────────────
    booster = lgb.Booster(model_file=str(MODEL_DIR / "booster.txt"))
    cats = json.load(open(MODEL_DIR / "categories.json"))
    fnames = json.load(open(MODEL_DIR / "feature_names.json"))
    X_pred = test.to_pandas()[fnames].copy()
    for c, vals in cats.items():
        if c in X_pred.columns:
            X_pred[c] = pd.Categorical(X_pred[c], categories=vals)
    for c in fnames:
        if c not in cats:
            X_pred[c] = pd.to_numeric(X_pred[c], errors="coerce").astype("float64")
    scores = booster.predict(X_pred)
    y = test["label"].to_numpy()

    bins = [0, 0.001, 0.01, 0.1, 0.3, 0.5, 0.7, 0.9, 0.99, 1.001]
    hist_pos = np.histogram(scores[y == 1], bins=bins)[0]
    hist_neg = np.histogram(scores[y == 0], bins=bins)[0]
    print(f"  bin                  pos          neg")
    for i in range(len(bins) - 1):
        print(f"  [{bins[i]:>5.3f},{bins[i+1]:>5.3f})  "
              f"{hist_pos[i]:>9,}  {hist_neg[i]:>9,}")
    print(f"  pos median score: {np.median(scores[y==1]):.4f}  "
          f"neg median score: {np.median(scores[y==0]):.4f}")
    print(f"  pos % score>0.99: {100*(scores[y==1]>0.99).mean():.2f}%")
    print(f"  neg % score<0.01: {100*(scores[y==0]<0.01).mean():.2f}%")

    # ──────────────────────────────────────────────────────────────────
    log("(5) Sensitivity: zero out top-3 features and re-score test")
    # ──────────────────────────────────────────────────────────────────
    gains = booster.feature_importance("gain")
    ranked = sorted(zip(fnames, gains), key=lambda x: -x[1])
    print(f"  top-3 by gain: {[r[0] for r in ranked[:3]]}")
    for col, _ in ranked[:3]:
        Xz = X_pred.copy()
        if col in cats:
            Xz[col] = pd.Categorical([None] * len(Xz), categories=cats[col])
        else:
            Xz[col] = np.nan
        sz = booster.predict(Xz)
        auc_z = roc_auc_score(y, sz)
        print(f"    zero out {col!r}: test AUC = {auc_z:.6f} "
              f"(baseline {roc_auc_score(y, scores):.6f})")

    # ──────────────────────────────────────────────────────────────────
    log("(6) Per-feature: vocabulary overlap between BOTSv2 vs Mordor positives")
    # ──────────────────────────────────────────────────────────────────
    pos_bots = train.filter(
        (pl.col("label") == 1) & ~pl.col("scenario").str.starts_with("mordor_")
    )
    pos_mord = train.filter(
        (pl.col("label") == 1) & pl.col("scenario").str.starts_with("mordor_")
    )
    neg = train.filter(pl.col("label") == 0)
    print(f"  positives BOTSv2={pos_bots.height:,}  Mordor={pos_mord.height:,}  "
          f"negatives={neg.height:,}")
    for col in ("image", "command_line", "process_name", "image_basename",
                "object_name_ext", "user", "target_dir"):
        if col not in train.columns:
            continue
        v_mord = set(pos_mord[col].drop_nulls().unique().to_list())
        v_neg = set(neg[col].drop_nulls().unique().to_list())
        overlap = len(v_mord & v_neg) / max(len(v_mord), 1)
        print(f"  {col:<20}  |Mordor-pos|={len(v_mord):>6,}  "
              f"|Neg|={len(v_neg):>7,}  "
              f"overlap(Mord_AND_Neg)/|Mord| = {100*overlap:.2f}%")

    print(f"\nAudit complete in {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
