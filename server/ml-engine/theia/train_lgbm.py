"""LightGBM ExtraTrees (LightGBMXT) ablation of the GraphSAGE FLASH model on
DARPA TC E3 THEIA, using FLASH's own processing (theia_flash_common).

Identical to train_gnn.py / evaluate.py EXCEPT the model: same FLASH parse, same
30-dim Word2Vec node features (reusing v2's w2v so features match the GNN
exactly), same self-supervised node-type label, same 20-round iterative
explain-away loop and same 2-hop eval -- but a gradient-boosted tree ensemble
with extra_trees=True replaces the GNN. No neighborhood aggregation, so this
isolates the contribution of graph structure.

Train (1r base) -> 20 boosters in trained_weights/theia_lgbm/, then eval on
held-out 6r.8. Directly comparable to v2 GNN (P0.8301 / R0.9983 / F1 0.9065).
Raw DARPA data is read from THEIA_DATA_ROOT (default: <repo>/external/Flash-IDS).

  python train_lgbm.py
"""
from __future__ import annotations

import json
import os
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from gensim.models import Word2Vec
from lightgbm import LGBMClassifier

import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT",
                                CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TRAIN_BASE = str(DATA_ROOT / "ta1-theia-e3-official-1r.json")
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
OUT_DIR = CODE_ROOT / os.environ.get("THEIA_LGBM_OUT", "trained_weights/theia_lgbm")
# Reuse v2's word2vec so node features are identical to the GNN's input.
W2V_SRC = CODE_ROOT / os.environ.get("THEIA_W2V", "trained_weights/theia_ours_v2/word2vec_theia_E3.model")
SEED = int(os.environ.get("THEIA_SEED", "42"))
N_EST = int(os.environ.get("N_ESTIMATORS", "300"))
LR = float(os.environ.get("LEARNING_RATE", "0.05"))
ROUNDS = 20
np.random.seed(SEED)


def featurize(base, split, out_txt, w2v, enc):
    """FLASH parse + attribute merge -> (X 30-dim, node-type labels, edges, mapp, all_ids)."""
    fc.parse_split(base, split, str(out_txt))
    rows = [l.split("\t") for l in
            Path(out_txt).read_text(encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    df = fc.add_attributes(df, split)
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    X = np.array([fc.infer(p, w2v, enc) for p in phrases])
    all_ids = set(df["actorID"]) | set(df["objectID"])
    return X, np.array(labels), edges, mapp, all_ids


def conf_margin(proba):
    """(top1-top2)/top1 confidence, min/max-normalized (mirrors the GNN)."""
    s = np.sort(proba, axis=1)[:, ::-1]
    c = (s[:, 0] - s[:, 1]) / np.clip(s[:, 0], 1e-9, None)
    rng = c.max() - c.min()
    return (c - c.min()) / rng if rng > 0 else np.zeros_like(c)


def get_adjacent(ids, mapp, edges, hops):
    if hops == 0:
        return set()
    nb = set()
    for s, t in zip(edges[0], edges[1]):
        if mapp[s] in ids or mapp[t] in ids:
            nb.add(mapp[s]); nb.add(mapp[t])
    if hops > 1:
        nb |= get_adjacent(nb, mapp, edges, hops - 1)
    return nb


def report(MP, all_ids, GP, edges, mapp):
    TP, FP, FN = MP & GP, MP - GP, GP - MP
    TN = all_ids - (GP | MP)
    two_gp = get_adjacent(GP, mapp, edges, 2)
    two_tp = get_adjacent(TP, mapp, edges, 2)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FN = FN - two_tp
    tp, fp, fn, tn = len(TPL), len(FPL), len(FN), len(TN)
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print("\n=== LightGBMXT METRICS (2-hop adjusted) ===")
    print(f"  out: {OUT_DIR}")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"  precision={prec:.4f}  recall={rec:.4f}  F1={f1:.4f}  FPR={fpr:.4f}")
    print("  compare v2 GNN: precision=0.8301  recall=0.9983  F1=0.9065")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    w2v = Word2Vec.load(str(W2V_SRC))
    enc = fc.PositionalEncoder()
    print(f"w2v vocab={len(w2v.wv)}  seed={SEED}  n_est={N_EST}  lr={LR}", flush=True)

    Xtr, ytr, _, _, _ = featurize(TRAIN_BASE, TRAIN_BASE, DATA_ROOT / "theia_train.txt", w2v, enc)
    print(f"train nodes={len(ytr):,}  (featurize {time.time()-t0:.0f}s)", flush=True)

    mask = np.ones(len(ytr), dtype=bool)
    n_saved = 0
    for m in range(ROUNDS):
        ti = time.time()
        idx = np.where(mask)[0]
        Xm, ym = Xtr[idx], ytr[idx]
        if len(np.unique(ym)) < 2:
            print(f"  round {m}: residual single-class ({len(ym)} nodes) -> stop", flush=True)
            break
        clf = LGBMClassifier(extra_trees=True, boosting_type="gbdt", n_estimators=N_EST,
                             learning_rate=LR, num_leaves=31, min_child_samples=20,
                             class_weight="balanced", random_state=SEED, n_jobs=-1, verbose=-1)
        clf.fit(Xm, ym)
        with open(OUT_DIR / f"lgbm_xt_theia{m}_E3.pkl", "wb") as fh:
            pickle.dump(clf, fh)
        n_saved += 1
        proba = clf.predict_proba(Xm)
        pred = clf.classes_[proba.argmax(1)]
        cond = (pred == ym) | (conf_margin(proba) >= 0.9)
        mask[idx[cond]] = False
        print(f"  round {m}: {int(mask.sum())} hard nodes  ({time.time()-ti:.0f}s)", flush=True)

    print(f"trained {n_saved} boosters in {time.time()-t0:.0f}s -> {OUT_DIR}", flush=True)

    # ---- eval on held-out 6r.8 ----
    Xte, yte, edges, mapp, all_ids = featurize(TEST_BASE, TEST_SPLIT, DATA_ROOT / "theia_test.txt", w2v, enc)
    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    print(f"test nodes={len(yte):,}  GT malicious={len(GT):,}", flush=True)

    flag = np.ones(len(yte), dtype=bool)
    for m in range(n_saved):
        with open(OUT_DIR / f"lgbm_xt_theia{m}_E3.pkl", "rb") as fh:
            clf = pickle.load(fh)
        proba = clf.predict_proba(Xte)
        pred = clf.classes_[proba.argmax(1)]
        cond = (pred == yte) & (conf_margin(proba) > 0.53)
        flag[cond] = False
        print(f"  eval booster {m}: {int(flag.sum())} still flagged", flush=True)

    alert_ids = {mapp[i] for i in np.where(flag)[0]}
    report(alert_ids, all_ids, GT, edges, mapp)


if __name__ == "__main__":
    main()
