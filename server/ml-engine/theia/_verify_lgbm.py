"""Skeptic's verification of the THEIA LightGBMXT result.

Feeds the REAL held-out 6r.8 edge log through the saved boosters and reports,
side by side:
  (a) the node-TYPE classification accuracy   -- what the model is actually trained to do
  (b) RAW flagged-vs-GT precision/recall/F1    -- no 2-hop forgiveness
  (c) 2-HOP ADJUSTED precision/recall/F1       -- reproduces _lgbm_run.log
plus a sample of per-node verdicts (tokens, true type, predicted type, conf, flagged?, malicious?).

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_verify_lgbm.py
"""
from __future__ import annotations
import json, os, pickle, time
from pathlib import Path
import numpy as np, pandas as pd
from gensim.models import Word2Vec
import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
LGBM_W = CODE_ROOT / "trained_weights/theia_lgbm"
W2V = CODE_ROOT / "trained_weights/theia_ours_v2/word2vec_theia_E3.model"


def conf_margin(proba):
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


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f = 2 * p * r / (p + r) if p + r else 0
    return p, r, f


def main():
    t0 = time.time()
    w2v = Word2Vec.load(str(W2V)); enc = fc.PositionalEncoder()
    fc.parse_split(TEST_BASE, TEST_SPLIT, str(DATA_ROOT / "theia_test.txt"))
    rows = [l.split("\t") for l in (DATA_ROOT / "theia_test.txt").read_text(
        encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID", "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    df = fc.add_attributes(df, TEST_SPLIT)
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    X = np.array([fc.infer(p, w2v, enc) for p in phrases])
    yte = np.array(labels)
    all_ids = set(df["actorID"]) | set(df["objectID"])
    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    print(f"test nodes={len(yte):,}  GT malicious={len(GT):,}  (featurize {time.time()-t0:.0f}s)", flush=True)

    boosters = sorted(LGBM_W.glob("lgbm_xt_theia*_E3.pkl"),
                      key=lambda p: int(p.stem.split("theia")[1].split("_")[0]))
    flag = np.ones(len(yte), dtype=bool)
    b0_pred = b0_conf = None
    for m, bp in enumerate(boosters):
        clf = pickle.load(open(bp, "rb"))
        proba = clf.predict_proba(X)
        pred = clf.classes_[proba.argmax(1)]
        conf = conf_margin(proba)
        if m == 0:
            b0_pred, b0_conf = pred, conf
        flag[(pred == yte) & (conf > 0.53)] = False

    # (a) node-TYPE accuracy of the real model (booster 0)
    type_acc = (b0_pred == yte).mean()
    print(f"\n(a) NODE-TYPE classification accuracy (booster0): {type_acc:.4f}  "
          f"-- this is the task the model was actually trained on")

    alert_ids = {mapp[i] for i in np.where(flag)[0]}

    # (b) RAW, no 2-hop forgiveness
    TP = alert_ids & GT; FP = alert_ids - GT; FN = GT - alert_ids
    TN = all_ids - (GT | alert_ids)
    p, r, f = prf(len(TP), len(FP), len(FN))
    print(f"\n(b) RAW (no 2-hop):      TP={len(TP)} FP={len(FP)} FN={len(FN)} TN={len(TN)}  "
          f"precision={p:.4f} recall={r:.4f} F1={f:.4f}")

    # (c) 2-hop adjusted (reproduces the log)
    two_gp = get_adjacent(GT, mapp, edges, 2)
    two_tp = get_adjacent(TP, mapp, edges, 2)
    FPL = FP - two_gp
    TPL = TP | (FN & two_tp)
    FNa = FN - two_tp
    p2, r2, f2 = prf(len(TPL), len(FPL), len(FNa))
    print(f"(c) 2-HOP ADJUSTED:      TP={len(TPL)} FP={len(FPL)} FN={len(FNa)}  "
          f"precision={p2:.4f} recall={r2:.4f} F1={f2:.4f}  "
          f"<- forgave {len(FP)-len(FPL)} FPs, promoted {len(TPL)-len(TP)} FNs->TP")

    # sample per-node verdicts: 6 malicious-flagged + 6 benign
    print("\n  sample per-node verdicts:")
    print(f"  {'truth':<6}{'ttype':<6}{'pred':<5}{'conf':<6}{'flag':<6}tokens(head)")
    shown_m = shown_b = 0
    for i, nid in enumerate(mapp):
        mal = nid in GT
        if mal and shown_m >= 6:
            continue
        if not mal and shown_b >= 6:
            continue
        toks = [t for t in phrases[i]][:4]
        print(f"  {'MAL' if mal else 'ben':<6}{yte[i]:<6}{int(b0_pred[i]):<5}{b0_conf[i]:<6.2f}"
              f"{'FLAG' if flag[i] else 'clean':<6}{toks}")
        if mal: shown_m += 1
        else: shown_b += 1
        if shown_m >= 6 and shown_b >= 6:
            break


if __name__ == "__main__":
    main()
