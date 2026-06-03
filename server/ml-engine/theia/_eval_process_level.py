"""EDR-relevant evaluation of THEIA detection: score at PROCESS and INCIDENT
granularity instead of the netflow-blob node level.

Answers three questions on the held-out 6r.8 graph:
  1. EXPLAIN-AWAY model (existing FLASH-copied boosters), raw: how many GT
     malicious PROCESS nodes does it actually flag? (the EDR-meaningful target)
  2. Honest SUPERVISED LightGBMXT (label = in theia.json), temporal split:
     node-level AND process-level PR-AUC / P / R / F1, content-only vs +structural.
  3. INCIDENT structure: do GT malicious nodes form one connected component?
     (i.e. is the attack one incident an analyst would triage?)

Featurizes once and caches to _eval_cache.npz so re-runs are instant.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_eval_process_level.py
"""
from __future__ import annotations
import json, os, pickle, time
from collections import defaultdict
from pathlib import Path
import numpy as np, pandas as pd
from gensim.models import Word2Vec
from sklearn.metrics import average_precision_score, roc_auc_score
from lightgbm import LGBMClassifier
import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")
LGBM_W = CODE_ROOT / "trained_weights/theia_lgbm"
W2V = CODE_ROOT / "trained_weights/theia_ours_v2/word2vec_theia_E3.model"
CACHE = DATA_ROOT / "_eval_cache.npz"
GT = set(u for u in json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")) if u)


def build_features():
    if CACHE.exists():
        print(f"cache hit: {CACHE}", flush=True)
        z = np.load(CACHE, allow_pickle=True)
        return (z["Xw2v"], z["struct"], z["ymal"], z["ts"], z["isproc"],
                list(z["mapp"]), z["edges"])
    t0 = time.time()
    w2v = Word2Vec.load(str(W2V)); enc = fc.PositionalEncoder()
    fc.parse_split(TEST_BASE, TEST_SPLIT, str(DATA_ROOT / "theia_test.txt"))
    rows = [l.split("\t") for l in (DATA_ROOT / "theia_test.txt").read_text(
        encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID", "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    # per-node min timestamp + cdm type string (before add_attributes drops cols)
    nts, ntype = {}, {}
    for a, at, o, ot, ts in zip(df.actorID, df.actor_type, df.objectID, df.object, df.timestamp):
        try: t = int(ts)
        except ValueError: continue
        for nid, ty in ((a, at), (o, ot)):
            if nid not in nts or t < nts[nid]: nts[nid] = t
            ntype.setdefault(nid, ty)
    df = fc.add_attributes(df, TEST_SPLIT)
    phrases, _typelabels, edges, mapp = fc.prepare_graph(df)
    Xw2v = np.array([fc.infer(p, w2v, enc) for p in phrases], dtype=np.float32)
    # structural features from edge indices
    src, dst = np.array(edges[0]), np.array(edges[1])
    N = len(mapp)
    outd = np.bincount(src, minlength=N); ind = np.bincount(dst, minlength=N)
    onb, inb = defaultdict(set), defaultdict(set)
    for s, t in zip(src, dst):
        onb[s].add(t); inb[t].add(s)
    n_onb = np.array([len(onb[i]) for i in range(N)])
    n_inb = np.array([len(inb[i]) for i in range(N)])
    isproc = np.array([ntype.get(n, "") == "SUBJECT_PROCESS" for n in mapp])
    type_code = np.array([fc.DUMMIES.get(ntype.get(n, ""), 0) for n in mapp])
    struct = np.stack([outd, ind, n_onb, n_inb, type_code], axis=1).astype(np.float32)
    ts = np.array([nts.get(n, 0) for n in mapp], dtype=np.int64)
    ymal = np.array([n in GT for n in mapp], dtype=bool)
    edges_arr = np.stack([src, dst]).astype(np.int32)
    np.savez_compressed(CACHE, Xw2v=Xw2v, struct=struct, ymal=ymal, ts=ts,
                        isproc=isproc, mapp=np.array(mapp, dtype=object), edges=edges_arr)
    print(f"featurized {N:,} nodes in {time.time()-t0:.0f}s -> cached", flush=True)
    return Xw2v, struct, ymal, ts, isproc, mapp, edges_arr


def prf_at(y, score, thr):
    pred = score >= thr
    tp = int((pred & y).sum()); fp = int((pred & ~y).sum()); fn = int((~pred & y).sum())
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    f = 2 * p * r / (p + r) if p + r else 0
    return tp, fp, fn, p, r, f


def best_f1_thr(y, score):
    thrs = np.quantile(score, np.linspace(0.5, 0.999, 60))
    best = max(thrs, key=lambda t: prf_at(y, score, t)[5])
    return best


def report_supervised(name, ytr, Xtr, yte, Xte, isproc_te):
    clf = LGBMClassifier(extra_trees=True, boosting_type="gbdt", n_estimators=300,
                         learning_rate=0.05, num_leaves=31, min_child_samples=20,
                         class_weight="balanced", random_state=42, n_jobs=-1, verbose=-1)
    clf.fit(Xtr, ytr)
    s = clf.predict_proba(Xte)[:, 1]
    thr = best_f1_thr(ytr, clf.predict_proba(Xtr)[:, 1])
    print(f"\n[{name}] supervised, temporal split  (train pos={ytr.sum():,} test pos={yte.sum():,})")
    apr = average_precision_score(yte, s); roc = roc_auc_score(yte, s)
    tp, fp, fn, p, r, f = prf_at(yte, s, thr)
    print(f"  NODE-level    PR-AUC={apr:.4f} ROC-AUC={roc:.4f} | @thr P={p:.3f} R={r:.3f} F1={f:.3f} (TP{tp}/FP{fp}/FN{fn})")
    # process-level: restrict to process nodes
    pm = isproc_te
    if yte[pm].sum() > 0:
        apr2 = average_precision_score(yte[pm], s[pm])
        tp, fp, fn, p, r, f = prf_at(yte[pm], s[pm], thr)
        print(f"  PROCESS-level PR-AUC={apr2:.4f} (proc nodes={pm.sum():,}, mal proc={int(yte[pm].sum())}) "
              f"| @thr P={p:.3f} R={r:.3f} F1={f:.3f} (TP{tp}/FP{fp}/FN{fn})")
    else:
        print(f"  PROCESS-level: no malicious processes in temporal test half")


def explain_away_process(Xw2v, type_code, ymal, isproc, mapp):
    """Raw flag set of the existing FLASH boosters, scored on PROCESS nodes.
    Faithful eval rule: un-flag nodes correctly typed with high confidence."""
    boosters = sorted(LGBM_W.glob("lgbm_xt_theia*_E3.pkl"),
                      key=lambda p: int(p.stem.split("theia")[1].split("_")[0]))
    flag = np.ones(len(ymal), dtype=bool)
    for bp in boosters:
        clf = pickle.load(open(bp, "rb"))
        proba = clf.predict_proba(Xw2v)
        s = np.sort(proba, axis=1)[:, ::-1]
        margin = (s[:, 0] - s[:, 1]) / np.clip(s[:, 0], 1e-9, None)
        rng = margin.max() - margin.min()
        conf = (margin - margin.min()) / rng if rng > 0 else np.zeros_like(margin)
        pred = clf.classes_[proba.argmax(1)]
        flag[(pred == type_code) & (conf > 0.53)] = False
    pm = isproc
    mal_proc = ymal & pm
    flagged_mal_proc = int((flag & mal_proc).sum())
    print(f"\n[explain-away FLASH boosters] PROCESS-level RAW (no 2-hop):")
    print(f"  malicious processes in graph={int(mal_proc.sum())}  flagged={flagged_mal_proc}  "
          f"total proc flagged={int((flag & pm).sum()):,}/{int(pm.sum()):,}")


def incident_structure(ymal, edges, mapp, isproc):
    N = len(mapp)
    parent = np.arange(N)
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    for s, t in zip(edges[0], edges[1]):
        rs, rt = find(int(s)), find(int(t))
        if rs != rt: parent[rs] = rt
    roots = np.array([find(i) for i in range(N)])
    mal_idx = np.where(ymal)[0]
    from collections import Counter
    comp = Counter(roots[mal_idx].tolist())
    big_root, big_n = comp.most_common(1)[0]
    in_big = roots == big_root
    print(f"\n[incident structure] union-find connected components:")
    print(f"  GT malicious nodes={len(mal_idx):,} span {len(comp)} components")
    print(f"  largest malicious component holds {big_n:,} GT nodes "
          f"({big_n/len(mal_idx)*100:.1f}% of all GT)")
    print(f"  that component total size={int(in_big.sum()):,} nodes, "
          f"of which malicious-processes={int((ymal & isproc & in_big).sum())}")
    print("  -> if ~one component holds the GT, the attack IS one triage-able incident")


def main():
    Xw2v, struct, ymal, ts, isproc, mapp, edges = build_features()
    print(f"\nnodes={len(mapp):,}  malicious={int(ymal.sum()):,}  "
          f"processes={int(isproc.sum()):,}  malicious-processes={int((ymal&isproc).sum())}")

    explain_away_process(Xw2v, struct[:, 4].astype(int), ymal, isproc, mapp)

    # temporal split at median malicious first-seen ts
    cut = np.median(ts[ymal])
    tr, te = ts < cut, ts >= cut
    print(f"\ntemporal cut @ p50(mal ts): train={tr.sum():,} (pos {int(ymal[tr].sum())}) "
          f"test={te.sum():,} (pos {int(ymal[te].sum())})")
    Xc = Xw2v
    Xcs = np.hstack([Xw2v, struct])
    report_supervised("content-only (w2v30)", ymal[tr], Xc[tr], ymal[te], Xc[te], isproc[te])
    report_supervised("content+structural", ymal[tr], Xcs[tr], ymal[te], Xcs[te], isproc[te])

    incident_structure(ymal, edges, mapp, isproc)


if __name__ == "__main__":
    main()
