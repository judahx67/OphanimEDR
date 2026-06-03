"""Novel-attack LightGBMXT for THEIA E3 -- NODE-scored, benign-1r-trained,
edge-emitting for Neo4j.

Honest novelty: trained ONLY on the benign 1r period (never sees an attack).
Learns the benign-node manifold via LightGBMXT density estimation (real benign
nodes vs uniform background negatives). On the 6r attack split it scores every
node; high anomaly = candidate attack. FLASH node GT (data_files/theia.json) is
used for EVALUATION ONLY.

A detected node maps to its incident provenance edges -> emit_cypher() returns the
Cypher to pull those edges from Neo4j. IsolationForest (benign-1r) is reported
alongside as the anomaly-detector reference.

Node features (built identically for 1r and 6r from the edge caches):
  - 30-dim mean Word2Vec over incident edges  (v2 w2v = benign-1r vocab)
  - out-degree, in-degree, node CDM type code

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/train_lgbm_novel.py
"""
from __future__ import annotations
import hashlib, json, os, pickle, time
from pathlib import Path
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
OUT = CODE_ROOT / "trained_weights/theia_novel"
SEED = 42
EMB = 30  # first EMB cols of edge X are the embedding


def node_feats(tag):
    """Aggregate edge cache -> per-node features (mean emb, out/in deg, type)."""
    z = np.load(DATA_ROOT / f"_edge_{tag}.npz", allow_pickle=True)
    X, actor, obj = z["X"], z["actor"], z["obj"]
    emb = X[:, :EMB].astype(np.float64)
    at = X[:, EMB].astype(int)        # actor type code
    ot = X[:, EMB + 1].astype(int)    # object type code
    # unique node ids
    ids, inv = np.unique(np.concatenate([actor, obj]), return_inverse=True)
    ai, oi = inv[:len(actor)], inv[len(actor):]
    n = len(ids)
    ssum = np.zeros((n, EMB)); cnt = np.zeros(n)
    np.add.at(ssum, ai, emb); np.add.at(cnt, ai, 1)
    np.add.at(ssum, oi, emb); np.add.at(cnt, oi, 1)
    mean_emb = ssum / np.clip(cnt[:, None], 1, None)
    outd = np.zeros(n); ind = np.zeros(n)
    np.add.at(outd, ai, 1); np.add.at(ind, oi, 1)
    tcode = np.zeros(n, dtype=int)
    tcode[ai] = at; tcode[oi] = ot   # last write wins; type is stable per node
    feats = np.hstack([mean_emb, np.log1p(outd)[:, None], np.log1p(ind)[:, None],
                       tcode[:, None]]).astype(np.float32)
    return feats, ids, actor, obj, z["action"], z["ts"]


def emit_cypher(actor, obj, action, ts):
    """Match the real graph-builder schema: nodes keyed by `uuid`, the edge's
    unique key is `event_id` = sha1(actor|obj|action|ts) (theia_normalizer._event_id)."""
    eid = hashlib.sha1(f"{actor}|{obj}|{action}|{int(ts)}".encode()).hexdigest()
    return (f"MATCH (s {{uuid:'{actor}'}})-[r {{event_id:'{eid}'}}]->(o {{uuid:'{obj}'}}) "
            f"RETURN s,r,o  // {action}")


def pr_at_recall(y, s, r):
    o = np.argsort(-s); ys = y[o]; tp = np.cumsum(ys); fp = np.cumsum(~ys)
    rec = tp / y.sum(); i = np.searchsorted(rec, r)
    return tp[i] / (tp[i] + fp[i]) if i < len(rec) else 0.0


def scores_report(name, y, s, isproc):
    apr = average_precision_score(y, s); roc = roc_auc_score(y, s)
    print(f"  [{name}] NODE  PR-AUC={apr:.4f} ROC={roc:.4f} "
          f"prec@90%rec={pr_at_recall(y,s,0.90):.3f} prec@99%rec={pr_at_recall(y,s,0.99):.3f}")
    if isproc.sum() and y[isproc].sum():
        apr2 = average_precision_score(y[isproc], s[isproc])
        print(f"  [{name}] PROC  PR-AUC={apr2:.4f} (mal-proc={int(y[isproc].sum())}/{int(isproc.sum())}) "
              f"prec@90%rec={pr_at_recall(y[isproc],s[isproc],0.90):.3f}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)
    t0 = time.time()
    Xtr, _, _, _, _, _ = node_feats("train")                       # benign 1r
    Xte, ids, e_actor, e_obj, e_action, e_ts = node_feats("test")  # attack 6r
    GT = set(u for u in json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")) if u)
    y = np.array([nid in GT for nid in ids])
    isproc = Xte[:, -1].astype(int) == 0   # type code 0 = SUBJECT_PROCESS
    print(f"train(1r) nodes={len(Xtr):,}  test(6r) nodes={len(Xte):,}  "
          f"malicious={int(y.sum()):,} ({y.mean()*100:.2f}%)  ({time.time()-t0:.0f}s)")

    # ---- LightGBMXT density: benign 1r nodes vs uniform background ----
    lo, hi = Xtr.min(0), Xtr.max(0)
    Xbg = rng.uniform(lo, hi, size=Xtr.shape).astype(np.float32)
    Xpu = np.vstack([Xtr, Xbg]); ypu = np.r_[np.ones(len(Xtr)), np.zeros(len(Xbg))]
    clf = LGBMClassifier(extra_trees=True, boosting_type="gbdt", n_estimators=400,
                         learning_rate=0.05, num_leaves=63, min_child_samples=50,
                         random_state=SEED, n_jobs=-1, verbose=-1)
    clf.fit(Xpu, ypu)
    pickle.dump(clf, open(OUT / "lgbm_xt_novel_E3.pkl", "wb"))
    anom_lgbm = 1.0 - clf.predict_proba(Xte)[:, 1]

    # ---- IsolationForest reference (benign 1r) ----
    iff = IsolationForest(n_estimators=300, random_state=SEED, n_jobs=-1).fit(Xtr)
    anom_if = -iff.score_samples(Xte)

    base = y.mean()
    print(f"\n=== NOVEL-ATTACK DETECTION (benign-1r trained, test=6r attack) ===")
    print(f"  base rate={base:.4f}")
    scores_report("LightGBMXT-density", y, anom_lgbm, isproc)
    scores_report("IsolationForest", y, anom_if, isproc)

    # ---- top LightGBM detections -> incident edges -> Neo4j ----
    flagged = ids[np.argsort(-anom_lgbm)[:200]]
    fset = set(flagged)
    print(f"\ntop detected nodes -> incident edges (Neo4j). showing first 8 edges of flagged MALICIOUS nodes:")
    shown = 0
    for a, o, act, ts in zip(e_actor, e_obj, e_action, e_ts):
        if shown >= 8: break
        if (a in fset and a in GT) or (o in fset and o in GT):
            print(f"  {emit_cypher(a, o, act, ts)}")
            shown += 1
    print(f"\nsaved model -> {OUT/'lgbm_xt_novel_E3.pkl'}")


if __name__ == "__main__":
    main()
