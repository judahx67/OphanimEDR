"""PHASE 1 confounder check — does the 20-dim w2v NO-GO reflect lossy features or no signal?

train_content_supervised.py (mean-pooled 20-dim w2v) was a NO-GO at process level. That
representation averages a node's tokens into 20 dims, destroying discriminative command-line/
path tokens, and the w2v saw attack data (no OOV mechanism). This script re-tests with a RICHER
content representation: path-SUBTOKENIZED TF-IDF over each node's raw token doc (so cross-host
shared components like 'powershell.exe', 'temp', 'appdata' survive), + LightGBM-XT.

Two regimes separate the two hypotheses:
  LOHO  (cross-host, leave-one-host-out)  -> tests cross-host transfer.
  WITHIN(per-host stratified 70/30 split) -> tests whether content separates malicious PROCESSES
                                             at all when train/test share vocabulary.
If WITHIN also fails => content carries no process signal (robust NO-GO). If WITHIN works but
LOHO fails => signal exists, doesn't transfer (host-specific identifiers). Process-level, RAW.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/eval_content_tfidf_process.py
"""
from __future__ import annotations
import os, pickle, re
from pathlib import Path
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

CODE_ROOT = Path(__file__).resolve().parent
GT_TXT = CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "data_files" / "optc.txt"
N_EST = int(os.environ.get("GNN_ESTIMATORS", "300"))
MAXF = int(os.environ.get("TFIDF_MAXF", "8000"))
HOSTS = ["0051", "0201", "0501"]
PROCESS = 0
_SPLIT = re.compile(r"[\\/.:\-_]+")
np.random.seed(42)


def subtokenize(tokens):
    """Split path/identifier tokens into shared components; drop pure numbers (ports) and
    long host-specific hex; lowercase. Gives cross-host vocabulary a fair chance."""
    out = []
    for t in tokens:
        for p in _SPLIT.split(t.lower()):
            if p and not p.isdigit() and len(p) < 40:
                out.append(p)
    return " ".join(out)


def load_host(host, gt_all):
    c = pickle.load(open(CODE_ROOT / f"_cache_{host}.pkl", "rb"))
    docs = [subtokenize(d) for d in c["node_docs"]]
    ybin = np.array([1 if u in gt_all else 0 for u in c["mapp"]], dtype=np.int64)
    ntype = np.array(c["labels"], dtype=np.int64)
    return docs, ybin, ntype


def fit_score(docs_tr, ytr, docs_te):
    vec = TfidfVectorizer(max_features=MAXF, token_pattern=r"\S+")
    Xtr = vec.fit_transform(docs_tr); Xte = vec.transform(docs_te)
    spw = (ytr == 0).sum() / max((ytr == 1).sum(), 1)
    clf = LGBMClassifier(boosting_type="gbdt", extra_trees=True, n_estimators=N_EST,
                         learning_rate=0.05, num_leaves=31, min_child_samples=20,
                         scale_pos_weight=spw, n_jobs=-1, verbose=-1)
    clf.fit(Xtr, ytr)
    return clf.predict_proba(Xte)[:, 1]


def report(y, score, tag):
    base = y.mean()
    prauc = average_precision_score(y, score) if y.sum() else float("nan")
    roc = roc_auc_score(y, score) if 0 < y.sum() < len(y) else float("nan")
    order = np.argsort(score)[::-1]
    rec = {}
    for fpb in (10, 50, 100):
        fpc = tpc = 0
        for i in order:
            if y[i] == 1: tpc += 1
            else:
                fpc += 1
                if fpc > fpb: break
        rec[fpb] = tpc / y.sum() if y.sum() else 0
    return (f"  {tag:<22} pos={int(y.sum()):>4}/{len(y):>6} base={base:.4f} "
            f"PR-AUC={prauc:.4f} ROC={roc:.4f} lift={prauc/base if base else 0:.1f}x "
            f"R@10fp={rec[10]:.3f} R@50fp={rec[50]:.3f} R@100fp={rec[100]:.3f}")


def main():
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    data = {h: load_host(h, gt_all) for h in HOSTS}
    log = [f"=== PHASE 1 confounder: path-subtokenized TF-IDF (max_features={MAXF}) + LightGBM-XT, "
           f"PROCESS-level, RAW ==="]

    log.append("\n--- REGIME A: LOHO (cross-host transfer) ---")
    for test_h in HOSTS:
        tr = [h for h in HOSTS if h != test_h]
        docs_tr = sum([data[h][0] for h in tr], []); ytr = np.concatenate([data[h][1] for h in tr])
        docs_te, yte, ntype_te = data[test_h]
        s = fit_score(docs_tr, ytr, docs_te)
        pmask = ntype_te == PROCESS
        log.append(f"[test={test_h}]")
        log.append(report(yte, s, "NODE(all)"))
        log.append(report(yte[pmask], s[pmask], "PROCESS"))
        print("\n".join(log[-3:]), flush=True)

    log.append("\n--- REGIME B: WITHIN-host stratified 70/30 (shared vocab, signal test) ---")
    for h in HOSTS:
        docs, y, ntype = data[h]
        idx = np.arange(len(y))
        itr, ite = train_test_split(idx, test_size=0.3, random_state=42, stratify=y)
        s_te = np.zeros(len(y))
        s_te[ite] = fit_score([docs[i] for i in itr], y[itr], [docs[i] for i in ite])
        pmask = np.zeros(len(y), bool); pmask[ite] = ntype[ite] == PROCESS
        log.append(f"[host={h}]")
        log.append(report(y[ite], s_te[ite], "NODE(all,test)"))
        log.append(report(y[pmask], s_te[pmask], "PROCESS(test)"))
        print("\n".join(log[-3:]), flush=True)

    (CODE_ROOT / "_eval_content_tfidf_process.log").write_text("\n".join(log), encoding="utf-8")
    print("\nDONE -> _eval_content_tfidf_process.log", flush=True)


if __name__ == "__main__":
    main()
