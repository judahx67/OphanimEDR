"""B-8 control: composition floor vs our OWN positive (THEIA content detector).

Committee critique B-8: the thesis applies its composition-floor control to the
rival Orthrus-style detector (C3) and to the rejected PCSA, but never to its OWN
surviving positive -- the supervised content detector at node PR-AUC 0.9929
(results-frozen A3). The honesty discipline the thesis demands of others requires
running the same control against its own win.

Floor = a parameter-free node-type frequency lookup P(malicious | node-type),
estimated on the train half and read off on the test half, under the IDENTICAL
label-agnostic temporal split as A3 (F.3). We compare node-level PR-AUC / ROC of:
  (a) composition floor (node-type only, parameter-free)
  (b) content-only (w2v30)        -- reproduces A3
  (c) content + structural
The honest residual of the content detector is (content) - (floor).

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/b8_floor_vs_own_positive.py
"""
from __future__ import annotations
import os
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score
from lightgbm import LGBMClassifier

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
CACHE = DATA_ROOT / "_eval_cache.npz"


def content_clf():
    return LGBMClassifier(extra_trees=True, boosting_type="gbdt", n_estimators=300,
                          learning_rate=0.05, num_leaves=31, min_child_samples=20,
                          class_weight="balanced", random_state=42, n_jobs=-1, verbose=-1)


def freq_floor_scores(type_code_tr, y_tr, type_code_te):
    """Parameter-free floor: P(malicious | node-type) with Laplace smoothing,
    learned on train, applied to test. No embeddings, no model fitting."""
    mal = defaultdict(float)
    tot = defaultdict(float)
    for t, y in zip(type_code_tr, y_tr):
        tot[int(t)] += 1.0
        if y:
            mal[int(t)] += 1.0
    glob = (y_tr.sum() + 1.0) / (len(y_tr) + 2.0)
    rate = {t: (mal[t] + 1.0) / (tot[t] + 2.0) for t in tot}
    return np.array([rate.get(int(t), glob) for t in type_code_te], dtype=np.float64)


def node_and_proc(name, s, yte, isproc_te):
    apr = average_precision_score(yte, s)
    roc = roc_auc_score(yte, s)
    line = f"  {name:30} NODE PR-AUC={apr:.4f} ROC={roc:.4f}"
    pm = isproc_te
    apr_p = float("nan")
    if yte[pm].sum() > 0:
        apr_p = average_precision_score(yte[pm], s[pm])
        line += f" | PROCESS PR-AUC={apr_p:.4f} (mal proc={int(yte[pm].sum())})"
    print(line, flush=True)
    return apr, roc, apr_p


def supervised_scores(Xtr, ytr, Xte):
    clf = content_clf()
    clf.fit(Xtr, ytr)
    return clf.predict_proba(Xte)[:, 1]


def main():
    z = np.load(CACHE, allow_pickle=True)
    Xw2v, struct, ymal, ts, isproc = z["Xw2v"], z["struct"], z["ymal"], z["ts"], z["isproc"]
    # struct columns: [out_deg, in_deg, n_out_nbr, n_in_nbr, type_code]; col 4 = node-type code
    type_code = struct[:, 4]
    cut = np.median(ts[ts > 0])  # label-AGNOSTIC cut == A3 headline (F.3)
    tr, te = ts < cut, ts >= cut
    print(f"label-agnostic temporal cut @ {int(cut)}: "
          f"train={tr.sum():,} (pos {int(ymal[tr].sum())}) "
          f"test={te.sum():,} (pos {int(ymal[te].sum())})")
    print(f"nodes={len(ymal):,} malicious={int(ymal.sum()):,} "
          f"processes={int(isproc.sum()):,} mal-proc-in-test={int((ymal&isproc&te).sum())}\n")

    # node-type composition of the test-half ground truth (the thing the floor exploits)
    by = defaultdict(int)
    for t, y in zip(type_code[te], ymal[te]):
        if y:
            by[int(t)] += 1
    print(f"  test-half malicious nodes by type-code: {dict(sorted(by.items()))}\n")

    s_floor = freq_floor_scores(type_code[tr], ymal[tr], type_code[te])
    apr_f, roc_f, aprp_f = node_and_proc("composition floor (type only)", s_floor, ymal[te], isproc[te])

    s_content = supervised_scores(Xw2v[tr], ymal[tr], Xw2v[te])
    apr_c, roc_c, aprp_c = node_and_proc("content-only (w2v30)", s_content, ymal[te], isproc[te])

    Xcs = np.hstack([Xw2v, struct])
    s_cs = supervised_scores(Xcs[tr], ymal[tr], Xcs[te])
    node_and_proc("content+structural", s_cs, ymal[te], isproc[te])

    print(f"\nRESIDUAL of content-only over its parameter-free composition floor:")
    print(f"  NODE PR-AUC: {apr_c:.4f} - {apr_f:.4f} = {apr_c - apr_f:+.4f}")
    print(f"  NODE ROC   : {roc_c:.4f} - {roc_f:.4f} = {roc_c - roc_f:+.4f}")
    print("\nINTERPRETATION: a small positive residual means most of the headline "
          "0.99 is node-type composition (malicious == netflow/file), not learned "
          "content -- the same floor caveat the thesis applies to rivals, applied "
          "to its own positive.")


if __name__ == "__main__":
    main()
