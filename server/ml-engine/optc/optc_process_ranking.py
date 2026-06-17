"""A-2: process-level RANKING metrics for OpTC (recall@FP-budget, precision@k).

Committee critique A-2: the thesis summarizes process-level detection with RAW F1
(~0 everywhere), but F1 collapses only because thousands of file-node false
positives crush precision while process RECALL is non-trivial (0.14-0.63). F1 is
not what a triage analyst optimizes; a ranked queue cares about recall@FP-budget
and precision@k. This script recomputes those curves on the IDENTICAL per-host
caches/scores used by eval_process_level.py (the frozen B1/B5 result), so the
"~0" framing can be replaced with a deployment-relevant ranking story.

Pooled GLOBAL view (3 hosts, 99 malicious processes). Model B (supervised LOHO)
emits comparable probabilities so global pooling is clean; FLASH/Model A use
per-host-normalized explain-away scores, so for those we ALSO report a per-host
budget allocation (sum of per-host recall at a matched per-host FP budget) and
flag the pooling caveat.

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/optc_process_ranking.py
"""
from __future__ import annotations
import pickle
import numpy as np
import torch
from torch_geometric.data import Data
from gensim.models import Word2Vec

import optc_flash_common as fc
import eval_process_level as ev  # reuse frozen scoring (DRY): get_*_scores, SupSAGE, paths

HOSTS = ev.HOSTS
device = ev.device


def load_scores():
    """Return dict host -> {model -> (proc_scores, y_proc)} for process nodes only."""
    gt_all = set(ev.GT_TXT.read_text(encoding="utf-8").split())
    flash = fc.GCN().to(device)
    flash.load_state_dict(torch.load(ev.FLASH_GNN, map_location=device, weights_only=True))
    flash_w2v = Word2Vec.load(str(ev.FLASH_W2V))
    model_a = fc.GCN().to(device)
    model_a.load_state_dict(torch.load(ev.MODEL_A_GNN, map_location=device, weights_only=True))
    ours_w2v = Word2Vec.load(str(ev.OURS_W2V))
    enc = fc.PositionalEncoder()

    out = {}
    for host in HOSTS:
        c = pickle.load(open(ev.CODE_ROOT / f"_cache_{host}.pkl", "rb"))
        mapp, edges = c["mapp"], c["edges"]
        labels_type = np.array(c["labels"], dtype=np.int8)
        y_gt = np.array([1 if u in gt_all else 0 for u in mapp], dtype=np.int64)
        ei = torch.tensor(edges, dtype=torch.long)

        feats_flash = np.array([fc.infer(d, flash_w2v, enc) for d in c["node_docs"]], dtype=np.float32)
        g = Data(x=torch.tensor(feats_flash), edge_index=ei); g.n_id = torch.arange(g.num_nodes)
        s_flash, _, _ = ev.get_explain_away_scores(flash, g, labels_type)

        feats_ours = np.array([fc.infer(d, ours_w2v, enc) for d in c["node_docs"]], dtype=np.float32)
        g2 = Data(x=torch.tensor(feats_ours), edge_index=ei); g2.n_id = torch.arange(g2.num_nodes)
        s_a, _, _ = ev.get_explain_away_scores(model_a, g2, labels_type)

        mb = ev.SupSAGE().to(device)
        mb.load_state_dict(torch.load(ev.OURS_DIR / f"gnn_supervised_test{host}.pth",
                                      map_location=device, weights_only=True))
        g3 = Data(x=torch.tensor(feats_ours), edge_index=ei); g3.n_id = torch.arange(g3.num_nodes)
        s_b = ev.get_model_b_scores(mb, g3)

        isp = labels_type == 0
        out[host] = {
            "FLASH": (s_flash[isp], y_gt[isp]),
            "ModelA": (s_a[isp], y_gt[isp]),
            "ModelB": (s_b[isp], y_gt[isp]),
        }
    return out


def recall_at_fp_budget(scores, y, fp_budgets):
    """Sweep a global threshold; for each FP budget report processes recalled."""
    order = np.argsort(-scores, kind="mergesort")
    y_sorted = y[order]
    cum_tp = np.cumsum(y_sorted)
    cum_fp = np.cumsum(1 - y_sorted)
    res = {}
    for b in fp_budgets:
        idx = np.searchsorted(cum_fp, b, side="right") - 1
        res[b] = int(cum_tp[idx]) if idx >= 0 else 0
    return res


def precision_at_k(scores, y, ks):
    order = np.argsort(-scores, kind="mergesort")
    y_sorted = y[order]
    return {k: float(y_sorted[:k].sum()) / k for k in ks}


def main():
    sc = load_scores()
    total_mal = sum(int(sc[h]["ModelB"][1].sum()) for h in HOSTS)
    fp_budgets = [50, 100, 200, 500, 1000]
    ks = [10, 20, 50, 100, 200]
    print(f"total malicious processes across 3 hosts = {total_mal} (target 99)\n")

    for model in ["FLASH", "ModelA", "ModelB"]:
        # pooled global (clean for ModelB probs; approximate for explain-away)
        s = np.concatenate([sc[h][model][0] for h in HOSTS])
        y = np.concatenate([sc[h][model][1] for h in HOSTS])
        ratb = recall_at_fp_budget(s, y, fp_budgets)
        patk = precision_at_k(s, y, ks)
        print(f"[{model}] pooled global (n_proc={len(y):,}, mal={int(y.sum())})")
        print("  recall@FP-budget : " + "  ".join(f"{b}FP:{ratb[b]}/{total_mal}" for b in fp_budgets))
        print("  precision@k      : " + "  ".join(f"@{k}:{patk[k]:.3f}" for k in ks))

        # per-host budget allocation (score-scale-safe): matched per-host FP budget
        for per_host_fp in [50, 200]:
            rec = sum(recall_at_fp_budget(sc[h][model][0], sc[h][model][1], [per_host_fp])[per_host_fp]
                      for h in HOSTS)
            print(f"  sum-per-host recall @ {per_host_fp}FP/host (<= {3*per_host_fp} total FP): {rec}/{total_mal}")
        print()

    print("INTERPRETATION: replace 'RAW process F1 ~0 everywhere' with the ranking "
          "curve -- recall climbs with FP budget; the F1=0 headline is a precision "
          "artifact of thousands of file FPs, not zero recall. Report recall@budget.")


if __name__ == "__main__":
    main()
