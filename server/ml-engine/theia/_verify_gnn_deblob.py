"""De-blob the THEIA GNN RAW metric: re-score the SAME FLASH-GNN flag set against
Orthrus-style ground-truth denominators instead of FLASH's 25k netflow-blob GT.

Question answered: is our honest RAW F1 0.836 aligned with Orthrus's "node-level
detection collapses to ~0"? Orthrus's THEIA_E3 GT is 118 curated system-level
attack entities (TN 699,177); FLASH's theia.json GT is 25,359 nodes, 99.7% netflow
(type code 3). We reuse the EXACT explain-away flags and only swap the GT denominator:

  full      = theia.json blob (25,359)         -> reproduces ~0.836
  no_netflow= drop type-3 GT (process+file+mem+principal)
  proc_file = type 0 (SUBJECT_PROCESS) + type 2 (FILE_OBJECT_BLOCK)  ~ Orthrus curation
  proc_only = type 0 only

Each sub-GT keeps the SAME flag set; FPs are alerts-not-in-(sub)GT, so flagging the
netflow blob becomes FP exactly as in Orthrus's denominator.

  PYTHONPATH=external/Flash-IDS THEIA_WEIGHTS=<flash> THEIA_GNN_CACHE=<flash cache> \
    python server/ml-engine/theia/_verify_gnn_deblob.py
"""
from __future__ import annotations
import json, os, pickle, time
from pathlib import Path
import numpy as np, torch
from torch_geometric import utils
from torch_geometric.data import Data
import theia_flash_common as fc
from _verify_gnn import featurize, run_explain_away, prf, get_adjacent, DATA_ROOT, CONF

NETFLOW = fc.DUMMIES["NetFlowObject"]      # 3
PROC = fc.DUMMIES["SUBJECT_PROCESS"]       # 0
FILEOBJ = fc.DUMMIES["FILE_OBJECT_BLOCK"]  # 2


def score(alert_ids, gt, all_ids, tag):
    tp = alert_ids & gt; fp = alert_ids - gt; fn = gt - alert_ids
    p, r, f = prf(len(tp), len(fp), len(fn))
    print(f"  {tag:<11} |GT|={len(gt):>6}  TP={len(tp):>5} FP={len(fp):>6} FN={len(fn):>6}  "
          f"P={p:0.4f} R={r:0.4f} F1={f:0.4f}")
    return f


def main():
    t0 = time.time()
    X, yte, edges, mapp, all_ids = featurize()
    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    GT.discard("")  # stray empty uuid in FLASH's GT file

    # uuid -> node type code (from labels array produced by the same featurization)
    uuid_type = {mapp[i]: int(t) for i, t in enumerate(yte)}
    gt_types = np.array([uuid_type.get(u, -1) for u in GT])
    print(f"GT={len(GT)}  type histogram: "
          f"proc={int((gt_types==PROC).sum())} mem={int((gt_types==1).sum())} "
          f"file={int((gt_types==FILEOBJ).sum())} netflow={int((gt_types==NETFLOW).sum())} "
          f"principal={int(((gt_types==4)|(gt_types==5)).sum())} unknown={int((gt_types==-1).sum())}",
          flush=True)

    g = Data(x=torch.tensor(X, dtype=torch.float),
             y=torch.tensor(yte, dtype=torch.long),
             edge_index=torch.tensor(edges, dtype=torch.long))
    g.n_id = torch.arange(g.num_nodes)
    flag, _ = run_explain_away(g, CONF)
    alert_ids = {mapp[x] for x in utils.mask_to_index(flag).tolist()}
    n_alert_proc = sum(1 for a in alert_ids if uuid_type.get(a) == PROC)
    print(f"\nflagged={len(alert_ids)} (of these proc={n_alert_proc})  conf={CONF}  "
          f"({time.time()-t0:.0f}s)\n")

    gt_no_nf = {u for u in GT if uuid_type.get(u) != NETFLOW}
    gt_pf = {u for u in GT if uuid_type.get(u) in (PROC, FILEOBJ)}
    gt_p = {u for u in GT if uuid_type.get(u) == PROC}

    print("=== RAW (no 2-hop) under different GT denominators ===")
    score(alert_ids, GT, all_ids, "full(blob)")
    score(alert_ids, gt_no_nf, all_ids, "no_netflow")
    score(alert_ids, gt_pf, all_ids, "proc_file")
    score(alert_ids, gt_p, all_ids, "proc_only")

    # 2-hop adjusted on proc_file, for contrast (Orthrus rejects this expansion)
    tp = alert_ids & gt_pf; fp = alert_ids - gt_pf; fn = gt_pf - alert_ids
    two_gp = get_adjacent(gt_pf, mapp, edges, 2); two_tp = get_adjacent(tp, mapp, edges, 2)
    p2, r2, f2 = prf(len(tp | (fn & two_tp)), len(fp - two_gp), len(fn - two_tp))
    print(f"\n  proc_file + 2-hop forgiveness -> P={p2:0.4f} R={r2:0.4f} F1={f2:0.4f} "
          f"(this is the trick Orthrus removes)")


if __name__ == "__main__":
    main()
