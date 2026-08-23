"""C3 flag-budget sweep (reviewer critique R5).

The C3 control compares the Orthrus-style detector and the composition floor at
ONE operating point (benign p99 each). A hostile reading: "you compared two
arbitrary operating points." This sweep re-runs the comparison across a grid of
benign calibration budgets (p90..p99.9) and reports, per budget:
  - within-Process flag counts for both scorers,
  - their overlap, and the number of SUBSET VIOLATIONS (processes the detector
    flags that the floor does not),
  - per-label flag totals.
If the detector's Process flags remain a subset of the floor's across budgets,
the strict-subset finding is a property of the scorers, not of the p99 choice.
Scores are computed ONCE per scorer; only the threshold moves -> cheap.

Run (from server/ml-engine/theia, CPU):
  python c3_budget_sweep.py                 # eval=200k test edges, v1 weights
  ORTHRUS_WEIGHTS=trained_weights/theia_orthrus_s1 python c3_budget_sweep.py
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np
import torch
from gensim.models import Word2Vec

import theia_flash_common as fc
import theia_orthrus_common as oc
from c3_composition_control import (
    CODE2LABEL, N_TRAIN, N_VAL, TEST_TXT, TRAIN_TXT, W2V_PATH, WEIGHTS,
    build_floor_table, floor_per_node_loss, per_label_counts, spearman,
)

N_EVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
BUDGETS = [0.90, 0.95, 0.99, 0.995, 0.999]


def main():
    device = torch.device("cpu")
    print(f"eval edges = {N_EVAL:,}  budgets = {BUDGETS}  weights = {WEIGHTS}", flush=True)

    meta = json.load(open(os.path.join(WEIGHTS, "meta.json")))
    action2id, n_actions = meta["action2id"], meta["n_actions"]

    print("loading w2v + weights...", flush=True)
    w2v = Word2Vec.load(W2V_PATH)
    enc = fc.PositionalEncoder()
    encoder = oc.OrthrusEncoder(fc.VECTOR_SIZE).to(device)
    decoder = oc.EdgeActionDecoder(oc.EMB_DIM, n_actions).to(device)
    encoder.load_state_dict(torch.load(os.path.join(WEIGHTS, "encoder.pth"), map_location=device))
    decoder.load_state_dict(torch.load(os.path.join(WEIGHTS, "decoder.pth"), map_location=device))
    encoder.eval(); decoder.eval()

    print("benign composition table + calibration scores...", flush=True)
    df_ben = oc.read_edge_txt(TRAIN_TXT, N_TRAIN + N_VAL)
    df_train = df_ben.iloc[:N_TRAIN].reset_index(drop=True)
    df_val = df_ben.iloc[N_TRAIN:].reset_index(drop=True)
    pair_logp, global_logp = build_floor_table(df_train, action2id, n_actions)

    x_va, ei_va, ea_va, _, _ = oc.build_graph(df_val, w2v, enc, action2id, device)
    with torch.no_grad():
        orth_va = oc.per_node_loss(encoder(x_va, ei_va), ei_va, ea_va, decoder).cpu().numpy()
    floor_va = floor_per_node_loss(df_val, ei_va, x_va.size(0), pair_logp, global_logp, action2id)

    print("eval graph scores (computed once)...", flush=True)
    df_ev = oc.read_edge_txt(TEST_TXT, N_EVAL)
    x, ei, ea, types, _ = oc.build_graph(df_ev, w2v, enc, action2id, device)
    types = types.cpu().numpy()
    with torch.no_grad():
        orth = oc.per_node_loss(encoder(x, ei), ei, ea, decoder).cpu().numpy()
    floor = floor_per_node_loss(df_ev, ei, x.size(0), pair_logp, global_logp, action2id)

    proc = types == 0
    rho_proc = spearman(orth[proc], floor[proc])
    print(f"\neval nodes = {len(orth):,}  Process n = {int(proc.sum())}  "
          f"within-Process rho = {rho_proc:.3f} (budget-independent)")

    print("\nbudget   orth-thr floor-thr | Proc: orth floor overlap VIOLATIONS | total: orth floor")
    for b in BUDGETS:
        othr = float(np.quantile(orth_va, b))
        fthr = float(np.quantile(floor_va, b))
        of_, ff_ = orth > othr, floor > fthr
        po, pf = of_ & proc, ff_ & proc
        ov = int((po & pf).sum())
        viol = int((po & ~pf).sum())  # detector-only Process flags = subset violations
        print(f"  p{100*b:<5.1f} {othr:8.3f} {fthr:8.3f} |"
              f" {int(po.sum()):6} {int(pf.sum()):6} {ov:7} {viol:10} |"
              f" {int(of_.sum()):6} {int(ff_.sum()):6}", flush=True)

    # per-label detail at the extreme budgets, to see where divergence lives
    for b in (BUDGETS[0], BUDGETS[-1]):
        othr = float(np.quantile(orth_va, b))
        fthr = float(np.quantile(floor_va, b))
        oc_lab = per_label_counts(orth > othr, types)
        fl_lab = per_label_counts(floor > fthr, types)
        print(f"\nper-label at p{100*b:.1f} (flagged/total)  orthrus | floor:")
        for lab in ["Process", "File", "Socket", "Memory", "User"]:
            o = oc_lab.get(lab, [0, 0]); f_ = fl_lab.get(lab, [0, 0])
            if o[1] == 0 and f_[1] == 0:
                continue
            print(f"  {lab:8} {o[0]:6}/{o[1]:<6} | {f_[0]:6}/{f_[1]:<6}")

    print("\nINTERPRETATION: VIOLATIONS == 0 at every budget -> the strict-subset "
          "finding is budget-independent; >0 -> report at which budgets it breaks.")


if __name__ == "__main__":
    main()
