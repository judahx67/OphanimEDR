"""C3 composition-floor control for the Orthrus-style detector.

Question under test (thesis critique C3): is our Orthrus detector's flag
distribution (concentrating onto Process/Socket nodes that FLASH floods past) a
LEARNED anomaly signal, or is it reproducible from node-type/action COMPOSITION
alone -- i.e. the same node-type-composition floor the thesis already documents?

Control = a parameter-free scorer that predicts each edge's action using ONLY
P(action | actor_type, object_type) estimated from benign training data. No
embeddings, no GNN. Per-node score = mean -log P over incident edges, exactly
the aggregation Orthrus uses. Both scorers run on the IDENTICAL eval graph and
are thresholded at their own benign p99 (calibrated on the same benign window).

If the floor reproduces Orthrus's per-label flag profile AND flags the same
nodes (high overlap, high rank correlation), Orthrus adds nothing over
composition -> the "precision" is an artifact. If Orthrus flags markedly
different nodes -- especially WITHIN the Process class, where the type effect is
held constant -- it is learning something beyond composition.

Run (from server/ml-engine/theia, CPU is fine):
  python c3_composition_control.py            # eval=200k test edges
  python c3_composition_control.py 120000     # match the demo scale
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

import numpy as np
import torch
from gensim.models import Word2Vec

import theia_flash_common as fc
import theia_orthrus_common as oc

HERE = os.path.dirname(os.path.abspath(__file__))
W2V_PATH = os.path.join(HERE, "trained_weights/theia_ours_v3/word2vec_theia_E3.model")
WEIGHTS = os.path.join(HERE, os.environ.get("ORTHRUS_WEIGHTS", "trained_weights/theia_orthrus_v1"))
EXT = os.path.join(HERE, "../../../external/Flash-IDS")
TRAIN_TXT = os.path.join(EXT, "theia_train.txt")
TEST_TXT = os.path.join(EXT, "theia_test.txt")

N_TRAIN = 300_000   # benign edges Orthrus was trained on -> composition table
N_VAL = 100_000     # held-out benign window -> p99 calibration (both scorers)
N_EVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000

# DUMMIES type code -> Neo4j-style label (see fc.DUMMIES)
CODE2LABEL = {0: "Process", 1: "Memory", 2: "File", 3: "Socket", 4: "User", 5: "User"}


def _avg_ranks(x: np.ndarray) -> np.ndarray:
    """Average (midrank) ranks -- ties get the mean of their rank span.
    The floor's scores are heavily tied (finite composition table), so plain
    argsort-argsort ranking assigns arbitrary distinct ranks to ties and
    biases rho (reviewer critique R3)."""
    order = np.argsort(x, kind="mergesort")
    ranks = np.empty(len(x), dtype=np.float64)
    sx = x[order]
    i = 0
    while i < len(sx):
        j = i
        while j + 1 < len(sx) and sx[j + 1] == sx[i]:
            j += 1
        ranks[order[i:j + 1]] = 0.5 * (i + j)  # midrank of the tie block
        i = j + 1
    return ranks


def spearman(a: np.ndarray, b: np.ndarray) -> float:
    """Tie-corrected Spearman rho: Pearson on midranks."""
    ra, rb = _avg_ranks(a), _avg_ranks(b)
    ra -= ra.mean(); rb -= rb.mean()
    denom = np.sqrt((ra * ra).sum() * (rb * rb).sum())
    return float((ra * rb).sum() / denom) if denom else 0.0


def build_floor_table(df, action2id, n_actions):
    """P(action_id | actor_type, object_type) with +1 Laplace smoothing.

    Returns (pair_logp dict, global_logp) where each is a length-n_actions
    log-probability vector. Unknown actions fold into id 0 (Orthrus convention).
    """
    pair = defaultdict(lambda: np.ones(n_actions))   # Laplace prior
    glob = np.ones(n_actions)
    a_types = df["actor_type"].tolist()
    o_types = df["object"].tolist()
    actions = df["action"].tolist()
    for at, ot, ac in zip(a_types, o_types, actions):
        aid = action2id.get(ac, 0)
        pair[(at, ot)][aid] += 1.0
        glob[aid] += 1.0
    pair_logp = {k: np.log(v / v.sum()) for k, v in pair.items()}
    global_logp = np.log(glob / glob.sum())
    return pair_logp, global_logp


def floor_per_node_loss(df, edge_index, n_nodes, pair_logp, global_logp, action2id):
    """Mean -log P(action|types) aggregated onto each node, same as Orthrus."""
    a_types = df["actor_type"].tolist()
    o_types = df["object"].tolist()
    actions = df["action"].tolist()
    per_edge = np.empty(len(df), dtype=np.float64)
    for i, (at, ot, ac) in enumerate(zip(a_types, o_types, actions)):
        lp = pair_logp.get((at, ot), global_logp)
        per_edge[i] = -lp[action2id.get(ac, 0)]
    pe = torch.tensor(per_edge, dtype=torch.float64)
    loss_sum = torch.zeros(n_nodes, dtype=torch.float64)
    cnt = torch.zeros(n_nodes, dtype=torch.float64)
    ones = torch.ones_like(pe)
    for end in (edge_index[0], edge_index[1]):
        loss_sum.index_add_(0, end, pe)
        cnt.index_add_(0, end, ones)
    return (loss_sum / cnt.clamp(min=1)).numpy()


def per_label_counts(flagged_mask, types):
    out = defaultdict(lambda: [0, 0])  # label -> [flagged, total]
    for t, f in zip(types, flagged_mask):
        lab = CODE2LABEL.get(int(t), "User")
        out[lab][1] += 1
        if f:
            out[lab][0] += 1
    return out


def main():
    device = torch.device("cpu")
    print(f"eval edges = {N_EVAL:,}  (train={N_TRAIN:,} calib={N_VAL:,})", flush=True)

    meta = json.load(open(os.path.join(WEIGHTS, "meta.json")))
    action2id, n_actions = meta["action2id"], meta["n_actions"]
    meta_thr = meta["threshold"]

    print("loading w2v + weights...", flush=True)
    w2v = Word2Vec.load(W2V_PATH)
    enc = fc.PositionalEncoder()
    encoder = oc.OrthrusEncoder(fc.VECTOR_SIZE).to(device)
    decoder = oc.EdgeActionDecoder(oc.EMB_DIM, n_actions).to(device)
    encoder.load_state_dict(torch.load(os.path.join(WEIGHTS, "encoder.pth"), map_location=device))
    decoder.load_state_dict(torch.load(os.path.join(WEIGHTS, "decoder.pth"), map_location=device))
    encoder.eval(); decoder.eval()

    # ---- benign data: composition table + calibration window ----
    print("reading benign train/val...", flush=True)
    df_ben = oc.read_edge_txt(TRAIN_TXT, N_TRAIN + N_VAL)
    df_train = df_ben.iloc[:N_TRAIN].reset_index(drop=True)
    df_val = df_ben.iloc[N_TRAIN:].reset_index(drop=True)
    pair_logp, global_logp = build_floor_table(df_train, action2id, n_actions)
    print(f"  composition table: {len(pair_logp)} (actor_type,object_type) pairs", flush=True)

    # calibrate BOTH thresholds on the same held-out benign window
    print("calibrating p99 on benign val window...", flush=True)
    x_va, ei_va, ea_va, _, _ = oc.build_graph(df_val, w2v, enc, action2id, device)
    with torch.no_grad():
        orth_va = oc.per_node_loss(encoder(x_va, ei_va), ei_va, ea_va, decoder).cpu().numpy()
    floor_va = floor_per_node_loss(df_val, ei_va, x_va.size(0), pair_logp, global_logp, action2id)
    orth_thr = float(np.quantile(orth_va, 0.99))
    floor_thr = float(np.quantile(floor_va, 0.99))
    print(f"  orthrus p99 = {orth_thr:.4f}  (meta threshold = {meta_thr:.4f})")
    print(f"  floor   p99 = {floor_thr:.4f}")

    # ---- eval graph (held-out test split): score both ----
    print("building eval graph + scoring both detectors...", flush=True)
    df_ev = oc.read_edge_txt(TEST_TXT, N_EVAL)
    x, ei, ea, types, _ = oc.build_graph(df_ev, w2v, enc, action2id, device)
    types = types.cpu().numpy()
    with torch.no_grad():
        orth = oc.per_node_loss(encoder(x, ei), ei, ea, decoder).cpu().numpy()
    floor = floor_per_node_loss(df_ev, ei, x.size(0), pair_logp, global_logp, action2id)

    orth_flag = orth > orth_thr
    floor_flag = floor > floor_thr
    n = len(orth)
    print(f"\neval nodes = {n:,}  orthrus flags = {orth_flag.sum():,}  floor flags = {floor_flag.sum():,}")

    # ---- per-label flag profile ----
    oc_lab = per_label_counts(orth_flag, types)
    fl_lab = per_label_counts(floor_flag, types)
    print("\nper-label flag counts (flagged / total):")
    print(f"  {'label':8} {'orthrus':>16} {'floor':>16}")
    for lab in ["Process", "File", "Socket", "Memory", "User"]:
        of, ot = oc_lab.get(lab, [0, 0])
        ff, ft = fl_lab.get(lab, [0, 0])
        if ot == 0 and ft == 0:
            continue
        print(f"  {lab:8} {of:6}/{ot:<6} ({100*of/max(ot,1):4.1f}%) {ff:6}/{ft:<6} ({100*ff/max(ft,1):4.1f}%)")

    # ---- agreement / overlap ----
    both = (orth_flag & floor_flag).sum()
    jac = both / max((orth_flag | floor_flag).sum(), 1)
    rho_all = spearman(orth, floor)
    print(f"\noverlap of flagged sets: both={both:,}  jaccard={jac:.3f}")
    print(f"  of orthrus flags, floor also flags: {100*both/max(orth_flag.sum(),1):.1f}%")
    print(f"  of floor   flags, orthrus also flags: {100*both/max(floor_flag.sum(),1):.1f}%")
    print(f"spearman rho(orthrus, floor) over ALL eval nodes = {rho_all:.3f}")

    # ---- WITHIN-Process control (type effect held constant) ----
    proc = types == 0
    if proc.sum() > 2:
        rho_proc = spearman(orth[proc], floor[proc])
        of = orth_flag[proc].sum(); ff = floor_flag[proc].sum()
        ov = (orth_flag[proc] & floor_flag[proc]).sum()
        print(f"\nWITHIN Process (n={proc.sum():,}) -- type held constant:")
        print(f"  orthrus flags={of}  floor flags={ff}  overlap={ov}")
        print(f"  spearman rho(orthrus, floor) among processes = {rho_proc:.3f}")

    print("\nINTERPRETATION:")
    print("  high rho + high overlap + matching per-label profile -> Orthrus == composition floor (artifact).")
    print("  low within-Process rho / different processes flagged   -> Orthrus adds learned signal.")


if __name__ == "__main__":
    main()
