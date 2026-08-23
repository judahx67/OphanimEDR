"""B-4 ablation: does a *trained* reconstruction model beat the composition floor
when the GAT encoder is removed -- i.e. is C3's floor-equivalence a property of the
reconstruction paradigm, or an artifact of our under-trained GAT?

Committee critique B-4: C3 shows our Orthrus-style (GAT) detector does not exceed
the parameter-free composition floor within node type (rho 0.79-0.85, Process flags
floor-contained). A hostile reading is "your GAT was under-trained (edge-acc 0.81),
so it trivially regressed to the marginal action table." This ablation removes the
GAT entirely and trains a VELOX-class LINEAR edge-action model directly on the raw
Word2Vec endpoint features, then runs the IDENTICAL C3 control against the floor.

Two outcomes, both informative:
  - linear ALSO collapses to the floor within Process (rho ~ 0.8, flags contained):
    the floor-equivalence is not a GAT-undertraining artifact; it extends to a
    trained, embedding-based, VELOX-class model -> strengthens C3.
  - linear BEATS the floor (low within-Process rho, precise, distinct flags):
    the GAT result WAS an undertraining artifact -> C3's strong reading must be cut.

Same substrate as C3: same w2v features, same 300k benign train window, same 100k
benign p99 calibration, same 200k test split, same floor table. The ONLY change vs
the GAT detector is the encoder (identity / no GNN) and the decoder (single linear
layer over the two raw endpoint embeddings).

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/c3_linear_decoder_ablation.py
  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/c3_linear_decoder_ablation.py 120000
"""
from __future__ import annotations

import os
import sys
import time

import numpy as np
import torch
import torch.nn.functional as F
from gensim.models import Word2Vec

import theia_flash_common as fc
import theia_orthrus_common as oc
# reuse the EXACT C3 floor + stats so the comparison is apples-to-apples
import c3_composition_control as c3

HERE = os.path.dirname(os.path.abspath(__file__))
W2V_PATH = os.path.join(HERE, "trained_weights/theia_ours_v3/word2vec_theia_E3.model")
EXT = os.path.join(HERE, "../../../external/Flash-IDS")
TRAIN_TXT = os.path.join(EXT, "theia_train.txt")
TEST_TXT = os.path.join(EXT, "theia_test.txt")

N_TRAIN = 300_000
N_VAL = 100_000
N_EVAL = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
EPOCHS = int(os.environ.get("LIN_EPOCHS", 60))
LR = 0.01
SEED = int(os.environ.get("LIN_SEED", 0))


class LinearEdgeDecoder(torch.nn.Module):
    """VELOX-class: a single linear layer over the two endpoint embeddings.
    Signature matches oc.EdgeActionDecoder so oc.per_node_loss can reuse it with
    h = raw w2v features (no GNN encoder)."""

    def __init__(self, in_dim: int, n_actions: int):
        super().__init__()
        self.lin = torch.nn.Linear(in_dim * 2, n_actions)

    def forward(self, h, edge_index):
        return self.lin(torch.cat([h[edge_index[0]], h[edge_index[1]]], dim=1))


def build_action_vocab(*dfs) -> dict:
    actions = set()
    for df in dfs:
        actions.update(df["action"].unique().tolist())
    return {a: i + 1 for i, a in enumerate(sorted(actions))}


def main():
    torch.manual_seed(SEED)
    device = torch.device("cpu")
    print(f"LINEAR-decoder ablation (no GNN)  seed={SEED} epochs={EPOCHS}", flush=True)
    print(f"eval edges = {N_EVAL:,}  (train={N_TRAIN:,} calib={N_VAL:,})", flush=True)

    w2v = Word2Vec.load(W2V_PATH)
    enc = fc.PositionalEncoder()

    print("reading benign train/val...", flush=True)
    df_ben = oc.read_edge_txt(TRAIN_TXT, N_TRAIN + N_VAL)
    df_train = df_ben.iloc[:N_TRAIN].reset_index(drop=True)
    df_val = df_ben.iloc[N_TRAIN:].reset_index(drop=True)
    action2id = build_action_vocab(df_train, df_val)
    n_actions = len(action2id) + 1
    print(f"  action vocab: {n_actions} classes", flush=True)

    # build benign train/val graphs (raw w2v features; NO encoder)
    print("featurizing benign graphs...", flush=True)
    x_tr, ei_tr, ea_tr, _, _ = oc.build_graph(df_train, w2v, enc, action2id, device)
    x_va, ei_va, ea_va, _, _ = oc.build_graph(df_val, w2v, enc, action2id, device)

    decoder = LinearEdgeDecoder(fc.VECTOR_SIZE, n_actions).to(device)
    opt = torch.optim.Adam(decoder.parameters(), lr=LR, weight_decay=5e-4)

    print("training linear edge-action model on raw w2v endpoints...", flush=True)
    t0 = time.time()
    for ep in range(1, EPOCHS + 1):
        decoder.train()
        opt.zero_grad()
        logits = decoder(x_tr, ei_tr)          # h = raw features, no GNN
        loss = F.cross_entropy(logits, ea_tr)
        loss.backward()
        opt.step()
        if ep % 10 == 0 or ep == 1:
            with torch.no_grad():
                acc = (logits.argmax(1) == ea_tr).float().mean().item()
            print(f"  epoch {ep:3d}  loss={loss.item():.4f}  edge-acc={acc:.3f}  ({time.time()-t0:.0f}s)", flush=True)

    # calibrate benign p99 (same rule as the GAT detector + the floor)
    decoder.eval()
    with torch.no_grad():
        lin_va = oc.per_node_loss(x_va, ei_va, ea_va, decoder).cpu().numpy()
    floor_pair, floor_glob = c3.build_floor_table(df_train, action2id, n_actions)
    floor_va = c3.floor_per_node_loss(df_val, ei_va, x_va.size(0), floor_pair, floor_glob, action2id)
    lin_thr = float(np.quantile(lin_va, 0.99))
    floor_thr = float(np.quantile(floor_va, 0.99))
    print(f"\nlinear p99 = {lin_thr:.4f}   floor p99 = {floor_thr:.4f}", flush=True)

    # eval graph
    print("scoring eval split...", flush=True)
    df_ev = oc.read_edge_txt(TEST_TXT, N_EVAL)
    x, ei, ea, types, _ = oc.build_graph(df_ev, w2v, enc, action2id, device)
    types = types.cpu().numpy()
    with torch.no_grad():
        lin = oc.per_node_loss(x, ei, ea, decoder).cpu().numpy()
    floor = c3.floor_per_node_loss(df_ev, ei, x.size(0), floor_pair, floor_glob, action2id)

    lin_flag = lin > lin_thr
    floor_flag = floor > floor_thr
    n = len(lin)
    print(f"\neval nodes = {n:,}  linear flags = {lin_flag.sum():,}  floor flags = {floor_flag.sum():,}")

    lin_lab = c3.per_label_counts(lin_flag, types)
    fl_lab = c3.per_label_counts(floor_flag, types)
    print("\nper-label flag counts (flagged / total):")
    print(f"  {'label':8} {'linear':>16} {'floor':>16}")
    for lab in ["Process", "File", "Socket", "Memory", "User"]:
        lf, lt = lin_lab.get(lab, [0, 0])
        ff, ft = fl_lab.get(lab, [0, 0])
        if lt == 0 and ft == 0:
            continue
        print(f"  {lab:8} {lf:6}/{lt:<6} ({100*lf/max(lt,1):4.1f}%) {ff:6}/{ft:<6} ({100*ff/max(ft,1):4.1f}%)")

    both = (lin_flag & floor_flag).sum()
    jac = both / max((lin_flag | floor_flag).sum(), 1)
    print(f"\noverlap of flagged sets: both={both:,}  jaccard={jac:.3f}")
    print(f"  of linear flags, floor also flags: {100*both/max(lin_flag.sum(),1):.1f}%")
    print(f"spearman rho(linear, floor) over ALL eval nodes = {c3.spearman(lin, floor):.3f}")

    proc = types == 0
    if proc.sum() > 2:
        rho_proc = c3.spearman(lin[proc], floor[proc])
        lf = lin_flag[proc].sum(); ff = floor_flag[proc].sum()
        ov = (lin_flag[proc] & floor_flag[proc]).sum()
        contained = 100 * ov / max(lf, 1)
        print(f"\nWITHIN Process (n={proc.sum():,}) -- type held constant:")
        print(f"  linear flags={lf}  floor flags={ff}  overlap={ov}  (floor-contained {contained:.1f}%)")
        print(f"  spearman rho(linear, floor) among processes = {rho_proc:.3f}")

    print("\nVERDICT:")
    print("  rho_proc ~ 0.8 & Process flags floor-contained -> floor-equivalence is")
    print("    NOT a GAT-undertraining artifact; it extends to a trained VELOX-class")
    print("    linear model (B-4 confound closed, C3 strengthened).")
    print("  rho_proc low & linear precise/distinct -> GAT result was undertrained;")
    print("    cut C3's strong within-type reading.")


if __name__ == "__main__":
    main()
