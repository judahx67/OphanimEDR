"""Train our Orthrus-style detector on a benign THEIA window.

Self-supervised edge-action reconstruction on benign provenance, then calibrate
the detection threshold as the worst (max) per-node reconstruction loss over a
HELD-OUT benign window (`max_val_loss`). Reuses FLASH's Word2Vec node features so
the comparison isolates model+objective+threshold.

Usage (from server/ml-engine/theia, with torch_geometric + gensim installed):
  python train_orthrus.py \
    --train external/Flash-IDS/theia_train.txt \
    --w2v   trained_weights/theia_ours_v3/word2vec_theia_E3.model \
    --out   trained_weights/theia_orthrus_v1 \
    --train-edges 300000 --val-edges 100000 --epochs 40
"""
from __future__ import annotations

import argparse
import json
import os
import time

import torch
import torch.nn.functional as F
from gensim.models import Word2Vec

import theia_flash_common as fc
import theia_orthrus_common as oc


def build_action_vocab(*dfs) -> dict:
    """id 0 reserved for <unk>; remaining actions enumerated from benign data."""
    actions = set()
    for df in dfs:
        actions.update(df["action"].unique().tolist())
    return {a: i + 1 for i, a in enumerate(sorted(actions))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="../../../external/Flash-IDS/theia_train.txt")
    ap.add_argument("--w2v", default="trained_weights/theia_ours_v3/word2vec_theia_E3.model")
    ap.add_argument("--out", default="trained_weights/theia_orthrus_v1")
    ap.add_argument("--train-edges", type=int, default=int(os.environ.get("ORTHRUS_TRAIN_EDGES", 300000)))
    ap.add_argument("--val-edges", type=int, default=int(os.environ.get("ORTHRUS_VAL_EDGES", 100000)))
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--lr", type=float, default=0.005)
    ap.add_argument("--seed", type=int, default=None,
                    help="torch RNG seed (init + any sampling); set for multi-seed variance runs")
    args = ap.parse_args()

    if args.seed is not None:
        torch.manual_seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"device={device}  seed={args.seed}")

    print("loading w2v...", flush=True)
    w2v = Word2Vec.load(args.w2v)
    enc = fc.PositionalEncoder()

    print(f"reading benign edges: train={args.train_edges:,} val={args.val_edges:,}", flush=True)
    df_all = oc.read_edge_txt(args.train, args.train_edges + args.val_edges)
    df_tr = df_all.iloc[: args.train_edges].reset_index(drop=True)
    df_va = df_all.iloc[args.train_edges:].reset_index(drop=True)
    print(f"  train rows={len(df_tr):,}  val rows={len(df_va):,}")

    action2id = build_action_vocab(df_tr, df_va)
    n_actions = len(action2id) + 1  # +1 for reserved <unk> id 0
    print(f"  action vocab: {n_actions} classes -> {list(action2id)[:8]}{'...' if n_actions > 8 else ''}")

    print("building graphs (w2v featurize)...", flush=True)
    x_tr, ei_tr, ea_tr, _, _ = oc.build_graph(df_tr, w2v, enc, action2id, device)
    x_va, ei_va, ea_va, _, _ = oc.build_graph(df_va, w2v, enc, action2id, device)
    print(f"  train graph: {x_tr.size(0):,} nodes / {ei_tr.size(1):,} edges")
    print(f"  val   graph: {x_va.size(0):,} nodes / {ei_va.size(1):,} edges")

    encoder = oc.OrthrusEncoder(fc.VECTOR_SIZE).to(device)
    decoder = oc.EdgeActionDecoder(oc.EMB_DIM, n_actions).to(device)
    opt = torch.optim.Adam(
        list(encoder.parameters()) + list(decoder.parameters()), lr=args.lr, weight_decay=5e-4
    )

    print("training (edge-action reconstruction)...", flush=True)
    t0 = time.time()
    for ep in range(1, args.epochs + 1):
        encoder.train(); decoder.train()
        opt.zero_grad()
        h = encoder(x_tr, ei_tr)
        logits = decoder(h, ei_tr)
        loss = F.cross_entropy(logits, ea_tr)
        loss.backward()
        opt.step()
        if ep % 5 == 0 or ep == 1:
            with torch.no_grad():
                acc = (logits.argmax(1) == ea_tr).float().mean().item()
            print(f"  epoch {ep:3d}  loss={loss.item():.4f}  edge-acc={acc:.3f}  ({time.time()-t0:.0f}s)", flush=True)

    # Calibrate the detection threshold on the held-out BENIGN window. Orthrus
    # names this max_val_loss (worst benign loss), but on a bounded benign
    # calibration set the pure max is dominated by a single outlier benign node
    # (it zeroes out detection). We therefore operate at the 99th-percentile
    # benign loss — an outlier-robust "max" — and keep p99.9/max for reference.
    encoder.eval(); decoder.eval()
    with torch.no_grad():
        h_va = encoder(x_va, ei_va)
        node_loss = oc.per_node_loss(h_va, ei_va, ea_va, decoder)
    q = torch.quantile(node_loss, torch.tensor([0.5, 0.9, 0.99, 0.999], device=device)).tolist()
    max_loss = float(node_loss.max().item())
    threshold = float(q[2])  # operating point = benign p99
    print(f"\nbenign val per-node loss: p50={q[0]:.4f} p90={q[1]:.4f} "
          f"p99={q[2]:.4f} p99.9={q[3]:.4f} max={max_loss:.4f}")
    print(f"operating threshold (benign p99) = {threshold:.4f}")

    os.makedirs(args.out, exist_ok=True)
    torch.save(encoder.state_dict(), os.path.join(args.out, "encoder.pth"))
    torch.save(decoder.state_dict(), os.path.join(args.out, "decoder.pth"))
    meta = {
        "action2id": action2id,
        "n_actions": n_actions,
        "threshold": threshold,            # operating point (benign p99)
        "calibration": {                   # benign loss distribution (held-out)
            "p99": float(q[2]), "p999": float(q[3]), "max_val_loss": max_loss,
        },
        "emb_dim": oc.EMB_DIM,
        "vector_size": fc.VECTOR_SIZE,
        "train_edges": args.train_edges,
        "val_edges": args.val_edges,
        "epochs": args.epochs,
        "seed": args.seed,
    }
    with open(os.path.join(args.out, "meta.json"), "w") as fw:
        json.dump(meta, fw, indent=2)
    print(f"saved encoder/decoder/meta -> {args.out}")


if __name__ == "__main__":
    main()
