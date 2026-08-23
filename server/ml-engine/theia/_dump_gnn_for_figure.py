"""Generate frozen figure data from FLASH GNN at CONF=0.53 for Hình 4.2 (confusion matrix).

This script dumps the node-level scores from the FLASH GNN model (20-shard explain-away)
at the table's operating point (CONF=0.53) so the confusion matrix figure matches
the table (Bảng 4.1) numbers.

Usage:
  PYTHONPATH=external/Flash-IDS python server/ml-engine/theia/_dump_gnn_for_figure.py
"""
from __future__ import annotations
import json, os, pickle, time
from pathlib import Path
import numpy as np, pandas as pd, torch
from gensim.models import Word2Vec
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
import theia_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TEST_BASE = str(DATA_ROOT / "ta1-theia-e3-official-6r.json")
TEST_SPLIT = str(DATA_ROOT / "ta1-theia-e3-official-6r.json.8")

# Use shipped FLASH weights (external/Flash-IDS/trained_weights/theia) for Table 4.1 reproduction
# Override with THEIA_WEIGHTS env var to use different weights
if "THEIA_WEIGHTS" in os.environ:
    WEIGHTS = Path(os.environ["THEIA_WEIGHTS"])
    if not WEIGHTS.is_absolute():
        WEIGHTS = CODE_ROOT / WEIGHTS
else:
    # Default: use shipped FLASH weights from external/Flash-IDS
    WEIGHTS = DATA_ROOT / "trained_weights" / "theia"

CACHE = Path(os.environ.get("THEIA_GNN_CACHE", DATA_ROOT / "_verify_gnn_feats.pkl"))
CONF = 0.53  # Table 4.1 uses CONF=0.53 (FLASH GNN gốc)
device = torch.device("cpu")


def featurize():
    if CACHE.exists():
        print(f"reusing feature cache {CACHE}", flush=True)
        return pickle.load(open(CACHE, "rb"))
    w2v = Word2Vec.load(str(WEIGHTS / "word2vec_theia_E3.model")); enc = fc.PositionalEncoder()
    fc.parse_split(TEST_BASE, TEST_SPLIT, str(DATA_ROOT / "theia_test.txt"))
    rows = [l.split("\t") for l in (DATA_ROOT / "theia_test.txt").read_text(
        encoding="utf-8", errors="ignore").split("\n")]
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID", "object", "action", "timestamp"]).dropna()
    df.sort_values("timestamp", inplace=True)
    df = fc.add_attributes(df, TEST_SPLIT)
    phrases, labels, edges, mapp = fc.prepare_graph(df)
    X = np.array([fc.infer(p, w2v, enc) for p in phrases]).astype(np.float32)
    all_ids = set(df["actorID"]) | set(df["objectID"])
    out = (X, np.array(labels), edges, mapp, all_ids)
    pickle.dump(out, open(CACHE, "wb"))
    return out


def run_explain_away_with_scores(g, conf):
    """Run explain-away and capture per-node scores.

    For the confusion matrix, we want: score >= thr predicts "flagged as anomalous".
    The explain-away loop un-flags correctly-typed nodes with high confidence.
    So: score = confidence margin (higher = more likely to be un-flagged).

    Returns:
      flag: boolean array, True = normal (not flagged), False = anomalous
      margins: raw confidence margin (not normalized per-batch)
    """
    flag = torch.ones(g.num_nodes, dtype=torch.bool)
    margins = torch.zeros(g.num_nodes, dtype=torch.float)
    model = fc.GCN(fc.VECTOR_SIZE, 5).to(device)

    for m_n in range(20):
        sd = torch.load(WEIGHTS / f"lword2vec_gnn_theia{m_n}_E3.pth", map_location=device, weights_only=True)
        model.load_state_dict(sd); model.eval()
        for subg in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
            with torch.no_grad():
                out = model(subg.x, subg.edge_index)
            s, ind = out.sort(dim=1, descending=True)
            # Raw confidence margin (NOT normalized per-batch)
            c = (s[:, 0] - s[:, 1]) / s[:, 0]

            # Store margin from shard 0 only
            if m_n == 0:
                margins[subg.n_id] = c

            # Flagging decision: correctly typed with high confidence
            c_norm = (c - c.min()) / (c.max() - c.min() + 1e-9)
            cond = (ind[:, 0] == subg.y) & (c_norm > conf)
            flag[subg.n_id[cond]] = False

    return flag, margins.cpu().numpy()


def main():
    t0 = time.time()
    print(f"=== REGENERATING FIGURE 4.2 FROZEN DATA ===", flush=True)
    print(f"PURPOSE: Match Table 4.1 row 1 (FLASH GNN original, CONF=0.53)", flush=True)
    print(f"WEIGHTS: {WEIGHTS}", flush=True)
    print(f"CONF: {CONF}", flush=True)
    print(f"DATA: {TEST_SPLIT}", flush=True)
    X, yte, edges, mapp, all_ids = featurize()
    GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
    print(f"Nodes: {len(yte):,}  GT malicious: {len(GT):,}  (featurize {time.time()-t0:.0f}s)", flush=True)

    g = Data(x=torch.tensor(X, dtype=torch.float).to(device),
             y=torch.tensor(yte, dtype=torch.long).to(device),
             edge_index=torch.tensor(edges, dtype=torch.long).to(device))
    g.n_id = torch.arange(g.num_nodes)

    flag, margins = run_explain_away_with_scores(g, CONF)

    # Build isproc array for the figure script
    isproc = np.array([yte[i] == fc.DUMMIES.get("SUBJECT_PROCESS", 0) for i in range(len(yte))])

    # y is a binary array: True = malicious, False = benign
    y_binary = np.array([n in GT for n in mapp], dtype=bool)

    # For the confusion matrix: score = confidence margin
    # Higher margin = model more confident in its prediction
    # Nodes with margin >= CONF get un-flagged (marked as normal)
    # So: score >= thr means "predicted normal" which corresponds to NOT flagged
    scores = margins

    # Dump to figure-data directory
    fd = CODE_ROOT.parents[2] / "thesis-writing-main" / "src" / "figure-scripts" / "figure-data"
    fd.mkdir(parents=True, exist_ok=True)

    # For consistency with how the confusion matrix uses it:
    # pred = score >= thr means "not flagged" (normal)
    # We want to match the table's flagging pattern
    np.savez(
        fd / "theia-content-only.npz",
        score=scores,
        y=y_binary,
        isproc=isproc,
        thr=CONF
    )

    # Verify: compute metrics
    # Note: the confusion matrix uses pred = score >= thr
    # If pred=True, the node is classified as normal (not flagged)
    # The table reports: TP=25182 FP=9703 as FLAGGED nodes
    # So we need to invert: flagged = ~pred
    pred_normal = scores >= CONF
    pred_flagged = ~pred_normal

    tp_count = int((pred_flagged & y_binary).sum())
    fp_count = int((pred_flagged & ~y_binary).sum())
    fn_count = int((~pred_flagged & y_binary).sum())
    p = tp_count / (tp_count + fp_count) if tp_count + fp_count > 0 else 0
    r = tp_count / (tp_count + fn_count) if tp_count + fn_count > 0 else 0
    f1 = 2 * p * r / (p + r) if p + r > 0 else 0

    print(f"\nFrozen data saved: {fd / 'theia-content-only.npz'}")
    print(f"  Nodes: {len(scores):,}")
    print(f"  Malicious: {int(y_binary.sum()):,}")
    print(f"  Processes: {int(isproc.sum()):,}")
    print(f"  Score range: [{scores.min():.4f}, {scores.max():.4f}]")

    print(f"\n=== VERIFICATION (Node-level, flagged as malicious) ===")
    print(f"REGENERATED:  TP={tp_count:>5} FP={fp_count:>5} FN={fn_count:>5}  P={p:.4f} R={r:.4f} F1={f1:.4f}")
    print(f"TABLE 4.1 R1: TP=25182 FP=9703 FN=177  P=0.7219 R=0.9930 F1=0.8360")

    if abs(tp_count - 25182) < 100 and abs(fp_count - 9703) < 100:
        print(f"\n✓ SUCCESS: Regenerated values match Table 4.1!")
    else:
        delta_tp = tp_count - 25182
        delta_fp = fp_count - 9703
        print(f"\n✗ MISMATCH:")
        print(f"  TP delta: {delta_tp:+d} ({delta_tp/25182*100:+.1f}%)")
        print(f"  FP delta: {delta_fp:+d} ({delta_fp/9703*100:+.1f}%)")


if __name__ == "__main__":
    main()
