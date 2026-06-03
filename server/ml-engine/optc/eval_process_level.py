"""Process-level evaluation script for OpTC.
Evaluates:
  1. FLASH's shipped GNN (pretrained on OpTC, explain-away anomaly detection)
  2. Model A: our self-supervised replica GNN (explain-away anomaly detection)
  3. Model B: our supervised LOHO GraphSAGE (malicious vs benign probability)

Filters for process nodes (node type label == 0) and computes:
  - PR-AUC, ROC-AUC, Base rate.
  - Process-level True Positives, False Positives, False Negatives, Precision, Recall, F1.
  - Total malicious processes recalled across hosts.

Run with:
  RESEARCH/.venv/Scripts/python.exe server/ml-engine/optc/eval_process_level.py
"""
from __future__ import annotations
import os, pickle, time
from pathlib import Path
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import average_precision_score, roc_auc_score
from torch_geometric import utils
from torch_geometric.data import Data
from torch_geometric.loader import NeighborLoader
from gensim.models import Word2Vec

import optc_flash_common as fc

CODE_ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("OPTC_DATA", CODE_ROOT.parents[2] / "external" / "Flash-IDS" / "_optc_gt"))
FLASH_DIR = CODE_ROOT.parents[2] / "external" / "Flash-IDS"
GT_TXT = FLASH_DIR / "data_files" / "optc.txt"

# Models and Weights
FLASH_GNN = FLASH_DIR / "trained_weights" / "optc" / "gnn_temp.pth"
FLASH_W2V = DATA / "w2v_optc.model"

OURS_DIR = CODE_ROOT / "trained_weights" / "optc_ours"
MODEL_A_GNN = OURS_DIR / "gnn_selfsup_optc.pth"
OURS_W2V = OURS_DIR / "w2v_optc_ours.model"

device = torch.device("cpu")
HOSTS = ["0051", "0201", "0501"]


class SupSAGE(torch.nn.Module):
    """Same encoder as fc.GCN (SAGEConv 20->32->20) + binary head."""
    def __init__(self):
        super().__init__()
        self.conv1 = fc.SAGEConv(fc.VECTOR_SIZE, 32, normalize=True)
        self.conv2 = fc.SAGEConv(32, fc.VECTOR_SIZE, normalize=True)
        self.head = torch.nn.Linear(fc.VECTOR_SIZE, 2)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=0.5, training=self.training)
        x = self.conv2(x, edge_index)
        return self.head(x)


@torch.no_grad()
def get_model_b_scores(model, g):
    model.eval()
    out = torch.zeros(g.num_nodes)
    for b in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        p = F.softmax(model(b.x, b.edge_index), dim=1)[:, 1]
        out[b.n_id] = p.cpu()
    return out.numpy()


@torch.no_grad()
def get_explain_away_scores(model, g, y):
    model.eval()
    pred = torch.zeros(g.num_nodes, dtype=torch.long)
    conf = torch.zeros(g.num_nodes)
    for b in NeighborLoader(g, num_neighbors=[-1, -1], batch_size=5000):
        out = model(b.x, b.edge_index)
        s, ind = out.sort(dim=1, descending=True)
        c = (s[:, 0] - s[:, 1]) / s[:, 0]
        pred[b.n_id] = ind[:, 0].cpu()
        conf[b.n_id] = c.cpu()
    
    # Normalize confidence to [0, 1]
    cmin, cmax = conf.min(), conf.max()
    conf = (conf - cmin) / (cmax - cmin + 1e-9)
    
    # Anomaly score: 1.0 - conf if pred == y, else 1.0
    # Higher score = more anomalous
    pred_y = pred.numpy()
    conf_y = conf.numpy()
    
    anomaly_scores = np.where(pred_y == y, 1.0 - conf_y, 1.0)
    return anomaly_scores, pred_y, conf_y


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def evaluate_process_level(host, y_gt, labels_type, scores, model_name, method_type):
    # Process-level filter (labels_type == 0 corresponds to PROCESS nodes)
    is_proc = (labels_type == 0)
    total_proc = int(is_proc.sum())
    
    y_proc = y_gt[is_proc]
    scores_proc = scores[is_proc]
    mal_proc_count = int(y_proc.sum())
    
    if mal_proc_count == 0:
        return {
            "prauc": float("nan"), "rocauc": float("nan"), "base_rate": 0.0,
            "best_f1": 0.0, "best_tp": 0, "best_fp": 0, "best_fn": 0,
            "best_p": 0.0, "best_r": 0.0, "best_thr": 0.0
        }
        
    prauc = average_precision_score(y_proc, scores_proc)
    rocauc = roc_auc_score(y_proc, scores_proc)
    base_rate = y_proc.mean()
    
    # Sweep thresholds to find best F1
    best_f1 = -1.0
    best_metrics = (0, 0, 0, 0.0, 0.0, 0.0)
    
    # Evaluate at multiple percentiles of the anomaly scores
    thrs = np.unique(np.quantile(scores_proc, np.linspace(0.0, 1.0, 200)))
    for thr in thrs:
        pred_bin = scores_proc >= thr
        tp = int((pred_bin & y_proc).sum())
        fp = int((pred_bin & ~y_proc).sum())
        fn = int((~pred_bin & y_proc).sum())
        p, r, f = prf(tp, fp, fn)
        if f > best_f1:
            best_f1 = f
            best_metrics = (tp, fp, fn, p, r, thr)
            
    tp, fp, fn, p, r, thr = best_metrics
    
    return {
        "prauc": prauc, "rocauc": rocauc, "base_rate": base_rate,
        "best_f1": best_f1, "best_tp": tp, "best_fp": fp, "best_fn": fn,
        "best_p": p, "best_r": r, "best_thr": thr, "mal_proc_count": mal_proc_count,
        "total_proc": total_proc
    }


def main():
    print("=== STARTING PROCESS-LEVEL GO/NO-GO EVALUATION ===")
    gt_all = set(GT_TXT.read_text(encoding="utf-8").split())
    print(f"Total global ground truth UUIDs: {len(gt_all)}")
    
    # 1. Load architectures
    # FLASH GNN
    flash_model = fc.GCN().to(device)
    flash_model.load_state_dict(torch.load(FLASH_GNN, map_location=device, weights_only=True))
    flash_w2v = Word2Vec.load(str(FLASH_W2V))
    
    # Model A GNN
    model_a = fc.GCN().to(device)
    model_a.load_state_dict(torch.load(MODEL_A_GNN, map_location=device, weights_only=True))
    ours_w2v = Word2Vec.load(str(OURS_W2V))
    
    enc = fc.PositionalEncoder()
    
    results = {}
    
    for host in HOSTS:
        print(f"\nEvaluating Host {host}...")
        # Load cache
        cache_path = CODE_ROOT / f"_cache_{host}.pkl"
        c = pickle.load(open(cache_path, "rb"))
        mapp = c["mapp"]
        labels_type = np.array(c["labels"], dtype=np.int8)  # 0=PROCESS, etc.
        edges = c["edges"]
        
        # Ground truth labels
        y_gt = np.array([1 if u in gt_all else 0 for u in mapp], dtype=np.int64)
        
        # A. Evaluate FLASH
        # Featurize using FLASH W2V
        feats_flash = np.array([fc.infer(doc, flash_w2v, enc) for doc in c["node_docs"]], dtype=np.float32)
        g_flash = Data(x=torch.tensor(feats_flash), edge_index=torch.tensor(edges, dtype=torch.long))
        g_flash.n_id = torch.arange(g_flash.num_nodes)
        
        flash_scores, _, _ = get_explain_away_scores(flash_model, g_flash, labels_type)
        res_flash = evaluate_process_level(host, y_gt, labels_type, flash_scores, "FLASH (Shipped)", "Explain-Away")
        
        # B. Evaluate Model A (Self-supervised replica)
        # Featurize using our W2V
        feats_ours = np.array([fc.infer(doc, ours_w2v, enc) for doc in c["node_docs"]], dtype=np.float32)
        g_ours = Data(x=torch.tensor(feats_ours), edge_index=torch.tensor(edges, dtype=torch.long))
        g_ours.n_id = torch.arange(g_ours.num_nodes)
        
        model_a_scores, _, _ = get_explain_away_scores(model_a, g_ours, labels_type)
        res_model_a = evaluate_process_level(host, y_gt, labels_type, model_a_scores, "Model A (Our Self-sup)", "Explain-Away")
        
        # C. Evaluate Model B (Supervised LOHO)
        # Load fold model for Model B
        model_b_weights = OURS_DIR / f"gnn_supervised_test{host}.pth"
        model_b = SupSAGE().to(device)
        model_b.load_state_dict(torch.load(model_b_weights, map_location=device, weights_only=True))
        
        g_model_b = Data(x=torch.tensor(feats_ours), y=torch.tensor(y_gt, dtype=torch.long),
                         edge_index=torch.tensor(edges, dtype=torch.long))
        g_model_b.n_id = torch.arange(g_model_b.num_nodes)
        
        model_b_scores = get_model_b_scores(model_b, g_model_b)
        res_model_b = evaluate_process_level(host, y_gt, labels_type, model_b_scores, "Model B (Supervised LOHO)", "Supervised")
        
        results[host] = {
            "FLASH": res_flash,
            "Model A": res_model_a,
            "Model B": res_model_b
        }
        
        # Print summary for host
        print(f"Host {host} stats: Total Processes = {res_flash['total_proc']:,}, Malicious Processes = {res_flash['mal_proc_count']}")
        for m_name, res in [("FLASH (Shipped)", res_flash), ("Model A (Self-sup)", res_model_a), ("Model B (Supervised LOHO)", res_model_b)]:
            print(f"  {m_name:<25} -> Base: {res['base_rate']:.6f} | PR-AUC: {res['prauc']:.4f} | ROC-AUC: {res['rocauc']:.4f}")
            print(f"    Best F1: {res['best_f1']:.4f} @ thr {res['best_thr']:.4f} (TP {res['best_tp']} / FP {res['best_fp']} / FN {res['best_fn']})")

    # Overall Summary across all hosts
    print("\n" + "="*50)
    print("=== GLOBAL PROCESS-LEVEL GO/NO-GO SUMMARY ===")
    print("="*50)
    
    total_mal_proc = sum(results[h]["FLASH"]["mal_proc_count"] for h in HOSTS)
    print(f"Total malicious processes across all hosts: {total_mal_proc} (Target: 99)")
    
    # Calculate globally recalled malicious processes at best F1 thresholds
    for m_key, m_name in [("FLASH", "FLASH (Shipped)"), ("Model A", "Model A (Self-supervised)"), ("Model B", "Model B (Supervised LOHO)")]:
        recalled = 0
        total_fps = 0
        for host in HOSTS:
            res = results[host][m_key]
            recalled += res["best_tp"]
            total_fps += res["best_fp"]
        
        recall_rate = recalled / total_mal_proc if total_mal_proc else 0.0
        print(f"\n{m_name}:")
        print(f"  Recalled processes: {recalled}/{total_mal_proc} ({recall_rate*100:.1f}%)")
        print(f"  Total False Positives: {total_fps:,}")
        
        # Decision check
        if m_key == "Model B":
            avg_prauc = np.nanmean([results[h][m_key]["prauc"] for h in HOSTS])
            avg_base = np.nanmean([results[h][m_key]["base_rate"] for h in HOSTS])
            lift = avg_prauc / avg_base if avg_base else 0.0
            print(f"  Average PR-AUC: {avg_prauc:.4f} vs Average Base Rate: {avg_base:.6f} ({lift:.1f}x lift)")
            
            if recall_rate >= 0.50 and avg_prauc > 10 * avg_base:
                print("  Verdict: Model B PASSES the Phase 1 Go/No-Go check!")
            else:
                print("  Verdict: Model B FAILS the Phase 1 Go/No-Go check. Honest negative confirmed.")

    # Write logs to file
    log_content = []
    log_content.append("=== OpTC PROCESS-LEVEL EVALUATION LOG ===")
    for host in HOSTS:
        log_content.append(f"\n--- Host {host} ---")
        log_content.append(f"Total Processes: {results[host]['FLASH']['total_proc']:,} | Malicious Processes: {results[host]['FLASH']['mal_proc_count']}")
        for m_key, m_name in [("FLASH", "FLASH (Shipped)"), ("Model A", "Model A (Self-supervised)"), ("Model B", "Model B (Supervised LOHO)")]:
            res = results[host][m_key]
            log_content.append(f"  {m_name}:")
            log_content.append(f"    PR-AUC: {res['prauc']:.4f} | ROC-AUC: {res['rocauc']:.4f} | Base Rate: {res['base_rate']:.6f}")
            log_content.append(f"    Best F1: {res['best_f1']:.4f} (TP {res['best_tp']} / FP {res['best_fp']} / FN {res['best_fn']}) @ thr {res['best_thr']:.4f}")
            
    log_content.append("\n" + "="*50)
    log_content.append("=== GLOBAL VERDICT SUMMARY ===")
    for m_key, m_name in [("FLASH", "FLASH (Shipped)"), ("Model A", "Model A (Self-supervised)"), ("Model B", "Model B (Supervised LOHO)")]:
        recalled = sum(results[h][m_key]["best_tp"] for h in HOSTS)
        fps = sum(results[h][m_key]["best_fp"] for h in HOSTS)
        log_content.append(f"  {m_name}: Recalled {recalled}/{total_mal_proc} ({recalled/total_mal_proc*100:.1f}%) | FPs {fps:,}")
        
    (CODE_ROOT / "_eval_process_level_optc.log").write_text("\n".join(log_content), encoding="utf-8")
    print("\nLogs written to _eval_process_level_optc.log")


if __name__ == "__main__":
    main()
