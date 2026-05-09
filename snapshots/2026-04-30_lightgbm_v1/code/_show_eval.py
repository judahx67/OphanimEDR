"""Print permutation importance + headline metrics from both eval summaries."""
import json
from pathlib import Path

ROOT = Path(__file__).parent

for split in ("lgbm_xt_temporal", "lgbm_xt_stratified"):
    print("=" * 64)
    print(f"=== {split} ===")
    print("=" * 64)
    summary_path = ROOT / "models" / split / "eval" / "summary.json"
    with open(summary_path) as f:
        d = json.load(f)

    agg = d["aggregate"]
    print(f"  ROC-AUC      : {d['roc_auc']:.4f}")
    print(f"  PR-AUC       : {d['pr_auc']:.4f}")
    print(f"  F1           : {agg['f1']:.4f}")
    print(f"  Precision    : {agg['precision']:.4f}")
    print(f"  Recall       : {agg['recall']:.4f}")
    print(f"  Threshold    : {agg['threshold']:.3f}")
    print(f"  Test rows    : {agg['test_n']:,}  positive rate {agg['positive_rate']:.4f}")
    cm = d["confusion_matrix"]
    print(f"  CM           : tn={cm[0][0]:,}  fp={cm[0][1]:,}")
    print(f"                  fn={cm[1][0]:,}  tp={cm[1][1]:,}")

    print("\n  per-scenario recall:")
    for sid, st in d.get("per_scenario", {}).items():
        print(f"    {sid:35s} n={st['n_malicious']:>7,}  recall={st['recall']:.4f}")

    print("\n  per-sourcetype recall (top 12):")
    pst = sorted(d.get("per_sourcetype", {}).items(),
                 key=lambda x: -x[1]["n_malicious"])
    for st, info in pst[:12]:
        print(f"    {st:40s} n={info['n_malicious']:>7,}  recall={info['recall']:.4f}")

    print("\n  permutation importance (mean ROC-AUC drop when shuffled, top 20):")
    pi = sorted(d["permutation_importance"].items(),
                key=lambda x: -x[1]["mean"])
    total = sum(max(v["mean"], 0) for _, v in pi)
    for k, v in pi[:20]:
        share = (max(v["mean"], 0) / total * 100) if total > 0 else 0
        marker = "  <-- DOMINANT" if v["mean"] > 0.10 else ""
        print(f"    {k:30s} {v['mean']:+.5f} (+/-{v['std']:.5f})  share={share:5.1f}%{marker}")

    n_zero = sum(1 for _, v in pi if v["mean"] <= 0.001)
    print(f"\n  features with ~zero importance: {n_zero} / {len(pi)}")
    print()
