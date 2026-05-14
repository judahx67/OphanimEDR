"""Show permutation importance summaries for all four models, side by side."""
import json
from pathlib import Path

ROOT = Path(__file__).parent
MODELS = [
    "lgbm_xt_temporal",
    "lgbm_xt_temporal_no_st",
    "lgbm_xt_stratified",
    "lgbm_xt_stratified_no_st",
]

def load(name):
    p = ROOT / "models" / name / "eval" / "summary.json"
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)

print(f"{'feature':30s}", end="")
for m in MODELS:
    print(f"  {m.replace('lgbm_xt_',''):>22s}", end="")
print()
print("-" * 130)

datasets = {m: load(m) for m in MODELS}
all_features = set()
for d in datasets.values():
    if d:
        all_features.update(d["permutation_importance"].keys())

# Order by max importance across models
feat_order = sorted(
    all_features,
    key=lambda f: -max(
        d["permutation_importance"][f]["mean"] for d in datasets.values()
        if d and f in d["permutation_importance"]
    )
)

for f in feat_order[:20]:
    print(f"{f:30s}", end="")
    for m in MODELS:
        d = datasets[m]
        if not d or f not in d["permutation_importance"]:
            print(f"  {'-':>22s}", end="")
            continue
        v = d["permutation_importance"][f]["mean"]
        total = sum(max(x["mean"], 0) for x in d["permutation_importance"].values())
        share = (max(v, 0) / total * 100) if total else 0
        print(f"  {v:+.4f} ({share:4.1f}%)    ", end="")
    print()

print()
print("Feature concentration (share of top-N features):")
for n in (1, 3, 5, 10):
    print(f"  top-{n:>2d}", end="")
    for m in MODELS:
        d = datasets[m]
        if not d:
            print(f"  {'-':>22s}", end="")
            continue
        pi = sorted(d["permutation_importance"].items(), key=lambda x: -x[1]["mean"])
        total = sum(max(v["mean"], 0) for _, v in pi)
        share = sum(max(v["mean"], 0) for _, v in pi[:n]) / total * 100 if total else 0
        print(f"            {share:5.1f}%    ", end="")
    print()
