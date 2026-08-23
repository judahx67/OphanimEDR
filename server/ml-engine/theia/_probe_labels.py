"""Feasibility probe for a SUPERVISED malicious/benign LightGBMXT on THEIA.

No model. Just answers the split-design questions from the cached edge file:
  - how many distinct nodes are malicious (in data_files/theia.json) vs benign
  - per-node first-seen timestamp distribution, malicious vs benign
  - does the attack span a wide window (temporal split viable) or a narrow one?
  - node-type breakdown of malicious nodes (are they separable by content at all?)

  RESEARCH/.venv/Scripts/python.exe server/ml-engine/theia/_probe_labels.py
"""
from __future__ import annotations
import json, os
from collections import defaultdict
from pathlib import Path
import numpy as np

CODE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", CODE_ROOT.parents[2] / "external" / "Flash-IDS"))
TEST_TXT = DATA_ROOT / "theia_test.txt"

GT = set(json.load(open(DATA_ROOT / "data_files/theia.json", encoding="utf-8")))
first_ts, ntype = {}, {}
with open(TEST_TXT, encoding="utf-8", errors="ignore") as f:
    for line in f:
        p = line.rstrip("\n").split("\t")
        if len(p) != 6:
            continue
        a, at, o, ot, _, ts = p
        try:
            t = int(ts)
        except ValueError:
            continue
        for nid, ty in ((a, at), (o, ot)):
            if nid not in first_ts or t < first_ts[nid]:
                first_ts[nid] = t
            ntype.setdefault(nid, ty)

nodes = list(first_ts)
mal = np.array([n in GT for n in nodes])
ts = np.array([first_ts[n] for n in nodes], dtype=np.int64)
print(f"distinct nodes={len(nodes):,}  malicious={mal.sum():,} ({mal.mean()*100:.2f}%)  "
      f"GT not-in-graph={len(GT - set(nodes)):,}")

def pct(arr, label):
    if len(arr) == 0:
        print(f"  {label}: (none)"); return
    q = np.percentile(arr, [0, 10, 50, 90, 100]).astype(np.int64)
    span_h = (q[-1] - q[0]) / 1e9 / 3600
    print(f"  {label:<10} n={len(arr):>7,}  span={span_h:6.1f}h  "
          f"min..p10..p50..p90..max(ns): {list(q)}")

print("\nfirst-seen timestamp distribution:")
pct(ts[mal], "malicious")
pct(ts[~mal], "benign")

# overlap: does malicious window sit inside benign window? (temporal-split viability)
if mal.any():
    mlo, mhi = ts[mal].min(), ts[mal].max()
    frac_benign_before = (ts[~mal] < mlo).mean()
    frac_benign_after = (ts[~mal] > mhi).mean()
    print(f"\n  benign nodes BEFORE first malicious: {frac_benign_before*100:.1f}%")
    print(f"  benign nodes AFTER  last  malicious: {frac_benign_after*100:.1f}%")
    print(f"  -> if a temporal cut at p50(mal) leaves positives on both sides, temporal split is viable")
    cut = np.median(ts[mal])
    print(f"     malicious before/after p50-mal cut: {(ts[mal]<cut).sum():,} / {(ts[mal]>=cut).sum():,}")

print("\nnode-type breakdown of MALICIOUS nodes (FLASH dummies-ish):")
by = defaultdict(int)
for n in nodes:
    if n in GT:
        by[ntype[n]] += 1
for k, v in sorted(by.items(), key=lambda x: -x[1]):
    print(f"  {k:<22}{v:>7,}")
