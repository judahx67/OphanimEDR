"""Build the comparative ADP table from exported per-node score files.

Consumes the npz files produced by the various scorers (each with arrays `scores` and
`attack_ids`, benign = -1) and emits the headline artifact of the study: ADP per
(dataset, scorer), aggregated as mean ± relative-σ over seeds (Bilot SC5 protocol).

Expected filenames in --dir (flexible; unmatched files are skipped):
    adp_export_<DATASET>.npz                      -> scorer=orthrus, seed=na
    <scorer>_<DATASET>.npz                        -> seed=na
    <scorer>_<DATASET>_seed<N>.npz                -> seeded
e.g.  adp_export_CADETS_E3.npz, orthrus_CADETS_E3_seed4.npz,
      flash_THEIA_E3_seed2.npz, floor_CADETS_E3.npz, gat_THEIA_E3_seed1.npz

Usage:
    python build_adp_table.py --dir J:/THESIS-EDR/external/orthrus/artifacts
    python build_adp_table.py --dir <dir1> --dir <dir2>   # merge multiple sources
"""
from __future__ import annotations

import argparse
import glob
import os
import re
from collections import defaultdict

import numpy as np

from adp import compute_adp, relative_adp_std

# Known dataset tokens (longest-first so CADETS_E3 wins over a hypothetical CADETS).
DATASETS = ["CADETS_E3", "THEIA_E3", "CLEARSCOPE_E3", "CADETS_E5", "THEIA_E5", "CLEARSCOPE_E5", "OPTC"]


def parse_name(path: str):
    """-> (scorer, dataset, seed|None) or None if no dataset token is recognised."""
    base = os.path.basename(path)[: -len(".npz")]
    dataset = next((d for d in DATASETS if d in base), None)
    if dataset is None:
        return None
    rest = base.replace(dataset, "").strip("_")
    seed = None
    m = re.search(r"seed[_-]?(\d+)", rest)
    if m:
        seed = int(m.group(1))
        rest = rest[: m.start()].strip("_")
    scorer = rest.replace("adp_export", "orthrus").strip("_") or "orthrus"
    return scorer, dataset, seed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", action="append", required=True, help="dir(s) of *.npz (repeatable)")
    args = ap.parse_args()

    # (dataset, scorer) -> list of (seed, adp)
    groups: dict[tuple[str, str], list[tuple]] = defaultdict(list)
    for d in args.dir:
        for path in sorted(glob.glob(os.path.join(d, "*.npz"))):
            parsed = parse_name(path)
            if parsed is None:
                continue
            scorer, dataset, seed = parsed
            data = np.load(path)
            if "scores" not in data or "attack_ids" not in data:
                continue
            try:
                adp = compute_adp(data["scores"], data["attack_ids"])
            except ValueError as e:
                print(f"  skip {os.path.basename(path)}: {e}")
                continue
            groups[(dataset, scorer)].append((seed, adp))

    if not groups:
        print("No usable npz files found.")
        return

    datasets = sorted({k[0] for k in groups})
    scorers = sorted({k[1] for k in groups})

    print("\n# ADP comparison (mean +/- relative-sigma over seeds)\n")
    print("| Dataset | Scorer | n_seeds | mean ADP | rel_sigma_ADP | per-seed |")
    print("|---|---|---|---|---|---|")
    for dataset in datasets:
        for scorer in scorers:
            runs = groups.get((dataset, scorer))
            if not runs:
                continue
            adps = [a for _, a in runs]
            mean = float(np.mean(adps))
            sigma = relative_adp_std(adps) if len(adps) > 1 else 0.0
            per = ", ".join(
                f"s{seed}={a:.3f}" if seed is not None else f"{a:.3f}"
                for seed, a in sorted(runs, key=lambda t: (t[0] is None, t[0]))
            )
            print(f"| {dataset} | {scorer} | {len(adps)} | {mean:.4f} | {sigma:.3f} | {per} |")
    print()


if __name__ == "__main__":
    main()
