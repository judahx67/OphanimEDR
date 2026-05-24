r"""Build a Sysmon-only balanced training set + retrain.

Why: when Mordor positives (100% Sysmon) are mixed with BOTSv2 benigns
(mostly NOT Sysmon), the model learns trivial proxies for "this is Sysmon"
(subject_type=Process, event_id ∈ Sysmon range, image categorical) instead
of content. Forcing both classes to come from the same sourcetype removes
the shortcut.

Output: data/sysmon_balanced/{train,val,test}.parquet
Then retrains vanilla LightGBM and writes to models/lgbm_sysmon_balanced/.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import polars as pl

BASE = Path(__file__).parent
OUT = BASE / "data" / "sysmon_balanced"
SEED = 42
TRAIN_FRAC, VAL_FRAC = 0.6, 0.2  # test = 0.2


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def load_sysmon() -> pl.DataFrame:
    """Pull every featured Sysmon row from BOTSv2 + Mordor."""
    files = [
        Path("J:/THESIS-EDR/datasets/botsv2_features/sourcetype=XmlWinEventLog_Microsoft-Windows-Sysmon_Operational/featured.parquet"),
        Path("J:/THESIS-EDR/datasets/botsv2_features/sourcetype=mordor_sysmon/featured.parquet"),
    ]
    parts = []
    for f in files:
        if not f.exists():
            log(f"MISSING: {f}")
            continue
        df = pl.read_parquet(f)
        log(f"  read {f.parent.name:<60} rows={df.height:>9,} pos={int((df['label']==1).sum()):>7,}")
        parts.append(df)
    return pl.concat(parts, how="vertical_relaxed")


def stratified_split(df: pl.DataFrame) -> dict[str, pl.DataFrame]:
    # Shuffle deterministically per-label so each split keeps positive rate.
    pos = df.filter(pl.col("label") == 1).sample(fraction=1.0, shuffle=True, seed=SEED)
    neg = df.filter(pl.col("label") == 0).sample(fraction=1.0, shuffle=True, seed=SEED)

    def split(part):
        n = part.height
        n_tr = int(n * TRAIN_FRAC)
        n_val = int(n * VAL_FRAC)
        return part[:n_tr], part[n_tr:n_tr + n_val], part[n_tr + n_val:]

    p_tr, p_v, p_t = split(pos)
    n_tr, n_v, n_t = split(neg)
    out = {
        "train": pl.concat([p_tr, n_tr]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "val":   pl.concat([p_v, n_v]).sample(fraction=1.0, shuffle=True, seed=SEED),
        "test":  pl.concat([p_t, n_t]).sample(fraction=1.0, shuffle=True, seed=SEED),
    }
    return out


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    log("Loading Sysmon-only featured data...")
    df = load_sysmon()
    log(f"Total: {df.height:,}  positives: {int((df['label']==1).sum()):,}")

    splits = stratified_split(df)
    for name, sp in splits.items():
        path = OUT / f"{name}.parquet"
        sp.write_parquet(path, compression="zstd", compression_level=3)
        pos = int((sp["label"] == 1).sum())
        log(f"  wrote {name}: {sp.height:,} rows  ({pos:,} pos = {100*pos/sp.height:.1f}%)")

    # Override the train.py data path by symlinking sysmon_balanced into a
    # split name that train.py understands. Simpler: monkey-patch via a tmp
    # copy under data/stratified/ during the train run.
    # Cleanest: subprocess into train.py with --split stratified after
    # swapping the parquet files. Restore on completion.
    stratified = BASE / "data" / "stratified"
    backup = BASE / "data" / "stratified_pre_sysmon_balance"
    if not backup.exists():
        log(f"Backing up {stratified} -> {backup}")
        shutil.copytree(stratified, backup)

    log("Swapping sysmon_balanced into data/stratified for train.py...")
    for name in ("train", "val", "test"):
        src = OUT / f"{name}.parquet"
        dst = stratified / f"{name}.parquet"
        shutil.copy2(src, dst)

    log("=== Train vanilla LightGBM (no-xt, drop sourcetype + event_id) ===")
    rc = subprocess.call(
        [sys.executable, "train.py", "--split", "stratified",
         "--drop-feature", "sourcetype", "--drop-feature", "event_id",
         "--tag", "sysmon_balanced", "--no-xt"],
        cwd=BASE,
    )
    if rc != 0:
        log("train failed; restoring stratified backup")
        for name in ("train", "val", "test"):
            shutil.copy2(backup / f"{name}.parquet", stratified / f"{name}.parquet")
        return rc

    log("Restoring data/stratified from backup...")
    for name in ("train", "val", "test"):
        shutil.copy2(backup / f"{name}.parquet", stratified / f"{name}.parquet")

    log("DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
