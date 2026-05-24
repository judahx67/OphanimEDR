"""Rewrite the 3 file-only derived columns in the existing featured Parquet
so they're populated only when object_type == 'File'. Avoids a 90-min full
extract_features re-run.

Operates on the temporal+stratified train/val/test splits already produced by
downsample.py, plus the all.parquet master.

Then retrains both honest models in-place.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import polars as pl

BASE = Path(__file__).parent
DATA_DIR = BASE / "data"
TARGETS = [
    DATA_DIR / "all.parquet",
    DATA_DIR / "temporal" / "train.parquet",
    DATA_DIR / "temporal" / "val.parquet",
    DATA_DIR / "temporal" / "test.parquet",
    DATA_DIR / "stratified" / "train.parquet",
    DATA_DIR / "stratified" / "val.parquet",
    DATA_DIR / "stratified" / "test.parquet",
]


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def patch_parquet(p: Path) -> None:
    log(f"Patching {p.name} ({p.stat().st_size/1e6:.0f} MB)")
    df = pl.read_parquet(p)
    is_file = pl.col("object_type") == "File"
    df = df.with_columns([
        pl.when(is_file).then(pl.col("object_name_ext")).otherwise(None).alias("object_name_ext"),
        pl.when(is_file).then(pl.col("object_basename")).otherwise(None).alias("object_basename"),
        pl.when(is_file).then(pl.col("target_dir")).otherwise(None).alias("target_dir"),
    ])
    tmp = p.with_suffix(".parquet.new")
    df.write_parquet(tmp, compression="zstd", compression_level=3)
    p.unlink()
    tmp.rename(p)
    n = df.height
    n_ext = int((df["object_name_ext"].is_not_null()).sum())
    log(f"  -> {n:,} rows, {n_ext:,} non-null object_name_ext "
        f"({100*n_ext/max(n,1):.2f}%)")


def main() -> int:
    for p in TARGETS:
        if not p.exists():
            log(f"SKIP (missing) {p}")
            continue
        patch_parquet(p)

    log("=== Retraining temporal (no_st) ===")
    subprocess.check_call(
        [sys.executable, "train.py", "--split", "temporal",
         "--drop-feature", "sourcetype", "--tag", "no_st"],
        cwd=BASE,
    )
    log("=== Retraining stratified (no_st) ===")
    subprocess.check_call(
        [sys.executable, "train.py", "--split", "stratified",
         "--drop-feature", "sourcetype", "--tag", "no_st"],
        cwd=BASE,
    )
    log("ALL DONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
