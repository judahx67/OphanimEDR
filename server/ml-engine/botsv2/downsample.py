"""Phase 5: Stratified downsample to ~3M rows + DUAL split strategy.

Memory-conservative design (hard cap: 7 GB RSS, asserted at runtime):
- Pass 0:  build union arrow schema by scanning each partition's header
- Pass 1:  stream malicious rows into mal_buffer.parquet, count benign per sourcetype
- Pass 2:  per-sourcetype proportional benign sampling -> ben_buffer.parquet
- Combine: stream both buffers row-group-at-a-time -> all.parquet (no full materialize)
- Split:   compute boundaries from a tiny scalar pass, then stream all.parquet
           row-group-at-a-time and route each row to its split file. NEVER load
           the full sampled DataFrame into RAM.

TWO split families produced:
    temporal   60/20/20 by _time (real-world deployment realism)
    stratified 60/20/20 random, stratified by label (uniform positive rate)

Outputs (under data/):
    all.parquet                          — full ~3M sampled dataset
    temporal/{train,val,test}.parquet    — temporal split
    stratified/{train,val,test}.parquet  — random label-stratified split
    split_summary.json                   — stats for both families
"""
from __future__ import annotations

import gc
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

import polars as pl
import psutil
import pyarrow as pa
import pyarrow.parquet as pq

IN_DIR = Path("J:/THESIS-EDR/datasets/botsv2_features")
OUT_DIR = Path(__file__).parent / "data"
TMP_DIR = OUT_DIR / "_tmp"

# 5.2M target — keeps all ~173K malicious (0.125% rate) + ~5M proportionally-
# sampled benign, giving ~3.3% positive rate. Old target (3M) was sized for the
# old inflated label set (2.15M positives) and would leave too few positives here.
TARGET_TOTAL = 5_200_000
TRAIN_FRAC = 0.60
VAL_FRAC = 0.20
SEED = 42

# Hard RAM ceiling. Raised to 10 GB (host has 18 GB total).
RAM_LIMIT_GB = 10.0
RAM_LIMIT_BYTES = int(RAM_LIMIT_GB * 1024 ** 3)

# Stream chunk size for the splitting pass. 100k rows × 50 cols ≈ a few hundred
# MB peak per chunk; well under the 7 GB ceiling.
SPLIT_CHUNK = 100_000


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

_proc = psutil.Process(os.getpid())


def ram_check(label: str = "") -> int:
    """Hard-fail if RSS exceeds RAM_LIMIT_BYTES. Returns current RSS bytes."""
    rss = _proc.memory_info().rss
    if rss > RAM_LIMIT_BYTES:
        raise MemoryError(
            f"RAM limit exceeded at {label}: {rss/1024**3:.2f} GB > {RAM_LIMIT_GB} GB"
        )
    return rss


def ram_str() -> str:
    return f"{_proc.memory_info().rss / 1024**3:.2f} GB"


def _list_partitions() -> list[Path]:
    return sorted(IN_DIR.glob("sourcetype=*"))


# Partition read chunk size. Big partitions (WinRegistry 50M, Perfmon_Process
# 43M, collectd 16M) blow past the 7 GB cap if read whole, so we always
# chunk via slice(offset, batch).
PARTITION_BATCH = 1_000_000


def _iter_partition_batches(pdir: Path):
    """Yield polars DataFrames of <= PARTITION_BATCH rows.
    sourcetype is already in featured.parquet (added by extract_features.py)."""
    f = pdir / "featured.parquet"
    total = pl.scan_parquet(f).select(pl.len()).collect().item()
    if total == 0:
        return
    offset = 0
    while offset < total:
        df = pl.scan_parquet(f).slice(offset, PARTITION_BATCH).collect()
        if "sourcetype" not in df.columns:
            df = df.with_columns(
                pl.lit(pdir.name.replace("sourcetype=", "")).alias("sourcetype")
            )
        yield df
        offset += PARTITION_BATCH


def _to_arrow(df: pl.DataFrame, schema: pa.Schema) -> pa.Table:
    """Cast a polars DataFrame to a fixed pyarrow schema, filling missing
    columns with nulls of the right dtype."""
    cols = {}
    for field in schema:
        if field.name in df.columns:
            cols[field.name] = df[field.name]
        else:
            cols[field.name] = pl.Series(field.name, [None] * df.height, dtype=pl.String)
    return pl.DataFrame(cols).to_arrow().cast(schema)


# ──────────────────────────────────────────────────────────────────────────
# Pass 0: union schema
# ──────────────────────────────────────────────────────────────────────────

def build_union_schema() -> pa.Schema:
    """Scan partition headers, build a union pyarrow schema."""
    print("Pass 0: building union schema...")
    union_dtypes: dict[str, pl.DataType] = {}
    for pdir in _list_partitions():
        f = pdir / "featured.parquet"
        if not f.exists():
            continue
        head = pl.read_parquet(f, n_rows=0)
        if "sourcetype" not in head.columns:
            head = head.with_columns(pl.lit("", dtype=pl.String).alias("sourcetype"))
        for c, t in zip(head.columns, head.dtypes):
            if c not in union_dtypes:
                union_dtypes[c] = t
            elif union_dtypes[c] != t:
                union_dtypes[c] = pl.String
    union_cols = sorted(union_dtypes.keys())
    print(f"  union columns: {len(union_cols)}")
    type_map = {
        pl.Int64: pa.int64(),
        pl.Int32: pa.int32(),
        pl.Int8: pa.int8(),
        pl.Float64: pa.float64(),
        pl.String: pa.string(),
    }
    return pa.schema(
        [pa.field(c, type_map.get(union_dtypes[c], pa.string())) for c in union_cols]
    )


# ──────────────────────────────────────────────────────────────────────────
# Pass 1: extract malicious rows + count benign per sourcetype
# ──────────────────────────────────────────────────────────────────────────

def pass1_malicious(arrow_schema: pa.Schema, mal_path: Path) -> tuple[int, dict[str, int]]:
    print("\nPass 1: extracting malicious + counting benign per sourcetype...")
    mal_writer = pq.ParquetWriter(mal_path, arrow_schema, compression="zstd")
    benign_counts: dict[str, int] = {}
    mal_total = 0
    union_dtypes = {f.name: f.type for f in arrow_schema}
    pl_type_map = {
        pa.int64(): pl.Int64, pa.int32(): pl.Int32, pa.int8(): pl.Int8,
        pa.float64(): pl.Float64, pa.string(): pl.String,
    }

    for pdir in _list_partitions():
        f = pdir / "featured.parquet"
        if not f.exists():
            continue
        st = pdir.name.replace("sourcetype=", "")
        n_mal = 0
        n_ben = 0
        for df in _iter_partition_batches(pdir):
            casts = []
            for c in df.columns:
                target_pa = union_dtypes.get(c)
                if target_pa is None:
                    continue
                target_pl = pl_type_map.get(target_pa, pl.String)
                if df[c].dtype != target_pl:
                    casts.append(pl.col(c).cast(target_pl, strict=False))
            if casts:
                df = df.with_columns(casts)
            mal_part = df.filter(pl.col("label") == 1)
            if mal_part.height:
                mal_writer.write_table(_to_arrow(mal_part, arrow_schema))
                n_mal += mal_part.height
            n_ben += df.height - mal_part.height
            del df, mal_part
            gc.collect()
            ram_check(f"Pass 1 / {st}")
        mal_total += n_mal
        benign_counts[st] = n_ben
    mal_writer.close()

    total_benign = sum(benign_counts.values())
    print(f"  malicious : {mal_total:,}   benign : {total_benign:,}   RSS: {ram_str()}")
    return mal_total, benign_counts


# ──────────────────────────────────────────────────────────────────────────
# Pass 2: sample benign per sourcetype proportionally
# ──────────────────────────────────────────────────────────────────────────

def compute_quotas(benign_counts: dict[str, int], benign_budget: int) -> dict[str, int]:
    total_benign = sum(benign_counts.values())
    quotas: dict[str, int] = {}
    raw_quotas: dict[str, float] = {}
    for st, n in benign_counts.items():
        if total_benign == 0:
            quotas[st] = 0
            continue
        q = benign_budget * n / total_benign
        raw_quotas[st] = q
        quotas[st] = min(n, int(q))
    remainder = benign_budget - sum(quotas.values())
    if remainder > 0:
        rs = sorted(
            [(st, raw_quotas[st] - int(raw_quotas[st])) for st in raw_quotas],
            key=lambda x: x[1],
            reverse=True,
        )
        for st, _ in rs:
            if remainder <= 0:
                break
            if quotas[st] < benign_counts[st]:
                quotas[st] += 1
                remainder -= 1
    return quotas


def pass2_benign(arrow_schema: pa.Schema, ben_path: Path,
                 quotas: dict[str, int], benign_counts: dict[str, int]) -> int:
    print(f"\nPass 2: sampling benign (budget {sum(quotas.values()):,})...")
    union_dtypes = {f.name: f.type for f in arrow_schema}
    pl_type_map = {
        pa.int64(): pl.Int64, pa.int32(): pl.Int32, pa.int8(): pl.Int8,
        pa.float64(): pl.Float64, pa.string(): pl.String,
    }
    ben_writer = pq.ParquetWriter(ben_path, arrow_schema, compression="zstd")
    sampled_benign = 0
    for pdir in _list_partitions():
        f = pdir / "featured.parquet"
        if not f.exists():
            continue
        st = pdir.name.replace("sourcetype=", "")
        take_remaining = quotas.get(st, 0)
        if take_remaining == 0:
            continue
        # Quota for this sourcetype across all benign rows in the partition.
        # Batches sample proportional to their share of the partition's benign,
        # consuming take_remaining as we go. This is approximately equivalent
        # to a single-pass uniform sample without holding the whole partition
        # in RAM. Floor + remainder fixup gives an exact total.
        n_ben_total = max(benign_counts.get(st, 0), 1)
        for df in _iter_partition_batches(pdir):
            if take_remaining == 0:
                del df
                continue
            casts = []
            for c in df.columns:
                target_pa = union_dtypes.get(c)
                if target_pa is None:
                    continue
                target_pl = pl_type_map.get(target_pa, pl.String)
                if df[c].dtype != target_pl:
                    casts.append(pl.col(c).cast(target_pl, strict=False))
            if casts:
                df = df.with_columns(casts)
            ben_part = df.filter(pl.col("label") == 0)
            n_ben_batch = ben_part.height
            if n_ben_batch == 0:
                del df, ben_part
                gc.collect()
                continue
            # Proportional batch quota; cap at remaining and at batch size.
            batch_quota = min(
                take_remaining,
                max(1, int(round(quotas[st] * n_ben_batch / n_ben_total))),
                n_ben_batch,
            )
            sub = ben_part.sample(n=batch_quota, seed=SEED)
            ben_writer.write_table(_to_arrow(sub, arrow_schema))
            sampled_benign += sub.height
            take_remaining -= sub.height
            del df, ben_part, sub
            gc.collect()
            ram_check(f"Pass 2 / {st}")
    ben_writer.close()
    print(f"  sampled benign: {sampled_benign:,}   RSS: {ram_str()}")
    return sampled_benign


# ──────────────────────────────────────────────────────────────────────────
# Combine mal + ben buffers -> all.parquet (streaming row-group copy)
# ──────────────────────────────────────────────────────────────────────────

def combine_to_all(arrow_schema: pa.Schema, mal_path: Path, ben_path: Path,
                   all_path: Path) -> int:
    print("\nStreaming mal + ben -> all.parquet (no materialize)...")
    writer = pq.ParquetWriter(all_path, arrow_schema, compression="zstd")
    n = 0
    for src in (mal_path, ben_path):
        pf = pq.ParquetFile(src)
        for rg_idx in range(pf.num_row_groups):
            tbl = pf.read_row_group(rg_idx)
            writer.write_table(tbl.cast(arrow_schema))
            n += tbl.num_rows
            del tbl
            ram_check(f"combine / {src.name} rg{rg_idx}")
    writer.close()
    gc.collect()
    print(f"  combined: {n:,} rows -> {all_path}   RSS: {ram_str()}")
    return n


# ──────────────────────────────────────────────────────────────────────────
# Streaming temporal split
# ──────────────────────────────────────────────────────────────────────────

def temporal_boundaries(all_path: Path) -> tuple[int, int]:
    """Compute (train_max_time, val_max_time) by reading just the _time column.

    Snap to next strictly-greater value so single-second tied events don't
    straddle splits (the anti-leakage rule from the experiment).
    """
    print("\nComputing temporal boundaries (single-column scan)...")
    times = pl.read_parquet(all_path, columns=["_time"])["_time"].sort()
    n = times.len()
    train_idx = int(n * TRAIN_FRAC)
    val_idx = int(n * (TRAIN_FRAC + VAL_FRAC))

    def advance(idx: int) -> int:
        if idx >= n:
            return n - 1
        boundary = times[idx]
        while idx < n and times[idx] == boundary:
            idx += 1
        return idx - 1  # inclusive index of last row with the *previous* time

    t_train_idx = advance(train_idx)
    t_val_idx = advance(val_idx)
    train_max_t = int(times[t_train_idx]) if t_train_idx >= 0 else int(times[0])
    val_max_t = int(times[t_val_idx]) if t_val_idx >= 0 else train_max_t
    print(f"  train: _time <= {train_max_t}")
    print(f"  val  : {train_max_t} < _time <= {val_max_t}")
    print(f"  test : _time > {val_max_t}")
    del times
    gc.collect()
    return train_max_t, val_max_t


def stream_temporal_split(all_path: Path, out_dir: Path,
                          arrow_schema: pa.Schema,
                          train_max_t: int, val_max_t: int) -> dict:
    """Stream all.parquet, route each row group to train/val/test by _time."""
    out_dir.mkdir(exist_ok=True)
    paths = {
        "train": out_dir / "train.parquet",
        "val": out_dir / "val.parquet",
        "test": out_dir / "test.parquet",
    }
    writers = {k: pq.ParquetWriter(v, arrow_schema, compression="zstd")
               for k, v in paths.items()}
    counts = {"train": 0, "val": 0, "test": 0}
    mal_counts = {"train": 0, "val": 0, "test": 0}
    time_ranges = {k: [None, None] for k in counts}

    pf = pq.ParquetFile(all_path)
    for rg_idx in range(pf.num_row_groups):
        tbl = pf.read_row_group(rg_idx)
        df = pl.from_arrow(tbl)
        del tbl
        # Three masks
        for split, mask in [
            ("train", pl.col("_time") <= train_max_t),
            ("val", (pl.col("_time") > train_max_t) & (pl.col("_time") <= val_max_t)),
            ("test", pl.col("_time") > val_max_t),
        ]:
            sub = df.filter(mask)
            if sub.height == 0:
                continue
            writers[split].write_table(_to_arrow(sub, arrow_schema))
            counts[split] += sub.height
            mal_counts[split] += int((sub["label"] == 1).sum())
            tmin = int(sub["_time"].min())
            tmax = int(sub["_time"].max())
            tr = time_ranges[split]
            tr[0] = tmin if tr[0] is None else min(tr[0], tmin)
            tr[1] = tmax if tr[1] is None else max(tr[1], tmax)
            del sub
        del df
        gc.collect()
        ram_check(f"temporal split rg{rg_idx}")

    for w in writers.values():
        w.close()

    return {
        "train": {"name": "train", "rows": counts["train"], "malicious": mal_counts["train"],
                  "positive_rate": mal_counts["train"] / max(counts["train"], 1),
                  "time_min": time_ranges["train"][0], "time_max": time_ranges["train"][1]},
        "val":   {"name": "val",   "rows": counts["val"], "malicious": mal_counts["val"],
                  "positive_rate": mal_counts["val"] / max(counts["val"], 1),
                  "time_min": time_ranges["val"][0], "time_max": time_ranges["val"][1]},
        "test":  {"name": "test",  "rows": counts["test"], "malicious": mal_counts["test"],
                  "positive_rate": mal_counts["test"] / max(counts["test"], 1),
                  "time_min": time_ranges["test"][0], "time_max": time_ranges["test"][1]},
    }


# ──────────────────────────────────────────────────────────────────────────
# Streaming stratified split
# ──────────────────────────────────────────────────────────────────────────

# We want a deterministic, label-stratified 60/20/20 random split without
# materializing or shuffling the whole frame. Trick: each row gets a stable
# integer bucket in [0, 100) derived from a hash of its row index (within
# the streaming pass) plus its label, then routed by:
#   bucket <  60: train
#   bucket < 80: val
#   else: test
# Per-label routing happens by separately hashing rows of each label class
# so the bucket distribution is balanced within each label, giving the same
# 60/20/20 split for both class 0 and class 1 — i.e. label-stratified.

def _row_bucket(row_global_idx: int, label: int, seed: int) -> int:
    """Stable integer in [0, 100) for routing."""
    h = hashlib.blake2b(
        f"{seed}:{label}:{row_global_idx}".encode(),
        digest_size=4,
    ).digest()
    return int.from_bytes(h, "big") % 100


def stream_stratified_split(all_path: Path, out_dir: Path,
                            arrow_schema: pa.Schema) -> dict:
    """Stream-route each row by (label, deterministic-hash bucket)."""
    out_dir.mkdir(exist_ok=True)
    paths = {
        "train": out_dir / "train.parquet",
        "val": out_dir / "val.parquet",
        "test": out_dir / "test.parquet",
    }
    writers = {k: pq.ParquetWriter(v, arrow_schema, compression="zstd")
               for k, v in paths.items()}
    counts = {"train": 0, "val": 0, "test": 0}
    mal_counts = {"train": 0, "val": 0, "test": 0}
    time_ranges = {k: [None, None] for k in counts}

    train_cut = int(TRAIN_FRAC * 100)            # 60
    val_cut = int((TRAIN_FRAC + VAL_FRAC) * 100) # 80

    pf = pq.ParquetFile(all_path)
    # Per-label running counters so bucketing is stratified by label
    counter = {0: 0, 1: 0}
    for rg_idx in range(pf.num_row_groups):
        tbl = pf.read_row_group(rg_idx)
        df = pl.from_arrow(tbl)
        del tbl

        # For vectorized routing, compute bucket per row in numpy.
        labels = df["label"].to_numpy()
        n = len(labels)
        buckets = bytearray(n)
        for i in range(n):
            lab = int(labels[i])
            counter[lab] += 1
            buckets[i] = _row_bucket(counter[lab], lab, SEED)

        df = df.with_columns(pl.Series("_bucket", buckets, dtype=pl.UInt8))
        for split, mask in [
            ("train", pl.col("_bucket") < train_cut),
            ("val",   (pl.col("_bucket") >= train_cut) & (pl.col("_bucket") < val_cut)),
            ("test",  pl.col("_bucket") >= val_cut),
        ]:
            sub = df.filter(mask).drop("_bucket")
            if sub.height == 0:
                continue
            writers[split].write_table(_to_arrow(sub, arrow_schema))
            counts[split] += sub.height
            mal_counts[split] += int((sub["label"] == 1).sum())
            tmin = int(sub["_time"].min())
            tmax = int(sub["_time"].max())
            tr = time_ranges[split]
            tr[0] = tmin if tr[0] is None else min(tr[0], tmin)
            tr[1] = tmax if tr[1] is None else max(tr[1], tmax)
            del sub
        del df
        gc.collect()
        ram_check(f"stratified split rg{rg_idx}")

    for w in writers.values():
        w.close()

    return {
        "train": {"name": "train", "rows": counts["train"], "malicious": mal_counts["train"],
                  "positive_rate": mal_counts["train"] / max(counts["train"], 1),
                  "time_min": time_ranges["train"][0], "time_max": time_ranges["train"][1]},
        "val":   {"name": "val",   "rows": counts["val"], "malicious": mal_counts["val"],
                  "positive_rate": mal_counts["val"] / max(counts["val"], 1),
                  "time_min": time_ranges["val"][0], "time_max": time_ranges["val"][1]},
        "test":  {"name": "test",  "rows": counts["test"], "malicious": mal_counts["test"],
                  "positive_rate": mal_counts["test"] / max(counts["test"], 1),
                  "time_min": time_ranges["test"][0], "time_max": time_ranges["test"][1]},
    }


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    if not IN_DIR.exists():
        print(f"FATAL: {IN_DIR} missing", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    TMP_DIR.mkdir(parents=True)

    started = time.time()
    print(f"RAM ceiling: {RAM_LIMIT_GB} GB    initial RSS: {ram_str()}")

    arrow_schema = build_union_schema()

    mal_path = TMP_DIR / "mal_buffer.parquet"
    ben_path = TMP_DIR / "ben_buffer.parquet"
    all_path = OUT_DIR / "all.parquet"

    mal_total, benign_counts = pass1_malicious(arrow_schema, mal_path)

    benign_budget = max(TARGET_TOTAL - mal_total, 0)
    if benign_budget == 0:
        print(f"WARN: TARGET_TOTAL ({TARGET_TOTAL:,}) <= malicious ({mal_total:,}); "
              "no benign rows will be sampled. Bump TARGET_TOTAL.")
    quotas = compute_quotas(benign_counts, benign_budget)

    sampled_benign = pass2_benign(arrow_schema, ben_path, quotas, benign_counts)

    n = combine_to_all(arrow_schema, mal_path, ben_path, all_path)

    # Splits
    train_max_t, val_max_t = temporal_boundaries(all_path)
    print("\nProducing TEMPORAL split (streaming)...")
    temporal_stats = stream_temporal_split(all_path, OUT_DIR / "temporal",
                                           arrow_schema, train_max_t, val_max_t)
    print(f"  RSS: {ram_str()}")

    print("\nProducing STRATIFIED split (streaming, hash-routed)...")
    stratified_stats = stream_stratified_split(all_path, OUT_DIR / "stratified",
                                               arrow_schema)
    print(f"  RSS: {ram_str()}")

    # Read column list once for the summary (cheap — just header)
    cols = pl.read_parquet(all_path, n_rows=0).columns

    summary = {
        "seed": SEED,
        "target_total": TARGET_TOTAL,
        "actual_total": n,
        "malicious_total": mal_total,
        "benign_sampled": sampled_benign,
        "ram_limit_gb": RAM_LIMIT_GB,
        "columns": cols,
        "temporal_split": list(temporal_stats.values()),
        "stratified_split": list(stratified_stats.values()),
    }
    with open(OUT_DIR / "split_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("\nTEMPORAL split:")
    for s in temporal_stats.values():
        print(
            f"  {s['name']:6s}: {s['rows']:>10,} rows, {s['malicious']:>8,} mal "
            f"({s['positive_rate']*100:.3f}%), time {s['time_min']} -> {s['time_max']}"
        )
    print("\nSTRATIFIED split:")
    for s in stratified_stats.values():
        print(
            f"  {s['name']:6s}: {s['rows']:>10,} rows, {s['malicious']:>8,} mal "
            f"({s['positive_rate']*100:.3f}%), time {s['time_min']} -> {s['time_max']}"
        )

    shutil.rmtree(TMP_DIR)
    print(f"\nTotal wall time: {time.time()-started:.1f}s    final RSS: {ram_str()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
