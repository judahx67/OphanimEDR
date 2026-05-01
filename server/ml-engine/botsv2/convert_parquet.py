"""Phase 1: CSV -> partitioned Parquet (one partition per sourcetype).

Reads all CSVs from BOTSV2_CSV_DIR, drops _meta column, normalizes _time to int64
epoch, writes Parquet partitioned by sourcetype with ZSTD compression.

Usage:
    python convert_parquet.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import polars as pl
import pyarrow as pa
import pyarrow.csv as pacsv
from tqdm import tqdm

CSV_DIR = Path("J:/THESIS-EDR/datasets/botsv2")
OUT_DIR = Path("J:/THESIS-EDR/datasets/botsv2_parquet")

# PyArrow handles BOTSv2's irregular CSVs better than Polars: some rows have
# embedded multi-line _raw with """" escaping that trips Polars's multi-line
# field detection, and a small number of rows are missing the trailing _meta
# column entirely. PyArrow + invalid_row_handler='skip' tolerates both.
PA_COLUMN_TYPES = {
    "_time": pa.float64(),
    "source": pa.string(),
    "host": pa.string(),
    "sourcetype": pa.string(),
    "_raw": pa.string(),
    "_meta": pa.string(),
}


def sanitize_partition(name: str) -> str:
    """Filesystem-safe partition name from sourcetype value."""
    return (
        name.replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace("*", "_")
        .replace("?", "_")
        .replace('"', "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace("|", "_")
        .replace(" ", "_")
    )


def convert_one(csv_path: Path, out_root: Path) -> tuple[int, int, int]:
    """Convert one CSV. Returns (rows_in, rows_out, rows_skipped)."""
    bucket_id = csv_path.stem  # db_xxxx_yyyy_zz

    skipped = [0]
    def on_invalid(row):
        skipped[0] += 1
        return "skip"

    parse_opts = pacsv.ParseOptions(
        quote_char='"',
        double_quote=True,
        newlines_in_values=True,
        invalid_row_handler=on_invalid,
    )
    read_opts = pacsv.ReadOptions(block_size=64 * 1024 * 1024)
    conv_opts = pacsv.ConvertOptions(column_types=PA_COLUMN_TYPES)

    table = pacsv.read_csv(
        csv_path, read_options=read_opts, parse_options=parse_opts, convert_options=conv_opts
    )
    rows_in = table.num_rows
    rows_skipped = skipped[0]
    if rows_in == 0:
        return 0, 0, rows_skipped

    # Convert to Polars for downstream operations (drop _meta, strip prefixes,
    # cast _time, partition by sourcetype).
    df = pl.from_arrow(table).select([
        pl.col("_time").cast(pl.Int64).alias("_time"),
        pl.col("source").str.strip_prefix("source::"),
        pl.col("host").str.strip_prefix("host::"),
        pl.col("sourcetype").str.strip_prefix("sourcetype::"),
        pl.col("_raw"),
        # _meta dropped
    ])
    rows_out = 0

    for st_value in df["sourcetype"].unique().to_list():
        partition_label = "_null" if st_value is None else st_value
        partition_dir = out_root / f"sourcetype={sanitize_partition(partition_label)}"
        partition_dir.mkdir(parents=True, exist_ok=True)
        if st_value is None:
            sub = df.filter(pl.col("sourcetype").is_null()).drop("sourcetype")
        else:
            sub = df.filter(pl.col("sourcetype") == st_value).drop("sourcetype")
        out_file = partition_dir / f"{bucket_id}.parquet"
        sub.write_parquet(out_file, compression="zstd", compression_level=3)
        rows_out += sub.height

    return rows_in, rows_out, rows_skipped


def main() -> int:
    if not CSV_DIR.exists():
        print(f"FATAL: {CSV_DIR} missing", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(CSV_DIR.glob("*.csv"))
    if not csv_files:
        print(f"FATAL: no CSVs in {CSV_DIR}", file=sys.stderr)
        return 1

    print(f"Converting {len(csv_files)} CSVs from {CSV_DIR}")
    print(f"Output: {OUT_DIR}")
    print(f"Skipping bucket if its corresponding parquet shards already exist.")

    total_in = 0
    total_out = 0
    total_skipped = 0
    failures: list[tuple[str, str]] = []
    started = time.time()
    pbar = tqdm(csv_files, unit="csv")
    for csv_path in pbar:
        bucket_id = csv_path.stem
        already_done = any(
            (st_dir / f"{bucket_id}.parquet").exists()
            for st_dir in OUT_DIR.glob("sourcetype=*")
        )
        if already_done:
            pbar.set_postfix(skip=bucket_id[:20])
            continue
        try:
            rin, rout, rskip = convert_one(csv_path, OUT_DIR)
            total_in += rin
            total_out += rout
            total_skipped += rskip
            pbar.set_postfix(rows=f"{rin:,}", skipped=f"{rskip}", parts=len(list(OUT_DIR.glob('sourcetype=*'))))
        except Exception as e:
            print(f"\nFAILED on {csv_path.name}: {e}", file=sys.stderr)
            failures.append((csv_path.name, str(e)[:200]))

    elapsed = time.time() - started
    print(f"\nDone in {elapsed/60:.1f} min")
    print(f"  rows in   : {total_in:,}")
    print(f"  rows out  : {total_out:,}")
    print(f"  rows skipped (malformed): {total_skipped:,}")
    print(f"  partitions: {len(list(OUT_DIR.glob('sourcetype=*')))}")
    if failures:
        print(f"  bucket failures: {len(failures)}")
        for name, err in failures:
            print(f"    {name}: {err}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
