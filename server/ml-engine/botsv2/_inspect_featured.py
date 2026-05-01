"""Inspect a few rows from a featured partition."""
import sys
import polars as pl

st = sys.argv[1] if len(sys.argv) > 1 else "stream_http"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
mal_only = "--mal" in sys.argv

f = f"J:/THESIS-EDR/datasets/botsv2_features_v2/sourcetype={st}/featured.parquet"
lf = pl.scan_parquet(f)
if mal_only:
    lf = lf.filter(pl.col("label") == 1)
df = lf.head(n).collect()
print(f"=== featured sourcetype={st} ({'mal only' if mal_only else 'first'}) ===")
print(f"cols ({len(df.columns)}): {df.columns}")
print(f"row count: {df.height}")
print()
for i, row in enumerate(df.iter_rows(named=True)):
    print(f"--- row {i} ---")
    for k, v in row.items():
        if v is None or v == "":
            continue
        s = str(v)
        if len(s) > 80:
            s = s[:80] + "..."
        print(f"  {k:25s} = {s}")
    print()

# Also count nulls for graph triple cols
print("=== graph triple null counts ===")
all_df = pl.scan_parquet(f).select(["subject_type", "object_type", "edge_type"]).collect()
total = all_df.height
for c in ["subject_type", "object_type", "edge_type"]:
    nulls = all_df[c].null_count()
    print(f"  {c}: {nulls:,} null / {total:,}  ({100*nulls/total:.2f}%)")
