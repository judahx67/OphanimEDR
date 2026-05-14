"""Quick inspection helper — sample rows from a labeled partition."""
import sys
import polars as pl

st = sys.argv[1] if len(sys.argv) > 1 else "stream_http"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 3
malicious_only = "--mal" in sys.argv

f = f"J:/THESIS-EDR/datasets/botsv2_labeled/sourcetype={st}/labeled.parquet"
lf = pl.scan_parquet(f)
if malicious_only:
    lf = lf.filter(pl.col("label") == 1)
df = lf.head(n).collect()
print(f"=== sourcetype={st} ({'malicious only' if malicious_only else 'first rows'}) ===")
print(f"cols: {df.columns}")
for i, row in enumerate(df.iter_rows(named=True)):
    print(f"\n--- row {i} (label={row['label']}, scenario={row['scenario']}) ---")
    raw = row["_raw"] or ""
    print(raw[:800])
