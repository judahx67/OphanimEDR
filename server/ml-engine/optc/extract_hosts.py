"""Extract the 3 OpTC red-team attack hosts from the downloaded eCAR .json.gz
into per-host line-delimited JSON text files (FLASH OpTC.ipynb `extract_logs`).

Each AIA-*.ecar*.json.gz holds a host *range* (e.g. AIA-51-75 = SysClient0051..0075);
FLASH evaluates ONE attack host per scenario:
  0051  Malicious Upgrade        <- AIA-51-75.ecar-last
  0201  Plain PowerShell Empire  <- AIA-201-225.ecar-2019-12-08 + ecar-last
  0501  Custom PowerShell Empire <- AIA-501-525.ecar-2019-11-17 + ecar-last

Output: <DATA>/SysClient0XXX.systemia.com.txt  (matches notebook eval cells).
Run with the RESEARCH venv python.
"""
import gzip, os, time

DATA = os.environ.get("OPTC_DATA",
    os.path.join(os.path.dirname(__file__), "..", "..", "..",
                 "external", "Flash-IDS", "_optc_gt"))
DATA = os.path.abspath(DATA)

SOURCES = {
    "0051": ["AIA-51-75.ecar-last.json.gz"],
    "0201": ["AIA-201-225.ecar-2019-12-08.json.gz", "AIA-201-225.ecar-last.json.gz"],
    "0501": ["AIA-501-525.ecar-2019-11-17.json.gz", "AIA-501-525.ecar-last.json.gz"],
}

for host, files in SOURCES.items():
    pat = f"SysClient{host}"
    out = os.path.join(DATA, f"SysClient{host}.systemia.com.txt")
    if os.path.exists(out) and os.path.getsize(out) > 0:
        print(f"[skip] {os.path.basename(out)} exists ({os.path.getsize(out):,} B)")
        continue
    t0 = time.time(); kept = scanned = 0
    with open(out, "w", encoding="utf-8") as fw:
        for fn in files:
            p = os.path.join(DATA, fn)
            if not os.path.exists(p):
                print(f"  !! missing {fn}"); continue
            with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fr:
                for line in fr:
                    scanned += 1
                    if pat in line:
                        fw.write(line)
                        kept += 1
            print(f"  {fn}: scanned now {scanned:,}, kept {kept:,}", flush=True)
    print(f"[done] {os.path.basename(out)}  kept {kept:,} lines  "
          f"({os.path.getsize(out)/1e6:.0f} MB, {time.time()-t0:.0f}s)", flush=True)
print("ALL HOSTS EXTRACTED")
