r"""Convert Mordor JSON events to a labeled.parquet in our schema.

Strategy: for each Mordor Sysmon event, synthesise the Splunk-style XML
_raw that our existing parse_sysmon parser consumes. This means zero
parser changes — the new partition just gets the same Sysmon parser at
extract_features time, and ranger downstream is unchanged.

Output: J:/THESIS-EDR/datasets/botsv2_labeled/sourcetype=mordor_sysmon/labeled.parquet

Schema matches existing labeled.parquet:
  _time:Int64, source:str, host:str, sourcetype:str, _raw:str,
  label:Int8 (always 1), scenario:str (derived from filename)
"""
from __future__ import annotations

import gc
import gzip
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

EXTRACTED = Path("J:/THESIS-EDR/datasets/mordor/extracted")
OUT_DIR = Path("J:/THESIS-EDR/datasets/botsv2_labeled/sourcetype=mordor_sysmon")
OUT_FILE = OUT_DIR / "labeled.parquet"

# Fields we copy from Mordor JSON into the synthesised <Data Name='X'>V</Data>
# block. Names match the keys our parse_sysmon already understands. Restricting
# the set keeps the synthesised XML compact.
SYSMON_KEYS = (
    "ProcessId", "Image", "CommandLine", "ParentProcessId", "ParentImage",
    "ParentCommandLine", "User", "IntegrityLevel",
    "TargetFilename", "TargetObject",
    "SourceIp", "SourcePort", "DestinationIp", "DestinationPort", "Protocol",
    "ImageLoaded", "Details",
)

ARROW_SCHEMA = pa.schema([
    ("_time", pa.int64()),
    ("source", pa.string()),
    ("host", pa.string()),
    ("sourcetype", pa.string()),
    ("_raw", pa.string()),
    ("label", pa.int8()),
    ("scenario", pa.string()),
])

# Strip rare XML-unsafe chars from values before splicing into the synth _raw.
# Keep it cheap — no full escape; Sysmon's parser is regex-based.
_BAD_XML = re.compile(r"[<>&\x00-\x08\x0b\x0c\x0e-\x1f]")


def to_epoch(ts) -> int | None:
    """Mordor uses ISO 8601 strings or @timestamp ms. Coerce to epoch sec."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        v = int(ts)
        return v // 1000 if v > 1e12 else v
    if not isinstance(ts, str):
        return None
    s = ts.replace("Z", "+00:00")
    try:
        return int(datetime.fromisoformat(s).timestamp())
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return int(datetime.strptime(ts.split(".")[0], fmt).timestamp())
        except ValueError:
            continue
    return None


def scenario_for(path: Path) -> str:
    """Derive a scenario tag from the file path. Use the third-to-last dir."""
    parts = path.parts
    if len(parts) >= 3:
        return f"mordor_{parts[-3]}_{parts[-2]}"[:60]
    return f"mordor_{path.stem}"[:60]


def synth_sysmon_xml(ev: dict, eid: str | int, host: str) -> str:
    """Build a minimal Splunk-style Sysmon XML matching our parse_sysmon regex.
    parse_sysmon looks for: <EventID>N</EventID>, <Computer>H</Computer>,
    <Data Name='K'>V</Data> repeated."""
    parts = ["<Event><System><EventID>", str(eid), "</EventID><Computer>",
             _BAD_XML.sub(" ", host), "</Computer></System><EventData>"]
    for k in SYSMON_KEYS:
        v = ev.get(k)
        if v is None or v == "":
            continue
        parts.append(f"<Data Name='{k}'>")
        parts.append(_BAD_XML.sub(" ", str(v))[:500])
        parts.append("</Data>")
    parts.append("</EventData></Event>")
    return "".join(parts)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    files = sorted(EXTRACTED.rglob("*.json"))
    print(f"Found {len(files)} Mordor JSON files", flush=True)

    writer = pq.ParquetWriter(OUT_FILE, ARROW_SCHEMA, compression="zstd")
    started = time.time()
    n_in = n_out = n_files = 0
    BATCH = 100_000
    buf_t, buf_s, buf_h, buf_st, buf_r, buf_l, buf_sc = [], [], [], [], [], [], []

    for f in files:
        n_files += 1
        scenario = scenario_for(f)
        source = str(f.relative_to(EXTRACTED)).replace("\\", "/")
        try:
            opener = gzip.open if f.suffix == ".gz" else open
            with opener(f, "rt", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line[0] != "{":
                        continue
                    n_in += 1
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        continue
                    if "Sysmon" not in (ev.get("Channel") or ""):
                        continue
                    eid = ev.get("EventID")
                    if eid is None:
                        continue
                    t = to_epoch(ev.get("EventTime") or ev.get("@timestamp")
                                 or ev.get("EventReceivedTime"))
                    if t is None:
                        continue
                    host = ev.get("Hostname") or ev.get("Computer") or "mordor-host"
                    buf_t.append(t)
                    buf_s.append(source[:200])
                    buf_h.append(host[:80])
                    buf_st.append("mordor_sysmon")
                    buf_r.append(synth_sysmon_xml(ev, eid, host))
                    buf_l.append(1)
                    buf_sc.append(scenario)
                    n_out += 1
                    if len(buf_t) >= BATCH:
                        table = pa.table({"_time": buf_t, "source": buf_s,
                                          "host": buf_h, "sourcetype": buf_st,
                                          "_raw": buf_r, "label": buf_l,
                                          "scenario": buf_sc}, schema=ARROW_SCHEMA)
                        writer.write_table(table)
                        buf_t, buf_s, buf_h, buf_st, buf_r, buf_l, buf_sc = \
                            [], [], [], [], [], [], []
                        gc.collect()
        except Exception as e:
            print(f"  SKIP {f.name}: {e}", flush=True)
            continue
        if n_files % 10 == 0:
            print(f"  ... {n_files}/{len(files)} files,"
                  f" {n_out:,}/{n_in:,} kept", flush=True)

    if buf_t:
        table = pa.table({"_time": buf_t, "source": buf_s, "host": buf_h,
                          "sourcetype": buf_st, "_raw": buf_r, "label": buf_l,
                          "scenario": buf_sc}, schema=ARROW_SCHEMA)
        writer.write_table(table)
    writer.close()

    elapsed = time.time() - started
    print(f"\nDone in {elapsed/60:.1f} min")
    print(f"  files scanned   : {n_files}")
    print(f"  events read     : {n_in:,}")
    print(f"  sysmon kept     : {n_out:,}")
    print(f"  wrote           : {OUT_FILE}  ({OUT_FILE.stat().st_size/1e6:.0f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
