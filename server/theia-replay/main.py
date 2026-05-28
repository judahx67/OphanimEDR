"""
THEIA E3 CDM18 replay (offline dataset adapter).

Mirrors the old BOTSv2 simulator, but for the DARPA TC E3 THEIA dataset. Reads
CDM18 JSON (one record per line) and publishes structured, type-resolved edge
events to RabbitMQ 'raw_events' tagged dataset="theia". The ingest service maps
these into NormalizedEvent; the GNN scorer consumes the resulting graph.

Why two passes over a bounded window:
  CDM18 node-defining records (Subject/FileObject/NetFlowObject/MemoryObject/
  Principal) carry the node *type*, while Event records only reference UUIDs.
  Pass A scans a bounded line window to build uuid -> cdm_type; pass B emits one
  raw_event per (subject -> object) Event edge, with cmdLine/path attributes.
  This is the offline analogue of the FLASH two-pass parse. In the live Wazuh
  path the collector emits the node records, so types come for free.

Usage:
  python main.py --file ta1-theia-e3-official-6r.json.8 --limit 20000 --rate 500
"""

import argparse
import json
import logging
import os
import re
import signal
import time
from pathlib import Path

import pika

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("theia-replay")

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

EXCHANGE = "edr"
RAW_QUEUE = "raw_events"

DATA_ROOT = Path(os.environ.get("THEIA_DATA_ROOT", "/data/theia"))

_uuid = re.compile(r'uuid":"(.*?)"')
_type = re.compile(r'type":"(.*?)"')
# Lines that are not node-defining records (mirror FLASH build_node_map skips).
_NON_NODE = (".Event", ".Host", ".TimeMarker", ".StartMarker",
             ".UnitDependency", ".EndMarker")

running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def build_type_map(path: Path, scan_lines: int) -> dict:
    """Pass A: resolve uuid -> cdm_type from node-defining records in a window."""
    m: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= scan_lines:
                break
            if any(t in line for t in _NON_NODE):
                continue
            u = _uuid.findall(line)
            if not u or u[0] in m:
                continue
            st = _type.findall(line)
            if st:
                m[u[0]] = st[0]
            elif ".MemoryObject" in line:
                m[u[0]] = "MemoryObject"
            elif ".NetFlowObject" in line:
                m[u[0]] = "NetFlowObject"
            elif ".UnnamedPipeObject" in line:
                m[u[0]] = "UnnamedPipeObject"
    logger.info("type map: %d uuids resolved (scanned %d lines)", len(m), scan_lines)
    return m


def _dig(d, *keys):
    for k in keys:
        d = d.get(k) if isinstance(d, dict) else None
        if d is None:
            return ""
    return d if isinstance(d, str) else ""


def iter_edges(path: Path, type_map: dict, scan_lines: int, gt: set):
    """Pass B: yield one structured edge dict per (subject -> object) Event."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= scan_lines:
                break
            if ".Event" not in line:
                continue
            try:
                ev = json.loads(line)["datum"].get(
                    "com.bbn.tc.schema.avro.cdm18.Event")
            except Exception:
                continue
            if not ev:
                continue
            actor = _dig(ev, "subject", "com.bbn.tc.schema.avro.cdm18.UUID")
            if not actor:
                continue
            action = ev.get("type", "")
            ts = ev.get("timestampNanos", "")
            cmd = _dig(ev, "properties", "map", "cmdLine")
            for okey, pkey in (("predicateObject", "predicateObjectPath"),
                               ("predicateObject2", "predicateObject2Path")):
                obj = _dig(ev, okey, "com.bbn.tc.schema.avro.cdm18.UUID")
                if not obj:
                    continue
                path_attr = _dig(ev, pkey, "string")
                label = 1 if (actor in gt or obj in gt) else 0
                yield {
                    "dataset": "theia",
                    "actor_id": actor,
                    "actor_cdm": type_map.get(actor, "SUBJECT_PROCESS"),
                    "object_id": obj,
                    "object_cdm": type_map.get(obj, "FILE_OBJECT_BLOCK"),
                    "action": action,
                    "exec": cmd,
                    "path": path_attr,
                    "timestamp": str(ts),
                    "label": label,
                }


def connect_rabbitmq() -> pika.BlockingConnection:
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST, port=RABBITMQ_PORT,
        credentials=credentials, heartbeat=600,
    )
    for attempt in range(30):
        try:
            conn = pika.BlockingConnection(params)
            logger.info("Connected to RabbitMQ")
            return conn
        except pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ not ready, retrying... (%d/30)", attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to RabbitMQ")


def load_gt() -> set:
    p = DATA_ROOT / "data_files" / "theia.json"
    if not p.exists():
        return set()
    try:
        return {u for u in json.load(open(p, encoding="utf-8")) if u}
    except Exception as e:
        logger.warning("could not load GT (%s)", e)
        return set()


def main():
    ap = argparse.ArgumentParser(description="THEIA E3 CDM18 replay")
    ap.add_argument("--file", default="ta1-theia-e3-official-6r.json.8",
                    help="CDM18 split filename under THEIA_DATA_ROOT")
    ap.add_argument("--limit", type=int, default=20000,
                    help="Max edges to publish (0 = window cap)")
    ap.add_argument("--rate", type=int, default=500,
                    help="Approx events/sec; 0 = as fast as possible")
    ap.add_argument("--scan-lines", type=int, default=0,
                    help="Lines to scan for the type map (0 = auto: limit*30)")
    args = ap.parse_args()

    path = DATA_ROOT / args.file
    if not path.exists():
        logger.error("CDM18 file not found: %s", path)
        return

    scan_lines = args.scan_lines or max(200_000, args.limit * 30)
    logger.info("=== THEIA replay: %s limit=%d rate=%d ===",
                path.name, args.limit, args.rate)

    gt = load_gt()
    logger.info("ground-truth malicious uuids: %d", len(gt))
    type_map = build_type_map(path, scan_lines)

    conn = connect_rabbitmq()
    channel = conn.channel()
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=RAW_QUEUE, durable=True)

    sent = mal = 0
    start = time.time()
    try:
        for edge in iter_edges(path, type_map, scan_lines, gt):
            if not running or (args.limit and sent >= args.limit):
                break
            channel.basic_publish(
                exchange=EXCHANGE, routing_key="raw",
                body=json.dumps(edge),
                properties=pika.BasicProperties(
                    delivery_mode=2, content_type="application/json"),
            )
            sent += 1
            mal += edge["label"]
            if args.rate and sent % args.rate == 0:
                time.sleep(1.0)
            if sent % 5000 == 0:
                logger.info("published %d edges (%d weak-malicious) %.1fs",
                            sent, mal, time.time() - start)
    finally:
        logger.info("done: %d edges published (%d weak-malicious) in %.1fs",
                    sent, mal, time.time() - start)
        conn.close()


if __name__ == "__main__":
    main()
