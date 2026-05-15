"""
EDR Event Simulator — BOTSv2 Parquet replay.

Reads partitioned labeled Parquet under <botsv2_dir>/sourcetype=*/labeled.parquet
and publishes each row to RabbitMQ as a raw Splunk-shaped JSON event:

  {
    "_raw":       str,   # original log line
    "sourcetype": str,
    "host":       str,
    "_time":      int,
    "label":      int,   # ground-truth 0/1
    "scenario":   str,   # s200 / s300 / s400 / null
  }

The ingest service normalizes these into graph edges. Per-partition fairness:
each parseable sourcetype contributes up to `per_partition` rows so the replay
is balanced across sourcetypes.

NOTE — TODO Phase 02 / P0-3: the current loop iterates partitions sequentially.
Cross-sourcetype causal ordering is destroyed because all of one sourcetype is
replayed before the next starts. A k-way merge by `_time` is planned in
plans/260515-1938-defense-prep/phase-02-causal-correctness.md.

Usage:
  python main.py --botsv2-dir /data/botsv2_labeled --limit 5000 --rate 200
"""

import argparse
import json
import logging
import os
import pathlib
import signal
import time

import pika

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("simulator")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

EXCHANGE = "edr"
RAW_QUEUE = "raw_events"

running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# Sourcetypes whose botsv2_parsers produce real graph triples. Other
# sourcetypes exist in the dataset (Perfmon_*, etc.) but yield stubs only,
# so we don't waste publish bandwidth on them.
PARSEABLE_SOURCETYPES = frozenset({
    "stream_http", "stream_tcp", "stream_ip", "stream_dns", "stream_arp",
    "stream_dhcp", "stream_ftp", "stream_icmp", "stream_irc", "stream_ldap",
    "stream_mysql", "stream_smb", "stream_smtp", "stream_udp",
    "suricata", "access_combined", "WebLogic_Access_Combined",
    "XmlWinEventLog_Microsoft-Windows-Sysmon_Operational",
    "pan_traffic", "pan_threat",
    "mysql_server_stats", "mysql_transaction_details",
    "WinHostMon", "WinRegistry",
    "linux_audit", "auditd",
})


def run_botsv2_loader(channel, botsv2_dir: str, limit: int, rate: int) -> None:
    """
    Stream BOTSv2 labeled Parquet events directly to RabbitMQ without buffering.

    Reads each partition row-group by row-group and publishes rows immediately.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError:
        logger.error("pyarrow not installed — cannot replay BOTSv2 Parquet files")
        return

    botsv2_path = pathlib.Path(botsv2_dir)
    parquet_files = sorted(botsv2_path.glob("sourcetype=*/labeled.parquet"))
    if not parquet_files:
        logger.error("No labeled.parquet files found under %s", botsv2_dir)
        return

    parseable_files = [
        p for p in parquet_files
        if p.parent.name.replace("sourcetype=", "") in PARSEABLE_SOURCETYPES
    ]
    logger.info(
        "Found %d parseable partitions (out of %d total) under %s",
        len(parseable_files), len(parquet_files), botsv2_dir,
    )

    # Fairness across sourcetypes: cap each partition's contribution. Without
    # this, partitions discovered first dominate the replay.
    per_partition = (
        max(200, limit // max(len(parseable_files), 1))
        if limit > 0 else 2000
    )

    def _publish(row: dict) -> None:
        channel.basic_publish(
            exchange=EXCHANGE,
            routing_key="raw",
            body=json.dumps(row),
            properties=pika.BasicProperties(
                delivery_mode=2,
                content_type="application/json",
            ),
        )

    start_time = time.time()
    total_sent = 0

    for pfile in parseable_files:
        if not running or (limit > 0 and total_sent >= limit):
            break
        sourcetype = pfile.parent.name.replace("sourcetype=", "")
        try:
            pf = pq.ParquetFile(pfile)
        except Exception as e:
            logger.warning("Cannot open %s: %s", pfile, e)
            continue

        partition_sent = 0
        for rg_idx in range(pf.metadata.num_row_groups):
            if not running or partition_sent >= per_partition:
                break
            if limit > 0 and total_sent >= limit:
                break
            try:
                batch = pf.read_row_group(
                    rg_idx,
                    columns=["_raw", "host", "_time", "label", "scenario"],
                )
                # Cast dict-encoded columns to plain string
                for col_name in ("_raw", "host", "scenario"):
                    idx = batch.schema.get_field_index(col_name)
                    if idx >= 0:
                        col = batch.column(col_name)
                        if pa.types.is_dictionary(col.type):
                            batch = batch.set_column(
                                idx, col_name, col.cast(pa.string())
                            )
            except Exception as e:
                logger.warning(
                    "Error reading row group %d of %s: %s", rg_idx, pfile, e
                )
                continue

            for i in range(batch.num_rows):
                if not running or partition_sent >= per_partition:
                    break
                if limit > 0 and total_sent >= limit:
                    break
                raw_val = batch.column("_raw")[i].as_py()
                if not raw_val:
                    continue
                _publish({
                    "_raw": raw_val,
                    "sourcetype": sourcetype,
                    "host": batch.column("host")[i].as_py(),
                    "_time": batch.column("_time")[i].as_py(),
                    "label": batch.column("label")[i].as_py(),
                    "scenario": batch.column("scenario")[i].as_py(),
                })
                total_sent += 1
                partition_sent += 1
                if rate > 0 and total_sent % rate == 0:
                    time.sleep(1.0)

        if partition_sent:
            logger.info(
                "BOTSv2: %s  +%d rows  total=%d  (%.1fs)",
                sourcetype, partition_sent, total_sent,
                time.time() - start_time,
            )

    logger.info(
        "BOTSv2 loader done: %d events sent in %.1fs",
        total_sent, time.time() - start_time,
    )


# ── Publisher ─────────────────────────────────────────────────────────────


def connect_rabbitmq() -> pika.BlockingConnection:
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=600,
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


def main():
    parser = argparse.ArgumentParser(description="BOTSv2 EDR Event Simulator")
    parser.add_argument(
        "--botsv2-dir", type=str, default="/data/botsv2_labeled",
        help="Path to BOTSv2 labeled Parquet dir (sourcetype=*/labeled.parquet)",
    )
    parser.add_argument(
        "--rate", type=int, default=200,
        help="Approx events per second; 0 = as fast as possible",
    )
    parser.add_argument(
        "--limit", type=int, default=5000,
        help="Max events to send (0 = no limit)",
    )
    # Legacy compatibility — older deploy scripts pass --scenario botsv2.
    # Accept and ignore: BOTSv2 is the only scenario now.
    parser.add_argument(
        "--scenario", type=str, default="botsv2",
        help="(Deprecated) Scenario tag; only 'botsv2' is supported.",
    )
    args = parser.parse_args()

    if args.scenario != "botsv2":
        logger.warning(
            "Only --scenario botsv2 is supported; ignoring '%s'", args.scenario,
        )

    logger.info("=== EDR Simulator: BOTSv2 replay rate=%d/s ===", args.rate)

    conn = connect_rabbitmq()
    channel = conn.channel()
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=RAW_QUEUE, durable=True)

    try:
        run_botsv2_loader(channel, args.botsv2_dir, args.limit, args.rate)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
