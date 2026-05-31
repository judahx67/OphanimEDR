"""
Event Ingest Service.

Consumes raw BOTSv2 Splunk events from RabbitMQ 'raw_events' queue, normalizes
them into provenance graph edges, and publishes NormalizedEvent JSON to the
'edr_fanout' exchange. graph-builder and ml-edge-scorer each declare their own
queue bound to the fanout, so each consumer gets exactly one copy.

Flow: raw_events (RabbitMQ direct) -> normalize -> edr_fanout -> consumers
"""

import json
import logging
import os
import signal
import time

import pika

from botsv2_normalizer import normalize_splunk_event
from theia_normalizer import normalize_theia_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ingest")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

RAW_QUEUE = "raw_events"
NORMALIZED_QUEUE = "normalized_events"
EXCHANGE = "edr"

# ── Globals ───────────────────────────────────────────────────────────────

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Shutting down gracefully...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def connect_rabbitmq() -> pika.BlockingConnection:
    """Connect to RabbitMQ with retries."""
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=600,
        blocked_connection_timeout=300,
    )
    for attempt in range(30):
        try:
            conn = pika.BlockingConnection(params)
            logger.info("Connected to RabbitMQ at %s:%s", RABBITMQ_HOST, RABBITMQ_PORT)
            return conn
        except pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ not ready, retrying in 2s... (attempt %d/30)", attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to RabbitMQ after 30 attempts")


def setup_queues(channel: pika.channel.Channel) -> None:
    """Declare exchange and queues.

    `edr_fanout` is the single normalized-event delivery point: graph-builder
    and ml-edge-scorer each declare their own queue bound to it, so each
    consumer gets one copy of every message without competing.

    `edr` (direct) carries raw_events (simulator → ingest) and ml_alerts
    (scorer → llm-analyzer) — both one-to-one flows.
    """
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.exchange_declare(exchange="edr_fanout", exchange_type="fanout", durable=True)
    channel.queue_declare(queue=RAW_QUEUE, durable=True)
    channel.queue_declare(queue=NORMALIZED_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=RAW_QUEUE, routing_key="raw")
    # graph-builder consumes normalized_events from the fanout — single bind
    # (no longer bound to the direct exchange to avoid duplicate delivery).
    channel.queue_bind(exchange="edr_fanout", queue=NORMALIZED_QUEUE)


def main():
    logger.info("=== EDR Event Ingest Service (BOTSv2 + THEIA) ===")

    conn = connect_rabbitmq()
    channel = conn.channel()
    setup_queues(channel)

    # Prefetch: process up to 100 in flight for backpressure
    channel.basic_qos(prefetch_count=100)

    stats = {"received": 0, "normalized": 0, "skipped": 0, "errors": 0}
    last_log = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_log
        try:
            datum = json.loads(body)
            stats["received"] += 1

            # Route by dataset: THEIA CDM18 edges (from theia-replay) vs the
            # legacy BOTSv2 Splunk events. The tag is set by the replay/simulator.
            if datum.get("dataset") == "theia":
                normalized = normalize_theia_event(datum)
            else:
                normalized = normalize_splunk_event(datum)

            if normalized:
                # Single publish to the fanout exchange — every consumer
                # (graph-builder, ml-edge-scorer) has its own queue bound to
                # this exchange and gets exactly one copy.
                ch.basic_publish(
                    exchange="edr_fanout",
                    routing_key="",
                    body=normalized.model_dump_json(),
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        content_type="application/json",
                    ),
                )
                stats["normalized"] += 1
            else:
                stats["skipped"] += 1

            ch.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            stats["errors"] += 1
            logger.error("Error processing message: %s", e)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        # Log stats every 10 seconds
        now = time.time()
        if now - last_log > 10:
            logger.info(
                "Stats: received=%d normalized=%d skipped=%d errors=%d",
                stats["received"], stats["normalized"], stats["skipped"], stats["errors"],
            )
            last_log = now

    channel.basic_consume(queue=RAW_QUEUE, on_message_callback=on_message)

    logger.info("Waiting for messages on '%s' queue...", RAW_QUEUE)
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    finally:
        conn.close()
        logger.info("Final stats: %s", stats)


if __name__ == "__main__":
    main()
