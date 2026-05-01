"""
Event Ingest Service.

Consumes raw THEIA CDM events from RabbitMQ 'raw_events' queue,
normalizes them into provenance graph edges, and publishes
NormalizedEvent JSON to the 'normalized_events' queue.

Flow: raw_events (RabbitMQ) -> normalize -> normalized_events (RabbitMQ)
"""

import json
import logging
import os
import signal
import sys
import time

import pika

from normalizer import TheiaNodeCache, normalize_event

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
    """Declare exchange and queues."""
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=RAW_QUEUE, durable=True)
    channel.queue_declare(queue=NORMALIZED_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=RAW_QUEUE, routing_key="raw")
    channel.queue_bind(exchange=EXCHANGE, queue=NORMALIZED_QUEUE, routing_key="normalized")


def main():
    logger.info("=== EDR Event Ingest Service ===")

    conn = connect_rabbitmq()
    channel = conn.channel()
    setup_queues(channel)

    # Prefetch: process one message at a time for backpressure
    channel.basic_qos(prefetch_count=100)

    cache = TheiaNodeCache()
    stats = {"received": 0, "normalized": 0, "skipped": 0, "errors": 0}
    last_log = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_log
        try:
            datum = json.loads(body)
            stats["received"] += 1

            normalized = normalize_event(datum, cache)

            if normalized:
                # Publish normalized event to the next queue
                ch.basic_publish(
                    exchange=EXCHANGE,
                    routing_key="normalized",
                    body=normalized.model_dump_json(),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # persistent
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
                "Stats: received=%d normalized=%d skipped=%d errors=%d | Cache: %s",
                stats["received"], stats["normalized"], stats["skipped"], stats["errors"],
                cache.stats,
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
