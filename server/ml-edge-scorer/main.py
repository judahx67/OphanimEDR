"""
ML Edge Scorer Service.

Consumes NormalizedEvent messages from the 'normalized_events' RabbitMQ queue
(separate consumer group from graph-builder — neither blocks the other).

For each event:
  1. Build a 39-column feature row from the event's _raw + graph triple.
  2. Score with both frozen LightGBM models:
       lgbm_xt_temporal        → botsv2_ml_score         (headline, 0.9877 ROC-AUC)
       lgbm_xt_temporal_no_st  → botsv2_ml_score_honest  (honest,   0.9135 ROC-AUC)
  3. MATCH the edge in Neo4j by event_id and SET the score properties.
  4. If either score exceeds the alert threshold, publish to 'ml_alerts' queue.

Alert thresholds (static, locked in plan):
  headline: 0.9    (botsv2_ml_score >= 0.9)
  honest:   0.7    (botsv2_ml_score_honest >= 0.7)
"""

import json
import logging
import os
import signal
import time
from pathlib import Path

import pika
from neo4j import GraphDatabase

from model_loader import load_models
from feature_row import build_feature_row

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ml-edge-scorer")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

NORMALIZED_QUEUE = "normalized_events"
# Scorer gets its own queue so it doesn't compete with graph-builder for messages
SCORER_QUEUE = "normalized_events_scoring"
ML_ALERTS_QUEUE = "ml_alerts"
EXCHANGE = "edr"

# Models directory — mounted read-only from ml-engine/botsv2/models/
MODELS_DIR = Path(os.environ.get("MODELS_DIR", "/app/models"))

# Alert thresholds — overridable via env, but default is derived from each
# model's threshold.json (set by threshold-calibration.py) so the value is
# always consistent with training-time calibration.
_THRESHOLD_HEADLINE_ENV = os.environ.get("ML_THRESHOLD_HEADLINE")
_THRESHOLD_HONEST_ENV = os.environ.get("ML_THRESHOLD_HONEST")

# Prefetch / batch
PREFETCH = int(os.environ.get("PREFETCH", "50"))

# ── Shutdown ──────────────────────────────────────────────────────────────

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Shutting down...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ── Neo4j writer ──────────────────────────────────────────────────────────

def connect_neo4j():
    for attempt in range(30):
        try:
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
            driver.verify_connectivity()
            logger.info("Connected to Neo4j")
            return driver
        except Exception as e:
            logger.warning("Neo4j not ready (%s), retrying... (%d/30)", e, attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to Neo4j")


_WRITE_SCORES_BATCH_CYPHER = """
UNWIND $rows AS row
MATCH ()-[r {event_id: row.event_id}]->()
SET r.botsv2_ml_score         = row.score_headline,
    r.botsv2_ml_score_honest  = row.score_honest,
    r.botsv2_ml_score_quality = row.quality,
    r.botsv2_ml_scored_at     = row.scored_at,
    r.botsv2_ml_alert         = row.is_alert
RETURN count(r) AS matched
"""

# In-memory write buffer: flush every WRITE_BATCH_SIZE events or WRITE_FLUSH_SECS seconds
WRITE_BATCH_SIZE = int(os.environ.get("WRITE_BATCH_SIZE", "50"))
WRITE_FLUSH_SECS = float(os.environ.get("WRITE_FLUSH_SECS", "2.0"))

_write_buffer: list[dict] = []
_last_flush: float = 0.0
# Minimum age (seconds) before a batch is flushed — lets graph-builder write edges first
WRITE_DELAY_SECS = float(os.environ.get("WRITE_DELAY_SECS", "3.0"))


def _flush_buffer(driver) -> int:
    global _write_buffer, _last_flush
    if not _write_buffer:
        _last_flush = time.time()
        return 0
    batch = _write_buffer
    _write_buffer = []
    _last_flush = time.time()
    with driver.session() as session:
        result = session.run(_WRITE_SCORES_BATCH_CYPHER, rows=batch)
        record = result.single()
        matched = record["matched"] if record else 0
    logger.info("flush_buffer: batch=%d matched=%d sample_id=%s",
                len(batch), matched, batch[0]["event_id"] if batch else "none")
    return matched


def buffer_scores(driver, event_id: str, score_headline: float, score_honest: float,
                  quality: str, is_alert: bool) -> int:
    """Buffer score writes. Flushes when batch is full AND the buffer has aged
    past WRITE_DELAY_SECS, giving graph-builder time to write the edges first."""
    global _write_buffer, _last_flush
    now = time.time()
    if _last_flush == 0.0:
        _last_flush = now
    _write_buffer.append({
        "event_id": event_id,
        "score_headline": round(score_headline, 4),
        "score_honest": round(score_honest, 4),
        "quality": quality,
        "scored_at": int(now * 1000),
        "is_alert": is_alert,
    })
    aged = (now - _last_flush) >= WRITE_DELAY_SECS
    full = len(_write_buffer) >= WRITE_BATCH_SIZE
    if aged and full:
        return _flush_buffer(driver)
    if aged and len(_write_buffer) >= 10:  # flush smaller batches after delay too
        return _flush_buffer(driver)
    return 0


# ── RabbitMQ ──────────────────────────────────────────────────────────────

def connect_rabbitmq() -> pika.BlockingConnection:
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST, port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=600, blocked_connection_timeout=300,
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


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    logger.info("=== ML Edge Scorer Service ===")
    logger.info("Loading models from %s", MODELS_DIR)

    models = load_models(MODELS_DIR)
    headline_model = models["lgbm_xt_temporal"]
    honest_model = models["lgbm_xt_temporal_no_st"]
    logger.info("Models loaded: %s", list(models.keys()))

    # Resolve alert thresholds: env override > model's threshold.json
    threshold_headline = (
        float(_THRESHOLD_HEADLINE_ENV) if _THRESHOLD_HEADLINE_ENV
        else headline_model.threshold
    )
    threshold_honest = (
        float(_THRESHOLD_HONEST_ENV) if _THRESHOLD_HONEST_ENV
        else honest_model.threshold
    )
    logger.info(
        "Alert thresholds: headline=%.4f (model=%.4f)  honest=%.4f (model=%.4f)",
        threshold_headline, headline_model.threshold,
        threshold_honest, honest_model.threshold,
    )

    neo4j_driver = connect_neo4j()
    conn = connect_rabbitmq()
    channel = conn.channel()

    # Use a fanout exchange so both graph-builder and scorer get every message.
    # Declare the fanout exchange; ingest publishes to it.
    channel.exchange_declare(exchange="edr_fanout", exchange_type="fanout", durable=True)
    # Also keep the direct exchange for backward compat with ingest
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    # Scorer's own private queue bound to the fanout exchange
    channel.queue_declare(queue=SCORER_QUEUE, durable=True)
    channel.queue_bind(exchange="edr_fanout", queue=SCORER_QUEUE)
    channel.queue_declare(queue=ML_ALERTS_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=ML_ALERTS_QUEUE, routing_key="ml_alert")

    channel.basic_qos(prefetch_count=PREFETCH)

    stats = {"received": 0, "scored": 0, "alerts": 0, "errors": 0, "skipped": 0}
    last_log = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_log
        try:
            event = json.loads(body)
            stats["received"] += 1

            event_id = event.get("event_id")
            if not event_id:
                stats["skipped"] += 1
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

            feature_row, quality = build_feature_row(event)

            score_headline = headline_model.predict_proba(feature_row)
            score_honest = honest_model.predict_proba(feature_row)

            is_alert = (score_headline >= threshold_headline or
                        score_honest >= threshold_honest)

            buffer_scores(
                neo4j_driver, event_id,
                score_headline, score_honest, quality, is_alert,
            )
            stats["scored"] += 1

            if is_alert:
                alert_payload = {
                    "event_id": event_id,
                    "score_headline": score_headline,
                    "score_honest": score_honest,
                    "quality": quality,
                    "edge_type": event.get("edge_type"),
                    "subject": event.get("subject"),
                    "object": event.get("object"),
                    "endpoint_id": event.get("endpoint_id"),
                    "timestamp": event.get("timestamp"),
                    "sourcetype": event.get("sourcetype"),
                }
                ch.basic_publish(
                    exchange=EXCHANGE,
                    routing_key="ml_alert",
                    body=json.dumps(alert_payload),
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        content_type="application/json",
                    ),
                )
                stats["alerts"] += 1

            ch.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            stats["errors"] += 1
            logger.error("Scoring error for event %s: %s", event.get("event_id", "?"), e)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        now = time.time()
        if now - last_log > 10:
            logger.info(
                "Stats: received=%d scored=%d alerts=%d errors=%d skipped=%d",
                stats["received"], stats["scored"], stats["alerts"],
                stats["errors"], stats["skipped"],
            )
            last_log = now

    channel.basic_consume(queue=SCORER_QUEUE, on_message_callback=on_message)
    logger.info(
        "Scoring edges from '%s' (headline_threshold=%.2f, honest_threshold=%.2f)",
        NORMALIZED_QUEUE, threshold_headline, threshold_honest,
    )

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    finally:
        _flush_buffer(neo4j_driver)  # flush any remaining buffered writes
        conn.close()
        neo4j_driver.close()
        logger.info("Final stats: %s", stats)


if __name__ == "__main__":
    main()
