"""
Rule Engine Service

Consumes NormalizedEvent messages from RabbitMQ (normalized_events queue),
runs the rule-based FSM engine, and writes fired incidents to Neo4j.

Flow:
  [RabbitMQ: normalized_events]
       |
       v
  RuleEngine.process_event()   <- stateful FSM, per (rule_id, root_process_id)
       |
       v  (when rule fires)
  write (:Incident) node to Neo4j
  publish to RabbitMQ: incidents  (for future ML engine)
"""

import json
import logging
import os
import signal
import sys
import time

import pika
from neo4j import GraphDatabase

from engine import RuleEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rule-engine] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("rule-engine")

# ── Config ──────────────────────────────────────────────────────────────────
RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "localhost")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", 5672))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

NEO4J_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

EXCHANGE    = "edr"
# Own queue bound to the normalized-events fanout — sharing graph-builder's
# queue makes the two compete as rival consumers, so each sees only part of
# the stream. One queue per consumer is the correct fanout pattern.
IN_QUEUE    = "normalized_events_rules"
OUT_QUEUE   = "incidents"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _connect_rabbitmq() -> pika.BlockingConnection:
    creds = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=creds,
        heartbeat=60,
        blocked_connection_timeout=300,
    )
    for attempt in range(1, 11):
        try:
            conn = pika.BlockingConnection(params)
            log.info("Connected to RabbitMQ")
            return conn
        except Exception as exc:
            log.warning("RabbitMQ not ready (attempt %d/10): %s", attempt, exc)
            time.sleep(5)
    log.error("Could not connect to RabbitMQ after 10 attempts")
    sys.exit(1)


def _connect_neo4j():
    for attempt in range(1, 11):
        try:
            driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)
            )
            driver.verify_connectivity()
            log.info("Connected to Neo4j")
            # Ensure constraint
            with driver.session() as s:
                s.run(
                    "CREATE CONSTRAINT incident_id IF NOT EXISTS "
                    "FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE"
                )
            return driver
        except Exception as exc:
            log.warning("Neo4j not ready (attempt %d/10): %s", attempt, exc)
            time.sleep(5)
    log.error("Could not connect to Neo4j after 10 attempts")
    sys.exit(1)


def _write_incident_to_neo4j(driver, incident: dict):
    query = """
    MERGE (i:Incident {incident_id: $incident_id})
    SET
      i.rule_id         = $rule_id,
      i.rule_name       = $rule_name,
      i.severity        = $severity,
      i.status          = $status,
      i.title           = $title,
      i.description     = $description,
      i.mitre_technique = $mitre_technique,
      i.endpoint_id     = $endpoint_id,
      i.matched_nodes   = $matched_nodes,
      i.matched_edges   = $matched_edges,
      i.rule_conditions = $rule_conditions,
      i.root_node_id    = $root_node_id,
      i.confidence      = $confidence,
      i.created_at      = $created_at,
      i.updated_at      = $updated_at,
      i.notes           = $notes,
      i.source          = 'rule-engine'
    """
    with driver.session() as s:
        s.run(query, **incident)


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    neo4j_driver = _connect_neo4j()
    mq_conn = _connect_rabbitmq()
    channel = mq_conn.channel()

    # Ensure exchanges + queues exist. Normalized events arrive via the fanout
    # (one private queue per consumer); incidents go out on the direct exchange.
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.exchange_declare(exchange="edr_fanout", exchange_type="fanout", durable=True)
    channel.queue_declare(queue=IN_QUEUE,  durable=True)
    channel.queue_declare(queue=OUT_QUEUE, durable=True)
    channel.queue_bind(queue=IN_QUEUE,  exchange="edr_fanout")
    channel.queue_bind(queue=OUT_QUEUE, exchange=EXCHANGE, routing_key=OUT_QUEUE)

    # Prefetch 1 so we don't buffer too many events
    channel.basic_qos(prefetch_count=50)

    engine = RuleEngine()
    counters = {"processed": 0, "incidents": 0}

    def on_message(ch, method, _props, body):
        try:
            event = json.loads(body)
        except json.JSONDecodeError as exc:
            log.warning("Bad JSON: %s", exc)
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        incidents = engine.process_event(event)
        for incident in incidents:
            _write_incident_to_neo4j(neo4j_driver, incident)
            ch.basic_publish(
                exchange=EXCHANGE,
                routing_key=OUT_QUEUE,
                body=json.dumps(incident),
                properties=pika.BasicProperties(delivery_mode=2),
            )
            log.info(
                "INCIDENT [%s] %s  root=%s",
                incident["severity"].upper(),
                incident["rule_name"],
                incident.get("root_node_id", "?")[:8],
            )
            counters["incidents"] += 1

        counters["processed"] += 1
        if counters["processed"] % 1000 == 0:
            log.info(
                "Processed %d events, fired %d incidents",
                counters["processed"],
                counters["incidents"],
            )

        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=IN_QUEUE, on_message_callback=on_message)

    def _shutdown(sig, frame):
        log.info("Shutting down (signal %d)", sig)
        channel.stop_consuming()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info(
        "Rule engine ready — consuming from '%s', %d rules loaded",
        IN_QUEUE,
        len(engine._rules),
    )
    try:
        channel.start_consuming()
    finally:
        mq_conn.close()
        neo4j_driver.close()
        log.info(
            "Stopped. Processed %d events, fired %d incidents.",
            counters["processed"],
            counters["incidents"],
        )


if __name__ == "__main__":
    main()
