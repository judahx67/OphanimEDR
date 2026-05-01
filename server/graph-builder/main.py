"""
Graph Builder Service.

Consumes NormalizedEvent from RabbitMQ 'normalized_events' queue
and incrementally builds a causal provenance graph in Neo4j.

Each NormalizedEvent becomes:
  - 2 nodes (subject + object), MERGE'd by their unique ID
  - 1 edge (causal relationship), CREATE'd with timestamp

Neo4j schema:
  Nodes: (:Process), (:File), (:Socket), (:Registry), (:Memory), (:Pipe)
    - uuid (unique), name, endpoint_id, properties (JSON string), first_seen, last_seen
  Edges: -[:FORK|EXEC|READ|WRITE|CONNECT|SEND|RECEIVE|MMAP|RENAME|DELETE|LOAD|MODIFY_REG]->
    - event_id, timestamp, size, properties (JSON string)
"""

import json
import logging
import os
import signal
import time

import pika
from neo4j import GraphDatabase

from schema import NormalizedEvent, NodeType

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("graph-builder")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

NORMALIZED_QUEUE = "normalized_events"
EXCHANGE = "edr"

BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "200"))
BATCH_TIMEOUT = float(os.environ.get("BATCH_TIMEOUT", "2.0"))

# ── Neo4j ─────────────────────────────────────────────────────────────────


class GraphWriter:
    """Writes normalized events to Neo4j as a provenance graph."""

    # Map NodeType -> Neo4j label
    LABELS = {
        NodeType.PROCESS: "Process",
        NodeType.FILE: "File",
        NodeType.SOCKET: "Socket",
        NodeType.REGISTRY: "Registry",
        NodeType.MEMORY: "Memory",
        NodeType.PIPE: "Pipe",
    }

    def __init__(self, uri: str, user: str, password: str):
        self._driver = None
        self._uri = uri
        self._user = user
        self._password = password

    def connect(self):
        """Connect to Neo4j with retries."""
        for attempt in range(30):
            try:
                self._driver = GraphDatabase.driver(
                    self._uri, auth=(self._user, self._password)
                )
                self._driver.verify_connectivity()
                logger.info("Connected to Neo4j at %s", self._uri)
                self._create_constraints()
                return
            except Exception as e:
                logger.warning("Neo4j not ready (%s), retrying in 2s... (%d/30)", e, attempt + 1)
                time.sleep(2)
        raise RuntimeError("Could not connect to Neo4j after 30 attempts")

    def _create_constraints(self):
        """Create uniqueness constraints and indexes."""
        with self._driver.session() as session:
            for label in self.LABELS.values():
                try:
                    session.run(
                        f"CREATE CONSTRAINT IF NOT EXISTS "
                        f"FOR (n:{label}) REQUIRE n.uuid IS UNIQUE"
                    )
                except Exception as e:
                    logger.warning("Constraint for %s: %s", label, e)

            # Index on endpoint_id for multi-host queries
            try:
                session.run(
                    "CREATE INDEX IF NOT EXISTS FOR (n:Process) ON (n.endpoint_id)"
                )
            except Exception:
                pass

        logger.info("Neo4j constraints and indexes ready")

    def write_batch(self, events: list[NormalizedEvent]) -> int:
        """
        Write a batch of normalized events to Neo4j.
        Uses UNWIND for efficient batch insertion.
        Returns number of edges created.
        """
        if not events:
            return 0

        # Build batch params
        rows = []
        for ev in events:
            rows.append({
                "event_id": ev.event_id,
                "timestamp": ev.timestamp,
                "endpoint_id": ev.endpoint_id,
                "edge_type": ev.edge_type.value,
                "subj_uuid": ev.subject.id,
                "subj_label": self.LABELS[ev.subject.node_type],
                "subj_name": ev.subject.name,
                "subj_props": json.dumps(ev.subject.properties),
                "obj_uuid": ev.object.id,
                "obj_label": self.LABELS[ev.object.node_type],
                "obj_name": ev.object.name,
                "obj_props": json.dumps(ev.object.properties),
                "size": ev.size,
                "props": json.dumps(ev.properties),
            })

        # Cypher can't dynamically set labels or relationship types, so we
        # group rows by the (subj_label, obj_label, edge_type) triple and
        # interpolate them statically into each query.
        by_key: dict[tuple[str, str, str], list[dict]] = {}
        for row in rows:
            key = (row["subj_label"], row["obj_label"], row["edge_type"])
            by_key.setdefault(key, []).append(row)

        valid_labels = set(self.LABELS.values())
        total = 0
        with self._driver.session() as session:
            for (subj_label, obj_label, edge_type), type_rows in by_key.items():
                if subj_label not in valid_labels or obj_label not in valid_labels:
                    logger.warning("Skipping rows with invalid labels: %s/%s", subj_label, obj_label)
                    continue
                query = self._build_merge_query(subj_label, obj_label, edge_type)
                result = session.run(query, {"rows": type_rows})
                summary = result.consume()
                total += summary.counters.relationships_created

        return total

    def _build_merge_query(self, subj_label: str, obj_label: str, edge_type: str) -> str:
        """
        Build a Cypher query that:
        1. MERGE subject node (by uuid)
        2. MERGE object node (by uuid)
        3. CREATE the edge (every event is a unique causal edge)

        We use APOC-free approach: MERGE with label via CALL subquery.
        Since we can't dynamically set labels in pure Cypher,
        we handle it by always using a common label + node_type property,
        plus the specific label set at creation time.
        """
        return f"""
        UNWIND $rows AS row

        MERGE (s:{subj_label} {{uuid: row.subj_uuid}})
        ON CREATE SET
            s.name = row.subj_name,
            s.endpoint_id = row.endpoint_id,
            s.properties = row.subj_props,
            s.node_type = row.subj_label,
            s.first_seen = row.timestamp,
            s.last_seen = row.timestamp
        ON MATCH SET
            s.last_seen = CASE WHEN row.timestamp > s.last_seen
                          THEN row.timestamp ELSE s.last_seen END,
            // Upgrade the name if (a) the cached name is a bare placeholder
            // or (b) the incoming row carries a richer label — a command
            // line (contains a space) is strictly more informative than a
            // bare exe path, which beats a placeholder.
            s.name = CASE
                WHEN s.name STARTS WITH 'process:' OR s.name STARTS WITH 'file:' OR s.name STARTS WITH 'socket:'
                    THEN row.subj_name
                WHEN row.subj_name CONTAINS ' ' AND NOT s.name CONTAINS ' '
                    THEN row.subj_name
                ELSE s.name
            END,
            s.properties = CASE WHEN row.subj_props <> '{{}}'
                           THEN row.subj_props ELSE s.properties END

        MERGE (o:{obj_label} {{uuid: row.obj_uuid}})
        ON CREATE SET
            o.name = row.obj_name,
            o.endpoint_id = row.endpoint_id,
            o.properties = row.obj_props,
            o.node_type = row.obj_label,
            o.first_seen = row.timestamp,
            o.last_seen = row.timestamp
        ON MATCH SET
            o.last_seen = CASE WHEN row.timestamp > o.last_seen
                          THEN row.timestamp ELSE o.last_seen END,
            o.name = CASE
                WHEN o.name STARTS WITH 'process:' OR o.name STARTS WITH 'file:' OR o.name STARTS WITH 'socket:'
                    THEN row.obj_name
                WHEN row.obj_name CONTAINS ' ' AND NOT o.name CONTAINS ' '
                    THEN row.obj_name
                ELSE o.name
            END

        CREATE (s)-[r:{edge_type} {{
            event_id: row.event_id,
            timestamp: row.timestamp,
            size: row.size,
            properties: row.props
        }}]->(o)
        """

    def close(self):
        if self._driver:
            self._driver.close()

    def get_stats(self) -> dict:
        """Get graph statistics."""
        with self._driver.session() as session:
            nodes = session.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            edges = session.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            return {"nodes": nodes, "edges": edges}


# ── RabbitMQ consumer ─────────────────────────────────────────────────────

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Shutting down...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def connect_rabbitmq() -> pika.BlockingConnection:
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
            logger.info("Connected to RabbitMQ")
            return conn
        except pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ not ready, retrying... (%d/30)", attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to RabbitMQ")


def main():
    logger.info("=== EDR Graph Builder Service ===")

    # Connect to both services
    graph = GraphWriter(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    graph.connect()

    conn = connect_rabbitmq()
    channel = conn.channel()

    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=NORMALIZED_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=NORMALIZED_QUEUE, routing_key="normalized")

    channel.basic_qos(prefetch_count=BATCH_SIZE)

    stats = {"consumed": 0, "edges_created": 0, "errors": 0, "batches": 0}
    batch: list[tuple] = []  # (delivery_tag, NormalizedEvent)
    last_flush = time.time()
    last_log = time.time()

    def flush_batch():
        nonlocal batch, last_flush
        if not batch:
            return

        events = []
        tags = []
        for tag, ev in batch:
            events.append(ev)
            tags.append(tag)

        try:
            created = graph.write_batch(events)
            stats["edges_created"] += created
            stats["batches"] += 1

            # Ack all messages in the batch
            for tag in tags:
                channel.basic_ack(delivery_tag=tag)

            stats["consumed"] += len(events)
        except Exception as e:
            logger.error("Batch write failed: %s", e)
            stats["errors"] += len(events)
            for tag in tags:
                channel.basic_nack(delivery_tag=tag, requeue=True)

        batch = []
        last_flush = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_log
        try:
            ev = NormalizedEvent.model_validate_json(body)
            batch.append((method.delivery_tag, ev))

            # Flush if batch is full
            if len(batch) >= BATCH_SIZE:
                flush_batch()

        except Exception as e:
            logger.error("Error parsing event: %s", e)
            stats["errors"] += 1
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        # Log stats every 10 seconds
        now = time.time()
        if now - last_log > 10:
            graph_stats = graph.get_stats()
            logger.info(
                "Stats: consumed=%d edges_created=%d batches=%d errors=%d | Graph: %s",
                stats["consumed"], stats["edges_created"], stats["batches"],
                stats["errors"], graph_stats,
            )
            last_log = now

    channel.basic_consume(queue=NORMALIZED_QUEUE, on_message_callback=on_message)

    logger.info("Waiting for normalized events on '%s'...", NORMALIZED_QUEUE)
    try:
        while running:
            # Process messages with timeout so we can flush partial batches
            conn.process_data_events(time_limit=1)

            # Flush on timeout
            if batch and (time.time() - last_flush) > BATCH_TIMEOUT:
                flush_batch()
    except KeyboardInterrupt:
        pass
    finally:
        flush_batch()  # flush remaining
        conn.close()
        graph_stats = graph.get_stats()
        logger.info("Final stats: %s | Graph: %s", stats, graph_stats)
        graph.close()


if __name__ == "__main__":
    main()
