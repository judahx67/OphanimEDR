"""
THEIA Orthrus windowed scorer (our-own Orthrus-style detector).

Sibling of theia-gnn-scorer for the FLASH-vs-Orthrus head-to-head: it consumes
the SAME normalized THEIA edges off the fanout, accumulates the same provenance
window, and scores the SAME nodes — but with our Orthrus implementation instead
of FLASH:
  - GAT encoder + edge-action-reconstruction decoder (theia_orthrus_common).
  - per-node anomaly = mean reconstruction loss.
  - a node is a seed iff its loss exceeds `max_val_loss` (worst benign loss),
    so Orthrus flags few/precise where FLASH floods.

Writes per node (by uuid):  n.orthrus_score, n.orthrus_seed, n.orthrus_scored_at
— read by /api/compare on the dashboard.

Weights/code mounted at /app/theia (server/ml-engine/theia).
"""

import collections
import json
import logging
import os
import signal
import sys
import time

import pika
import torch
from gensim.models import Word2Vec
from neo4j import GraphDatabase

sys.path.insert(0, os.environ.get("THEIA_CODE", "/app/theia"))
import theia_flash_common as fc  # noqa: E402
import theia_orthrus_common as oc  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("theia-orthrus-scorer")

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

EXCHANGE = "edr"
ORTHRUS_QUEUE = "normalized_events_orthrus"

CODE_ROOT = os.environ.get("THEIA_CODE", "/app/theia")
WEIGHTS = os.path.join(CODE_ROOT, os.environ.get(
    "ORTHRUS_WEIGHTS", "trained_weights/theia_orthrus_v1"))
W2V_PATH = os.path.join(CODE_ROOT, os.environ.get(
    "W2V_PATH", "trained_weights/theia_ours_v3/word2vec_theia_E3.model"))
# Optional threshold override (defaults to the calibrated max_val_loss in meta).
THRESHOLD_ENV = os.environ.get("ORTHRUS_THRESHOLD", "")

SCORE_MODE = os.environ.get("SCORE_MODE", "full")
WINDOW_EDGES = int(os.environ.get("WINDOW_EDGES", "20000"))
MIN_EDGES = int(os.environ.get("MIN_EDGES", "300"))
SCORE_EVERY_SECS = float(os.environ.get("SCORE_EVERY_SECS", "3600"))
IDLE_SECS = float(os.environ.get("IDLE_SECS", "20"))

device = torch.device("cpu")
running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class Scorer:
    """Loads the Orthrus encoder/decoder once and scores a graph by per-node
    edge-reconstruction loss vs the benign-calibrated threshold."""

    def __init__(self):
        self.w2v = Word2Vec.load(W2V_PATH)
        self.enc = fc.PositionalEncoder()
        with open(os.path.join(WEIGHTS, "meta.json")) as f:
            self.meta = json.load(f)
        self.action2id = self.meta["action2id"]
        # Operating threshold = benign p99 (robust max); env can override.
        meta_thr = self.meta.get("threshold") or self.meta.get("max_val_loss")
        self.threshold = float(THRESHOLD_ENV) if THRESHOLD_ENV else float(meta_thr)
        self.encoder = oc.OrthrusEncoder(self.meta["vector_size"]).to(device)
        self.decoder = oc.EdgeActionDecoder(self.meta["emb_dim"], self.meta["n_actions"]).to(device)
        self.encoder.load_state_dict(torch.load(
            os.path.join(WEIGHTS, "encoder.pth"), map_location=device, weights_only=True))
        self.decoder.load_state_dict(torch.load(
            os.path.join(WEIGHTS, "decoder.pth"), map_location=device, weights_only=True))
        self.encoder.eval()
        self.decoder.eval()
        logger.info("loaded orthrus: w2v vocab=%d, %d actions, threshold=%.4f from %s",
                    len(self.w2v.wv), self.meta["n_actions"], self.threshold, WEIGHTS)

    def score(self, df):
        """Return (seed_uuids, {uuid: loss}). Seeds exceed the benign threshold."""
        if len(df) < 2:
            return set(), {}
        x, ei, ea, _, mapp = oc.build_graph(df, self.w2v, self.enc, self.action2id, device)
        if ei.size(1) == 0 or len(mapp) < 2:
            return set(), {}
        with torch.no_grad():
            h = self.encoder(x, ei)
            node_loss = oc.per_node_loss(h, ei, ea, self.decoder)
        losses = node_loss.tolist()
        scores = {mapp[i]: float(losses[i]) for i in range(len(mapp))}
        seeds = {u for u, s in scores.items() if s > self.threshold}
        return seeds, scores


# Labels carrying a per-label uuid uniqueness constraint (= usable index).
# We write the scored batch against each in turn; every uuid matches under
# exactly one of them.
VALID_LABELS = {"Process", "File", "Socket", "Memory", "Pipe", "User"}

_WRITE_CYPHER = (
    "UNWIND $rows AS row "
    "MATCH (n:`{label}` {{uuid: row.uuid}}) "
    "SET n.orthrus_score = row.score, n.orthrus_seed = row.seed, "
    "    n.orthrus_scored_at = row.scored_at"
)


def connect_neo4j():
    for attempt in range(30):
        try:
            d = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
            d.verify_connectivity()
            logger.info("Connected to Neo4j")
            return d
        except Exception as e:
            logger.warning("Neo4j not ready (%s), retry %d/30", e, attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to Neo4j")


def connect_rabbitmq():
    creds = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(host=RABBITMQ_HOST, port=RABBITMQ_PORT,
                                       credentials=creds, heartbeat=600,
                                       blocked_connection_timeout=300)
    for attempt in range(30):
        try:
            conn = pika.BlockingConnection(params)
            logger.info("Connected to RabbitMQ")
            return conn
        except pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ not ready, retry %d/30", attempt + 1)
            time.sleep(2)
    raise RuntimeError("Could not connect to RabbitMQ")


def run_scoring(scorer, driver, window):
    import pandas as pd
    rows = list(window)
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "exec", "path"]).astype(str)
    t0 = time.time()
    seeds, scores = scorer.score(df)
    now_ms = int(time.time() * 1000)

    # Write every scored node under its TRUE label: run the full batch against
    # each label's uuid index. A uuid exists under exactly one label, so the
    # other label-queries are harmless index no-ops. We do NOT guess the label
    # from the edge anymore — that guess was wrong for ~8% of nodes and silently
    # dropped ~58% of seeds, so persisted /compare counts undercounted the
    # scorer's own output. Index lookups (not a label-less AllNodesScan) keep
    # this O(labels * N), cheap at demo scale.
    rows_out = [{"uuid": u, "score": s, "seed": (u in seeds), "scored_at": now_ms}
                for u, s in scores.items()]
    with driver.session() as session:
        for label in VALID_LABELS:
            session.run(_WRITE_CYPHER.format(label=label), rows=rows_out)
    logger.info("scored window: edges=%d nodes=%d seeds=%d (%.1fs)",
                len(rows), len(scores), len(seeds), time.time() - t0)


def main():
    logger.info("=== THEIA Orthrus Windowed Scorer ===")
    scorer = Scorer()
    driver = connect_neo4j()
    conn = connect_rabbitmq()
    channel = conn.channel()
    channel.exchange_declare(exchange="edr_fanout", exchange_type="fanout", durable=True)
    channel.queue_declare(queue=ORTHRUS_QUEUE, durable=True)
    channel.queue_bind(exchange="edr_fanout", queue=ORTHRUS_QUEUE)
    channel.basic_qos(prefetch_count=500)

    maxlen = None if SCORE_MODE == "full" else WINDOW_EDGES
    window = collections.deque(maxlen=maxlen)
    stats = {"received": 0, "edges_since_score": 0}
    last_score = time.time()
    last_edge = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_edge
        try:
            ev = json.loads(body)
            props = ev.get("properties", {})
            if props.get("dataset") != "theia":
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return
            window.append((
                ev["subject"]["id"], props.get("actor_cdm", "SUBJECT_PROCESS"),
                ev["object"]["id"], props.get("object_cdm", "FILE_OBJECT_BLOCK"),
                props.get("action", ""), props.get("exec", ""), props.get("path", ""),
            ))
            stats["received"] += 1
            stats["edges_since_score"] += 1
            last_edge = time.time()
        except Exception as e:
            logger.error("msg error: %s", e)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=ORTHRUS_QUEUE, on_message_callback=on_message)
    logger.info("mode=%s window=%s min=%d score_every=%.0fs idle=%.0fs",
                SCORE_MODE, maxlen, MIN_EDGES, SCORE_EVERY_SECS, IDLE_SECS)
    try:
        while running:
            conn.process_data_events(time_limit=1)
            now = time.time()
            due = (now - last_score) >= SCORE_EVERY_SECS
            idle = (now - last_edge) >= IDLE_SECS
            if len(window) >= MIN_EDGES and stats["edges_since_score"] > 0 and (due or idle):
                run_scoring(scorer, driver, window)
                stats["edges_since_score"] = 0
                last_score = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        driver.close()
        logger.info("final stats: %s", stats)


if __name__ == "__main__":
    main()
