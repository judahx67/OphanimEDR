"""
THEIA GNN windowed scorer.

Replaces the per-edge BOTSv2 LightGBM scorer for the THEIA data plane. The FLASH
GraphSAGE model is a *sparse-seed graph anomaly detector*, not a per-event
classifier: a node's embedding and the explain-away confidence are batch-relative
(normalized across the graph), so single events carry no signal. This service
therefore accumulates normalized THEIA edges into a sliding provenance window and
scores nodes *in context*.

Flow:
  edr_fanout -> normalized_events_gnn (own queue) -> sliding window (deque)
  every SCORE_EVERY_SECS: build graph -> Word2Vec embed -> 20-shard explain-away
  surviving nodes = seeds -> SET :gnn_seed in Neo4j (by uuid) -> publish ml_alerts

Weights/code mounted at /app/theia (server/ml-engine/theia, env THEIA_WEIGHTS).
"""

import collections
import json
import logging
import os
import signal
import sys
import time

import numpy as np
import pika
import torch
from gensim.models import Word2Vec
from neo4j import GraphDatabase

sys.path.insert(0, os.environ.get("THEIA_CODE", "/app/theia"))
import theia_flash_common as fc  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("theia-gnn-scorer")

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

EXCHANGE = "edr"
GNN_QUEUE = "normalized_events_gnn"
ML_ALERTS_QUEUE = "ml_alerts"

CODE_ROOT = os.environ.get("THEIA_CODE", "/app/theia")
WEIGHTS = os.path.join(CODE_ROOT, os.environ.get(
    "THEIA_WEIGHTS", "trained_weights/theia_ours_v3"))
N_SHARDS = int(os.environ.get("N_SHARDS", "20"))
CONF_THRESHOLD = float(os.environ.get("CONF_THRESHOLD", "0.53"))

# SCORE_MODE: "full" accumulates the entire provenance graph and scores it with
# NeighborLoader exactly like evaluate.py (the paper regime); "window" keeps the
# legacy sliding-window behaviour. Full mode is required to reproduce the offline
# evaluation live — the GNN embedding is batch-relative, so a 20k fragment changes
# the explain-away survivors vs. the full graph.
SCORE_MODE = os.environ.get("SCORE_MODE", "full")
WINDOW_EDGES = int(os.environ.get("WINDOW_EDGES", "20000"))
MIN_EDGES = int(os.environ.get("MIN_EDGES", "300"))
SCORE_EVERY_SECS = float(os.environ.get("SCORE_EVERY_SECS", "60"))
# Re-score once the stream has been quiet this long (replay finished) so the
# final full-graph score reflects everything ingested.
IDLE_SECS = float(os.environ.get("IDLE_SECS", "15"))
# Bound the embedding cache so a long replay can't grow it without limit.
EMB_CACHE_CAP = int(os.environ.get("EMB_CACHE_CAP", "2000000"))

device = torch.device("cpu")
running = True


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


class Scorer:
    """Loads the v3 model once and scores a graph via 20-shard explain-away.

    Mirrors evaluate.py exactly: NeighborLoader batched forward, conf/conf.max()
    normalisation, flag cleared for confidently-correctly-typed nodes. A node
    that survives all 20 shards is an anomaly "seed". Word2Vec inference is
    cached per token-document so re-scoring an accumulating graph only embeds
    nodes whose document changed since the last round.
    """

    def __init__(self):
        self.w2v = Word2Vec.load(os.path.join(WEIGHTS, "word2vec_theia_E3.model"))
        self.enc = fc.PositionalEncoder()
        self.model = fc.GCN(fc.VECTOR_SIZE, 5).to(device)
        self.state_dicts = [
            torch.load(os.path.join(WEIGHTS, f"lword2vec_gnn_theia{m}_E3.pth"),
                       map_location=device, weights_only=True)
            for m in range(N_SHARDS)
        ]
        self.emb_cache: dict[tuple, np.ndarray] = {}
        logger.info("loaded v3: w2v vocab=%d, %d shards from %s (mode=%s)",
                    len(self.w2v.wv), len(self.state_dicts), WEIGHTS, SCORE_MODE)

    def _featurize(self, phrases):
        if len(self.emb_cache) > EMB_CACHE_CAP:
            self.emb_cache.clear()
        out = np.empty((len(phrases), fc.VECTOR_SIZE), dtype=np.float32)
        for i, p in enumerate(phrases):
            key = tuple(p)
            v = self.emb_cache.get(key)
            if v is None:
                v = fc.infer(p, self.w2v, self.enc).astype(np.float32)
                self.emb_cache[key] = v
            out[i] = v
        return out

    def score(self, df):
        """Return (seed_uuids, scored_uuids). Seeds survive all explain-away rounds.

        evaluate.py uses NeighborLoader(num_neighbors=[-1,-1]) — full neighbour
        expansion, i.e. no sampling — which is mathematically identical to a
        single full-batch forward over the whole graph. We do the latter to
        avoid the pyg-lib/torch-sparse dependency NeighborLoader requires, while
        keeping evaluate.py's conf/conf.max() normalisation exactly.
        """
        phrases, labels, edges, mapp = fc.prepare_graph(df)
        if len(mapp) < 2 or not edges[0]:
            return set(), set()
        g_x = torch.tensor(self._featurize(phrases), dtype=torch.float).to(device)
        g_ei = torch.tensor(edges, dtype=torch.long).to(device)
        y = torch.tensor(labels, dtype=torch.long).to(device)
        flag = torch.ones(len(mapp), dtype=torch.bool)
        for sd in self.state_dicts:
            self.model.load_state_dict(sd)
            self.model.eval()
            with torch.no_grad():
                out = self.model(g_x, g_ei)
            s, ind = out.sort(dim=1, descending=True)
            conf = (s[:, 0] - s[:, 1]) / s[:, 0]
            cmax = conf.max()
            conf = (conf - conf.min()) / cmax if cmax > 0 else conf - conf.min()
            cond = (ind[:, 0] == y) & (conf > CONF_THRESHOLD)
            flag[cond] = False
        seeds = {mapp[i] for i in flag.nonzero(as_tuple=True)[0].tolist()}
        return seeds, set(mapp)


# CDM object type -> Neo4j label (mirrors ingest._CDM_NODE + graph-builder.LABELS).
# Used so the seed write MATCHes per-label and hits the per-label uuid index;
# a label-less MATCH (n {uuid}) does an AllNodesScan per row -> O(N^2) at scale.
CDM_LABEL = {
    "SUBJECT_PROCESS": "Process",
    "FILE_OBJECT_BLOCK": "File", "FILE_OBJECT_FILE": "File", "FILE_OBJECT_DIR": "File",
    "NetFlowObject": "Socket",
    "MemoryObject": "Memory",
    "UnnamedPipeObject": "Pipe",
    "PRINCIPAL_LOCAL": "User", "PRINCIPAL_REMOTE": "User",
}
VALID_LABELS = {"Process", "File", "Socket", "Memory", "Pipe", "User"}
DEFAULT_LABEL = "File"

# Dynamic label can't be parameterised in Cypher; we group rows by label and
# interpolate the (enum-restricted) label into the query.
_WRITE_CYPHER = (
    "UNWIND $rows AS row "
    "MATCH (n:`{label}` {{uuid: row.uuid}}) "
    "SET n.gnn_seed = row.seed, n.gnn_scored_at = row.scored_at"
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


def run_scoring(scorer, driver, channel, window):
    import pandas as pd
    rows = list(window)
    df = pd.DataFrame(rows, columns=["actorID", "actor_type", "objectID",
                                     "object", "action", "exec", "path"]).astype(str)
    t0 = time.time()
    seeds, scored = scorer.score(df)
    now_ms = int(time.time() * 1000)

    # uuid -> Neo4j label from the window (actorID/actor_cdm, objectID/object_cdm)
    uuid_label = {}
    for r in rows:
        uuid_label[r[0]] = CDM_LABEL.get(r[1], DEFAULT_LABEL)
        uuid_label[r[2]] = CDM_LABEL.get(r[3], DEFAULT_LABEL)

    # Publish seeds FIRST so the metric/LLM don't depend on the (slower) Neo4j
    # write completing.
    for u in seeds:
        channel.basic_publish(
            exchange=EXCHANGE, routing_key="ml_alert",
            body=json.dumps({"node_id": u, "dataset": "theia",
                             "detector": "gnn_v3", "timestamp": now_ms}),
            properties=pika.BasicProperties(delivery_mode=2,
                                            content_type="application/json"),
        )

    # Group scored nodes by label, write per-label (uses per-label uuid index).
    by_label = {}
    for u in scored:
        by_label.setdefault(uuid_label.get(u, DEFAULT_LABEL), []).append(
            {"uuid": u, "seed": (u in seeds), "scored_at": now_ms})
    with driver.session() as session:
        for label, wr in by_label.items():
            if label not in VALID_LABELS:
                continue
            session.run(_WRITE_CYPHER.format(label=label), rows=wr)
    logger.info("scored window: edges=%d nodes=%d seeds=%d (%.1fs)",
                len(rows), len(scored), len(seeds), time.time() - t0)


def main():
    logger.info("=== THEIA GNN Windowed Scorer ===")
    scorer = Scorer()
    driver = connect_neo4j()
    conn = connect_rabbitmq()
    channel = conn.channel()
    channel.exchange_declare(exchange="edr_fanout", exchange_type="fanout", durable=True)
    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=GNN_QUEUE, durable=True)
    channel.queue_bind(exchange="edr_fanout", queue=GNN_QUEUE)
    channel.queue_declare(queue=ML_ALERTS_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=ML_ALERTS_QUEUE, routing_key="ml_alert")
    channel.basic_qos(prefetch_count=500)

    # Full mode accumulates the whole graph (unbounded); window mode caps it.
    maxlen = None if SCORE_MODE == "full" else WINDOW_EDGES
    window = collections.deque(maxlen=maxlen)
    stats = {"received": 0, "scored_runs": 0, "edges_since_score": 0}
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

    channel.basic_consume(queue=GNN_QUEUE, on_message_callback=on_message)
    logger.info("mode=%s window=%s min=%d score_every=%.0fs idle=%.0fs",
                SCORE_MODE, maxlen, MIN_EDGES, SCORE_EVERY_SECS, IDLE_SECS)
    try:
        while running:
            conn.process_data_events(time_limit=1)
            now = time.time()
            # Score when there is new data AND we're either due (periodic) or the
            # stream has gone idle (replay finished -> final full-graph score).
            due = (now - last_score) >= SCORE_EVERY_SECS
            idle = (now - last_edge) >= IDLE_SECS
            if len(window) >= MIN_EDGES and stats["edges_since_score"] > 0 and (due or idle):
                run_scoring(scorer, driver, channel, window)
                stats["scored_runs"] += 1
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
