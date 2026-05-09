"""
LLM Analyzer Service.

Consumes ml_alerts from RabbitMQ. For each alert:
  1. Pull a 2-hop subgraph from Neo4j around the flagged edge.
  2. Send the subgraph + alert context to Claude (via Anthropic SDK).
  3. Write the LLM narrative back as a Neo4j Incident node linked to the edge.

Uses prompt caching on the system prompt (cached across all alerts in a session).
Caps throughput to MAX_NARRATIVES_PER_RUN to avoid API budget blowout during demo.
"""

import json
import logging
import os
import signal
import time

import pika
from neo4j import GraphDatabase
import anthropic

from subgraph import pull_subgraph, subgraph_to_text

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("llm-analyzer")

# ── Config ────────────────────────────────────────────────────────────────

RABBITMQ_HOST = os.environ.get("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.environ.get("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.environ.get("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.environ.get("RABBITMQ_PASS", "guest")

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "edr-thesis")

ML_ALERTS_QUEUE = "ml_alerts"
EXCHANGE = "edr"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# claude-sonnet-4-6 is fast + cost-effective for short structured analysis
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")

# Cap narratives per run to control API spend during thesis demo
MAX_NARRATIVES = int(os.environ.get("MAX_NARRATIVES_PER_RUN", "50"))

# ── System prompt (cached) ────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for an EDR (Endpoint Detection and Response) system.

You will be given a provenance graph subgraph representing suspicious activity detected by a LightGBM anomaly-detection model trained on the BOTS v2 security dataset. The model outputs two scores:
- headline score (may include sourcetype as a feature)
- honest score (sourcetype excluded to avoid leakage)

Your task is to analyse the subgraph and produce a structured incident analysis.

## Output Format (JSON only, no prose outside this structure)
{
  "attack_hypothesis": "One sentence describing the likely attack or suspicious behaviour",
  "mitre_technique": "e.g. T1059.001 - Command and Scripting Interpreter: PowerShell (or null if unclear)",
  "mitre_tactic": "e.g. Execution (or null if unclear)",
  "evidence_summary": "2-4 bullet points of specific indicators from the subgraph",
  "confidence": "high | medium | low",
  "analyst_action": "Specific recommended next step for a human analyst",
  "false_positive_risk": "high | medium | low — likelihood this is benign activity"
}

Be concise and precise. Base your analysis only on the provided subgraph data. If the data is insufficient, say so in evidence_summary and set confidence to low."""

# ── Shutdown ──────────────────────────────────────────────────────────────

running = True


def signal_handler(sig, frame):
    global running
    logger.info("Shutting down...")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ── Neo4j ─────────────────────────────────────────────────────────────────

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


_WRITE_INCIDENT_CYPHER = """
MERGE (i:Incident {event_id: $event_id, source: 'ml-llm'})
SET
  i.title           = $title,
  i.attack_hypothesis = $attack_hypothesis,
  i.mitre_technique = $mitre_technique,
  i.mitre_tactic    = $mitre_tactic,
  i.evidence_summary = $evidence_summary,
  i.confidence      = $confidence,
  i.analyst_action  = $analyst_action,
  i.false_positive_risk = $false_positive_risk,
  i.narrative_raw   = $narrative_raw,
  i.score_headline  = $score_headline,
  i.score_honest    = $score_honest,
  i.severity        = $severity,
  i.created_at      = $created_at,
  i.endpoint_id     = $endpoint_id
WITH i
MATCH ()-[r {event_id: $event_id}]->()
MERGE (i)-[:TRIGGERED_BY]->(r)
"""


def write_incident(driver, alert: dict, analysis: dict, narrative_raw: str) -> None:
    confidence = analysis.get("confidence", "low")
    severity = {"high": "critical", "medium": "high", "low": "medium"}.get(confidence, "medium")

    with driver.session() as session:
        session.run(
            _WRITE_INCIDENT_CYPHER,
            event_id=alert["event_id"],
            title=analysis.get("attack_hypothesis", "ML-detected anomaly")[:120],
            attack_hypothesis=analysis.get("attack_hypothesis", ""),
            mitre_technique=analysis.get("mitre_technique") or "",
            mitre_tactic=analysis.get("mitre_tactic") or "",
            evidence_summary=json.dumps(analysis.get("evidence_summary", "")),
            confidence=confidence,
            analyst_action=analysis.get("analyst_action", ""),
            false_positive_risk=analysis.get("false_positive_risk", "unknown"),
            narrative_raw=narrative_raw,
            score_headline=alert.get("score_headline", 0.0),
            score_honest=alert.get("score_honest", 0.0),
            severity=severity,
            created_at=int(time.time() * 1000),
            endpoint_id=alert.get("endpoint_id", ""),
        )


# ── LLM call ─────────────────────────────────────────────────────────────

def analyze_with_llm(client: anthropic.Anthropic, subgraph_text: str) -> tuple[dict, str]:
    """Call Claude with prompt caching on the system prompt. Returns (parsed_json, raw_text)."""
    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=1024,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Analyse this provenance subgraph alert:\n\n{subgraph_text}",
            }
        ],
    )

    raw = response.content[0].text.strip()

    # Extract JSON from the response (may have markdown fences)
    json_str = raw
    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            stripped = part.strip()
            if stripped.startswith("{"):
                json_str = stripped
                break

    try:
        analysis = json.loads(json_str)
    except json.JSONDecodeError:
        analysis = {
            "attack_hypothesis": "Parse error — see narrative_raw",
            "mitre_technique": None,
            "mitre_tactic": None,
            "evidence_summary": raw[:500],
            "confidence": "low",
            "analyst_action": "Review raw LLM output",
            "false_positive_risk": "unknown",
        }

    return analysis, raw


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
    logger.info("=== LLM Analyzer Service ===")

    if not ANTHROPIC_API_KEY:
        logger.error("ANTHROPIC_API_KEY not set — exiting")
        return

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    neo4j_driver = connect_neo4j()
    conn = connect_rabbitmq()
    channel = conn.channel()

    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=ML_ALERTS_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=ML_ALERTS_QUEUE, routing_key="ml_alert")

    # Only one alert at a time (LLM calls are slow)
    channel.basic_qos(prefetch_count=1)

    stats = {"received": 0, "analyzed": 0, "skipped": 0, "errors": 0}
    narratives_written = 0
    last_log = time.time()

    def on_message(ch, method, properties, body):
        nonlocal last_log, narratives_written
        try:
            alert = json.loads(body)
            stats["received"] += 1

            if narratives_written >= MAX_NARRATIVES:
                logger.info("Reached MAX_NARRATIVES=%d cap, dropping alert", MAX_NARRATIVES)
                stats["skipped"] += 1
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

            subj = alert.get("subject") or {}
            obj = alert.get("object") or {}
            subj_id = subj.get("id", "")
            obj_id = obj.get("id", "")

            subgraph = pull_subgraph(neo4j_driver, subj_id, obj_id, hops=2)
            subgraph_text = subgraph_to_text(subgraph, alert)

            analysis, raw = analyze_with_llm(client, subgraph_text)
            write_incident(neo4j_driver, alert, analysis, raw)

            narratives_written += 1
            stats["analyzed"] += 1
            logger.info(
                "Incident written for event_id=%s confidence=%s mitre=%s",
                alert.get("event_id", "?"),
                analysis.get("confidence", "?"),
                analysis.get("mitre_technique", "?"),
            )

            ch.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            stats["errors"] += 1
            logger.error("LLM analysis error: %s", e, exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        now = time.time()
        if now - last_log > 30:
            logger.info(
                "Stats: received=%d analyzed=%d skipped=%d errors=%d (cap=%d)",
                stats["received"], stats["analyzed"], stats["skipped"],
                stats["errors"], MAX_NARRATIVES,
            )
            last_log = now

    channel.basic_consume(queue=ML_ALERTS_QUEUE, on_message_callback=on_message)
    logger.info("Waiting for ML alerts (cap=%d narratives)...", MAX_NARRATIVES)

    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    finally:
        conn.close()
        neo4j_driver.close()
        logger.info("Final stats: %s", stats)


if __name__ == "__main__":
    main()
