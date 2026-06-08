"""
LLM Analyzer Service.

Consumes ml_alerts from RabbitMQ. For each alert:
  1. Pull a 1-hop subgraph from Neo4j around the flagged edge.
  2. Send the subgraph + alert context to Gemini (via google-genai SDK).
  3. Write the LLM narrative back as a Neo4j Incident node linked to the edge.

LLM choice is provisional pending prompt-tuning work — the analyzer may switch
to Anthropic later; the prompt format and Neo4j write contract are model-agnostic.

Caps throughput to MAX_NARRATIVES_PER_RUN to avoid API budget blowout during demo.
Sleeps GEMINI_PACING_SECONDS between calls to stay under per-minute rate limits.
"""

import json
import logging
import os
import signal
import time

import pika
from neo4j import GraphDatabase
from google import genai
from google.genai import types as genai_types

from subgraph import pull_subgraph, subgraph_to_text, subgraph_to_matched
from mitre import load_techniques, select_candidates, format_candidates_for_prompt
import groq_provider

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

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
# gemini-2.0-flash has the most generous free-tier quota (≈1500 req/day),
# enough for sustained narrative generation during the demo. Override via
# env if a paid key is wired up later.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
# Sleep between Gemini calls to stay under per-minute rate limits.
GEMINI_PACING_SECONDS = float(os.environ.get("GEMINI_PACING_SECONDS", "2.0"))

# Cap narratives per run to control API spend during thesis demo
MAX_NARRATIVES = int(os.environ.get("MAX_NARRATIVES_PER_RUN", "50"))

# Dedup window: suppress repeated alerts for the same (subj, obj, edge_type)
# pattern within this many seconds. Prevents LLM flood on repeated events.
DEDUP_WINDOW_SECONDS = int(os.environ.get("DEDUP_WINDOW_SECONDS", "300"))

# ── System prompt (cached) ────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for an EDR (Endpoint Detection and Response) system.

You will be given a provenance graph subgraph representing suspicious activity detected by a LightGBM anomaly-detection model trained on the BOTS v2 security dataset. The model outputs two scores:
- headline score (may include sourcetype as a feature)
- honest score (sourcetype excluded to avoid leakage)

Your task is to analyse the subgraph and produce a structured incident analysis.

If a "MITRE Candidates" section is provided in the user message, the
mitre_technique field MUST be one of those IDs (or null if none fit).
Without that section, fall back to your own MITRE judgement.

## Output Format (JSON only, no prose outside this structure)
{
  "attack_hypothesis": "One sentence describing the likely attack or suspicious behaviour",
  "mitre_technique": "e.g. T1059.001 (or null if unclear; if MITRE Candidates section was provided you MUST pick from those IDs)",
  "mitre_tactic": "e.g. Execution (or null if unclear)",
  "evidence_summary": "2-4 bullet points of specific indicators from the subgraph",
  "confidence": "high | medium | low",
  "analyst_action": "Specific recommended next step for a human analyst",
  "false_positive_risk": "high | medium | low — likelihood this is benign activity",
  "yara_rule": "A valid YARA rule string targeting a stable artefact from this alert (filename, command-line string, URI path, registry key). Null if no stable signature exists or if the only indicators are dynamic (IPs, timestamps, ephemeral ports). The rule MUST be syntactically valid YARA, named after the attack pattern (snake_case), and include a meta block with author='edr-llm-analyzer' and a reference to the event_id."
}

Be concise and precise. Base your analysis only on the provided subgraph data. If the data is insufficient, say so in evidence_summary and set confidence to low."""

# THEIA GNN path: the detector is a graph anomaly seed-finder, not a per-edge
# classifier. The prompt below replaces the BOTSv2/LightGBM framing so the LLM
# reasons about the flagged *node* and its provenance context correctly.
THEIA_SYSTEM_PROMPT = """You are a cybersecurity analyst assistant for a host-provenance intrusion-detection system.

You will be given a provenance subgraph centred on a NODE flagged by a FLASH GraphSAGE + Word2Vec graph-anomaly detector (trained on DARPA TC E3 THEIA host telemetry). The detector runs a 20-shard explain-away ensemble over a sliding provenance window: a node is flagged as an anomaly "seed" when it survives every round (the ensemble cannot confidently explain its embedding given the surrounding graph). Scores are batch-relative, so reason about the node's role in its 1-hop neighbourhood, not an absolute probability.

Your task is to analyse the flagged node + neighbourhood and produce a structured incident analysis.

If a "MITRE Candidates" section is provided in the user message, the
mitre_technique field MUST be one of those IDs (or null if none fit).
Without that section, fall back to your own MITRE judgement.

## Output Format (JSON only, no prose outside this structure)
{
  "attack_hypothesis": "One sentence describing the likely attack or suspicious behaviour involving this node",
  "mitre_technique": "e.g. T1059.001 (or null if unclear; if MITRE Candidates section was provided you MUST pick from those IDs)",
  "mitre_tactic": "e.g. Execution (or null if unclear)",
  "evidence_summary": "2-4 bullet points of specific indicators from the subgraph",
  "confidence": "high | medium | low",
  "analyst_action": "Specific recommended next step for a human analyst",
  "false_positive_risk": "high | medium | low — likelihood this is benign activity",
  "yara_rule": "A valid YARA rule string targeting a stable artefact (filename, path, command-line string). Null if the only indicators are dynamic (IPs, ephemeral ports, netflow). MUST be syntactically valid YARA, snake_case name, meta block with author='edr-llm-analyzer' and a reference to the node_id."
}

Be concise and precise. Base your analysis only on the provided subgraph data. THEIA E3 ground truth is netflow-heavy, so many seeds are network objects — note when a seed is a NetFlow/Socket node and temper false_positive_risk accordingly. If data is insufficient, say so and set confidence to low."""

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


_NODE_PROPS_CYPHER = """
MATCH (n {uuid: $node_id})
RETURN labels(n)[0] AS label, coalesce(n.name, '') AS name,
       coalesce(n.endpoint_id, '') AS endpoint_id
LIMIT 1
"""


def enrich_node_alert(driver, alert: dict) -> dict:
    """Normalise a THEIA GNN node-seed alert into the analyzer's alert shape.

    The GNN scorer publishes {node_id, dataset, detector, timestamp}. We look
    up the node's label/name from Neo4j and synthesise the subject/object/
    event_id fields the rest of the pipeline (dedup, prune, MITRE, write) needs.
    """
    node_id = alert["node_id"]
    label, name, endpoint_id = "Node", "", ""
    with driver.session() as session:
        rec = session.run(_NODE_PROPS_CYPHER, node_id=node_id).single()
        if rec is not None:
            label = rec["label"] or "Node"
            name = rec["name"] or ""
            endpoint_id = rec["endpoint_id"] or ""
    side = {"id": node_id, "name": name, "node_type": label}
    return {
        **alert,
        "is_node_alert": True,
        "event_id": node_id,
        "edge_type": alert.get("detector", "gnn"),
        "subject": side,
        "object": side,
        "score": 1.0,
        "endpoint_id": endpoint_id,
    }


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
  i.yara_rule       = $yara_rule,
  i.agreement_status     = $agreement_status,
  i.secondary_model      = $secondary_model,
  i.secondary_mitre      = $secondary_mitre,
  i.secondary_confidence = $secondary_confidence,
  i.secondary_hypothesis = $secondary_hypothesis,
  i.score           = $score,
  i.severity        = $severity,
  i.created_at      = $created_at,
  i.endpoint_id     = $endpoint_id,
  i.matched_nodes   = $matched_nodes,
  i.matched_edges   = $matched_edges,
  i.root_node_id    = $root_node_id
WITH i
// Root the incident at the flagged node (GNN seed uuid = event_id). Node-rooted,
// not edge-rooted: the GNN flags a node, so we link the incident to that node and
// persist its causal neighbourhood as matched_nodes/matched_edges above.
OPTIONAL MATCH (root {uuid: $root_node_id})
FOREACH (_ IN CASE WHEN root IS NULL THEN [] ELSE [1] END |
  MERGE (i)-[:TRIGGERED_BY {node_uuid: $root_node_id}]->(root)
)
"""

# THEIA node-seed variant: the alert keys on a flagged node (uuid), not an edge.
_WRITE_NODE_INCIDENT_CYPHER = """
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
  i.yara_rule       = $yara_rule,
  i.agreement_status     = $agreement_status,
  i.secondary_model      = $secondary_model,
  i.secondary_mitre      = $secondary_mitre,
  i.secondary_confidence = $secondary_confidence,
  i.secondary_hypothesis = $secondary_hypothesis,
  i.score           = $score,
  i.severity        = $severity,
  i.created_at      = $created_at,
  i.endpoint_id     = $endpoint_id,
  i.detector        = 'gnn_v3'
WITH i
MATCH (n {uuid: $event_id})
MERGE (i)-[:TRIGGERED_BY {node_uuid: $event_id}]->(n)
"""


def write_incident(
    driver,
    alert: dict,
    analysis: dict,
    narrative_raw: str,
    agreement: dict | None = None,
    subgraph: dict | None = None,
) -> None:
    confidence = analysis.get("confidence", "low")
    severity = {"high": "critical", "medium": "high", "low": "medium"}.get(confidence, "medium")
    agreement = agreement or {}
    cypher = _WRITE_NODE_INCIDENT_CYPHER if alert.get("is_node_alert") else _WRITE_INCIDENT_CYPHER

    # Persist the assembled causal subgraph so the dashboard CausalChain has data.
    matched_nodes, matched_edges = subgraph_to_matched(subgraph or {"nodes": [], "edges": []})

    with driver.session() as session:
        session.run(
            cypher,
            event_id=alert["event_id"],
            matched_nodes=json.dumps(matched_nodes),
            matched_edges=json.dumps(matched_edges),
            root_node_id=alert.get("event_id", ""),
            title=analysis.get("attack_hypothesis", "ML-detected anomaly")[:120],
            attack_hypothesis=analysis.get("attack_hypothesis", ""),
            mitre_technique=analysis.get("mitre_technique") or "",
            mitre_tactic=analysis.get("mitre_tactic") or "",
            evidence_summary=json.dumps(analysis.get("evidence_summary", "")),
            confidence=confidence,
            analyst_action=analysis.get("analyst_action", ""),
            false_positive_risk=analysis.get("false_positive_risk", "unknown"),
            narrative_raw=narrative_raw,
            yara_rule=analysis.get("yara_rule") or "",
            score=alert.get("score", 0.0),
            severity=severity,
            created_at=int(time.time() * 1000),
            endpoint_id=alert.get("endpoint_id", ""),
            agreement_status=agreement.get("agreement_status", "disabled"),
            secondary_model=agreement.get("secondary_model", ""),
            secondary_mitre=agreement.get("secondary_mitre", ""),
            secondary_confidence=agreement.get("secondary_confidence", ""),
            secondary_hypothesis=agreement.get("secondary_hypothesis", ""),
        )


# ── LLM call ─────────────────────────────────────────────────────────────

def analyze_with_llm(
    client: genai.Client,
    subgraph_text: str,
    mitre_section: str = "",
    system_prompt: str = SYSTEM_PROMPT,
) -> tuple[dict, str, dict]:
    """Call Gemini and request JSON output.

    Returns (parsed_json, raw_text, usage) where usage has prompt/output/total
    token counts pulled from the Gemini response's usage_metadata. Used by the
    main loop to track per-alert token spend and surface budget pressure.

    Retries on transient 429 RESOURCE_EXHAUSTED using the server-suggested
    delay; gives up after 3 attempts and propagates the error.
    """
    cfg = genai_types.GenerateContentConfig(
        system_instruction=system_prompt,
        response_mime_type="application/json",
        # 800 fits the 7-field schema + a small YARA rule comfortably.
        # 2048 caused gemini-2.5-flash-lite to drift into degenerate token
        # loops (emitting "0000..." until cap) on a non-trivial fraction of
        # alerts — wasted budget AND broke JSON parsing.
        max_output_tokens=800,
    )
    # gemini-2.5-* models add a "thinking" budget that eats output tokens
    # before any visible text. Disable it when present.
    if "2.5" in GEMINI_MODEL:
        cfg.thinking_config = genai_types.ThinkingConfig(thinking_budget=0)

    last_err: Exception | None = None
    for attempt in range(3):
        try:
            user_msg = f"Analyse this provenance subgraph alert:\n\n{subgraph_text}"
            if mitre_section:
                user_msg += f"\n\n{mitre_section}"
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=user_msg,
                config=cfg,
            )
            break
        except Exception as e:
            last_err = e
            msg = str(e)
            if "429" in msg or "RESOURCE_EXHAUSTED" in msg:
                # Parse retryDelay if present, fallback to exponential backoff.
                import re
                m = re.search(r"retry in ([0-9.]+)s", msg)
                wait = float(m.group(1)) + 1.0 if m else (2 ** attempt) * 5.0
                logger.warning("Gemini 429, retrying in %.1fs (attempt %d/3)", wait, attempt + 1)
                time.sleep(wait)
                continue
            raise
    else:
        raise last_err  # type: ignore[misc]

    raw = (response.text or "").strip()

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
            "yara_rule": None,
        }

    um = getattr(response, "usage_metadata", None)
    usage = {
        "prompt_tokens": getattr(um, "prompt_token_count", 0) or 0,
        "output_tokens": getattr(um, "candidates_token_count", 0) or 0,
        "total_tokens": getattr(um, "total_token_count", 0) or 0,
    }

    # Surface truncation explicitly — flash-lite drifts into degenerate
    # repeat-token loops on some inputs, hitting max_output_tokens with
    # garbage. Logging finish_reason makes that visible without a debugger.
    cands = getattr(response, "candidates", None) or []
    finish_reason = ""
    if cands:
        fr = getattr(cands[0], "finish_reason", None)
        finish_reason = getattr(fr, "name", str(fr or ""))
    if finish_reason and finish_reason not in ("STOP", "FINISH_REASON_STOP"):
        logger.warning("Gemini finish_reason=%s (output may be truncated/malformed)", finish_reason)
    usage["finish_reason"] = finish_reason

    return analysis, raw, usage


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

    if not GEMINI_API_KEY:
        logger.error("GEMINI_API_KEY not set — exiting")
        return

    client = genai.Client(api_key=GEMINI_API_KEY)
    mitre_techniques = load_techniques()
    neo4j_driver = connect_neo4j()

    groq_client = None
    if groq_provider.is_enabled():
        try:
            groq_client = groq_provider.make_client()
            logger.info("Groq second-opinion enabled (model=%s)", groq_provider.GROQ_MODEL)
        except Exception as e:
            logger.warning("Groq enabled but client init failed (%s) — running Gemini-only", e)
    else:
        logger.info("Groq second-opinion disabled (set GROQ_API_KEY to enable)")
    conn = connect_rabbitmq()
    channel = conn.channel()

    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=ML_ALERTS_QUEUE, durable=True)
    channel.queue_bind(exchange=EXCHANGE, queue=ML_ALERTS_QUEUE, routing_key="ml_alert")

    # Only one alert at a time (LLM calls are slow)
    channel.basic_qos(prefetch_count=1)

    stats = {
        "received": 0, "analyzed": 0, "deduped": 0, "skipped": 0, "errors": 0,
        "tokens_prompt": 0, "tokens_output": 0, "tokens_total": 0,
        "subgraph_chars_total": 0,
    }
    narratives_written = 0
    last_log = time.time()
    # dedup_cache: pattern_key → (first_seen_ts, duplicate_count)
    dedup_cache: dict[str, tuple[float, int]] = {}

    def _dedup_key(alert: dict) -> str:
        subj = alert.get("subject") or {}
        obj = alert.get("object") or {}
        edge_key = f"{subj.get('id','')}|{obj.get('id','')}|{alert.get('edge_type','')}"
        # Node-rooted (GNN) alerts carry no subject/object — key on the node id so
        # distinct seeds aren't collapsed into a single dedup bucket ("||").
        if edge_key == "||":
            return alert.get("event_id") or alert.get("node_id") or "||"
        return edge_key

    def _prune_dedup_cache() -> None:
        cutoff = time.time() - DEDUP_WINDOW_SECONDS
        expired = [k for k, (ts, _) in dedup_cache.items() if ts < cutoff]
        for k in expired:
            del dedup_cache[k]

    def on_message(ch, method, properties, body):
        nonlocal last_log, narratives_written
        try:
            alert = json.loads(body)
            # GNN alerts publish node_id only; the rest of the path keys on
            # event_id. Normalize so a node-rooted alert behaves like an edge one.
            alert.setdefault("event_id", alert.get("node_id", ""))
            stats["received"] += 1

            # THEIA GNN scorer emits node-level seeds; normalise to alert shape.
            if alert.get("node_id") and not alert.get("event_id"):
                alert = enrich_node_alert(neo4j_driver, alert)

            if narratives_written >= MAX_NARRATIVES:
                logger.info("Reached MAX_NARRATIVES=%d cap, dropping alert", MAX_NARRATIVES)
                stats["skipped"] += 1
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return

            # Dedup: if same (subj, obj, edge_type) seen recently, skip LLM call
            _prune_dedup_cache()
            key = _dedup_key(alert)
            now = time.time()
            if key in dedup_cache:
                first_ts, count = dedup_cache[key]
                dedup_cache[key] = (first_ts, count + 1)
                stats["deduped"] += 1
                ch.basic_ack(delivery_tag=method.delivery_tag)
                return
            dedup_cache[key] = (now, 0)

            subj = alert.get("subject") or {}
            obj = alert.get("object") or {}
            # Node-rooted GNN alerts have no subject/object — root the subgraph at
            # the flagged node itself so pull_subgraph returns its neighbourhood.
            subj_id = subj.get("id", "") or alert.get("event_id", "")
            obj_id = obj.get("id", "") or alert.get("event_id", "")

            # 1-hop keeps context manageable; 2-hop can reach 60+ nodes on busy hosts
            subgraph = pull_subgraph(neo4j_driver, subj_id, obj_id, hops=1)
            # Annotate how many duplicate alerts were suppressed
            alert["_dedup_count"] = dedup_cache[key][1]
            is_node = alert.get("is_node_alert", False)
            system_prompt = THEIA_SYSTEM_PROMPT if is_node else SYSTEM_PROMPT
            subgraph_text = (node_subgraph_to_text(subgraph, alert) if is_node
                             else subgraph_to_text(subgraph, alert))

            mitre_candidates = select_candidates(mitre_techniques, alert, subgraph)
            mitre_section = format_candidates_for_prompt(mitre_candidates)

            analysis, raw, usage = analyze_with_llm(client, subgraph_text, mitre_section, system_prompt)

            agreement: dict | None = None
            if groq_client is not None:
                try:
                    user_msg = f"Analyse this provenance subgraph alert:\n\n{subgraph_text}"
                    if mitre_section:
                        user_msg += f"\n\n{mitre_section}"
                    secondary, _, sec_usage = groq_provider.analyze(
                        groq_client, system_prompt, user_msg,
                    )
                    agreement = groq_provider.compare(analysis, secondary)
                    stats["tokens_total"] += sec_usage.get("total_tokens", 0)
                    stats["tokens_prompt"] += sec_usage.get("prompt_tokens", 0)
                    stats["tokens_output"] += sec_usage.get("output_tokens", 0)
                    if groq_provider.GROQ_PACING_SECONDS > 0:
                        time.sleep(groq_provider.GROQ_PACING_SECONDS)
                except Exception as e:
                    logger.warning("Groq second-opinion failed: %s", e)
                    agreement = {"agreement_status": "secondary_error"}

            write_incident(neo4j_driver, alert, analysis, raw, agreement, subgraph=subgraph)

            narratives_written += 1
            stats["analyzed"] += 1
            stats["tokens_prompt"] += usage["prompt_tokens"]
            stats["tokens_output"] += usage["output_tokens"]
            stats["tokens_total"] += usage["total_tokens"]
            stats["subgraph_chars_total"] += len(subgraph_text)

            # Pace requests to stay under the per-minute free-tier rate limit.
            if GEMINI_PACING_SECONDS > 0:
                time.sleep(GEMINI_PACING_SECONDS)
            logger.info(
                "Incident written event_id=%s confidence=%s mitre=%s tokens=%d/%d subgraph_chars=%d mitre_candidates=%d agreement=%s",
                alert.get("event_id", "?"),
                analysis.get("confidence", "?"),
                analysis.get("mitre_technique", "?"),
                usage["prompt_tokens"], usage["output_tokens"],
                len(subgraph_text),
                len(mitre_candidates),
                (agreement or {}).get("agreement_status", "disabled"),
            )

            ch.basic_ack(delivery_tag=method.delivery_tag)

        except Exception as e:
            stats["errors"] += 1
            logger.error("LLM analysis error: %s", e, exc_info=True)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        now = time.time()
        if now - last_log > 30:
            n = max(stats["analyzed"], 1)
            logger.info(
                "Stats: received=%d analyzed=%d deduped=%d skipped=%d errors=%d "
                "tokens(total=%d prompt=%d out=%d, avg=%d/alert) avg_subgraph=%d chars (cap=%d)",
                stats["received"], stats["analyzed"], stats["deduped"],
                stats["skipped"], stats["errors"],
                stats["tokens_total"], stats["tokens_prompt"], stats["tokens_output"],
                stats["tokens_total"] // n,
                stats["subgraph_chars_total"] // n,
                MAX_NARRATIVES,
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
