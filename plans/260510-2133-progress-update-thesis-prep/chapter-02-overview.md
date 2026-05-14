# Chapter 2 — System Overview

## 2.1 Goals

The system implements end-to-end EDR functionality: ingest enterprise security telemetry, construct a provenance graph, detect malicious activity through both rule-based and ML-based methods, and present incidents to analysts. Three principles guide the design:

1. **Heterogeneous-source unification.** All log types — network captures, IDS alerts, OS event logs, database queries, web access logs — normalize into a single provenance schema.
2. **Streaming, not batch.** Events flow through a message queue; detection runs as events arrive. There is no offline analysis phase.
3. **Two detection layers, one graph.** Rules and ML both annotate the same Neo4j provenance graph. Neither suppresses the other; both contribute to the analyst-facing incident view.

## 2.2 High-level architecture

```
simulator ──► rabbitmq(raw_events) ──► ingest ──► rabbitmq(normalized_events)
                                                          │
                                              ┌───────────┼─────────────┐
                                              ▼           ▼             ▼
                                       graph-builder  rule-engine  ml-edge-scorer
                                              │           │             │
                                              ▼           ▼             ▼
                                            neo4j ◄── api ──► incidents/scores
                                                       │             │
                                                   dashboard    llm-analyzer
```

All services run in Docker Compose. Communication is via RabbitMQ (event bus) and Neo4j (state).

## 2.3 Service responsibilities

| Service | Responsibility |
|---|---|
| `simulator` | Replays Splunk BOTSv2 events into the `raw_events` queue |
| `ingest` | Per-sourcetype parsers extract typed fields from `_raw`; emit `NormalizedEvent` with subject/edge/object triple |
| `graph-builder` | Batches MERGE operations into Neo4j; maintains 9 node labels × 14 edge types |
| `rule-engine` | 36 Sigma-style YAML rules; FSM matches causal edge sequences; writes Incident nodes |
| `ml-edge-scorer` | LightGBMXT scores each edge with two model variants; writes scores onto edges; publishes alerts |
| `llm-analyzer` | On ML alert, pulls 2-hop subgraph and generates Claude-Sonnet narrative |
| `api` | FastAPI; Neo4j queries for graph stats, incidents, subgraph exploration |
| `dashboard` | React + Fluent UI; overview, incident list with causal chain visualization, ML findings table |

## 2.4 Data model

**Nodes (9):** Process, File, Socket, Registry, Memory, Pipe, Host, User, Url

**Edges (14):** FORK, EXEC, READ, WRITE, CONNECT, SEND, RECEIVE, MMAP, RENAME, DELETE, LOAD, MODIFY_REG, ACCESS, AUTH

Each edge stores the subject UUID, object UUID, edge type, timestamp, and (where applicable) raw event fields used for ML scoring. Edges flagged by the rule engine acquire an `Incident` node linkage; edges scored by the ML engine carry `botsv2_ml_score` and `botsv2_ml_score_honest` properties.

## 2.5 Detection pipeline

For each event arriving on `normalized_events`:

1. **graph-builder** writes the edge to Neo4j.
2. **rule-engine** checks if the edge advances any active rule's FSM; matches produce Incident nodes.
3. **ml-edge-scorer** constructs the 39-column feature row, scores with both LightGBMXT variants, writes scores to the edge, and publishes to `ml_alerts` if either score crosses the threshold (≥0.9 headline, ≥0.7 honest).
4. **llm-analyzer** consumes ML alerts and generates incident narratives.

Rules and ML do not gate each other — every edge is graphed regardless, and both detection layers contribute orthogonal evidence to the analyst view.
