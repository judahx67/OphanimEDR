# System Architecture

## Pipeline overview

```
simulator ──► rabbitmq(raw_events) ──► ingest ──► rabbitmq(normalized_events)
                                                           │
                                              ┌────────────┼────────────┐
                                              ▼            ▼            ▼
                                       graph-builder  rule-engine  ml-edge-scorer
                                              │            │            │
                                              ▼            ▼            ▼
                                           neo4j ◄─── api ──────► llm-analyzer
                                                          │
                                                      dashboard
```

All services run in Docker via `server/docker-compose.yml`.  
Single pipeline container (`server/pipeline/`) runs ingest + graph-builder + rule-engine + ml-edge-scorer under supervisord.

## Services

| Service | Port | Purpose |
|---|---|---|
| `simulator` | — | Replays BOTSv2 parquet events into RabbitMQ `raw_events` queue |
| `ingest` | — | 11 per-sourcetype parsers; emits `NormalizedEvent` to `edr_fanout` exchange |
| `graph-builder` | — | Batches to Neo4j; MERGE nodes by UUID, MERGE edges on `event_id` (idempotent) |
| `rule-engine` | — | 36 Sigma-inspired YAML rules; FSM causal-chain matching; writes `Incident` nodes |
| `ml-edge-scorer` | — | Scores each edge with LightGBMXT; writes `r.botsv2_ml_score` to Neo4j |
| `llm-analyzer` | — | Gemini narratives for ML alerts above threshold |
| `api` | 8000 | FastAPI: graph stats, incidents, subgraph exploration |
| `dashboard` | 3000 | React + Fluent UI; incident list, causal-chain viz, endpoint list |
| `neo4j` | 7474/7687 | Provenance graph store |
| `rabbitmq` | 5672/15672 | Message broker (fanout exchange for normalized events) |

## Provenance graph schema

**Node labels (9):** Process, File, Socket, Registry, Memory, Pipe, Host, User, Url

**Edge types (14):** FORK, EXEC, READ, WRITE, CONNECT, SEND, RECEIVE, MMAP, RENAME, DELETE, LOAD, MODIFY_REG, ACCESS, AUTH

**Edge properties:** `event_id` (unique constraint), `timestamp`, `size`, `properties` blob, `r.botsv2_ml_score`, `r.botsv2_ml_score_honest`, `r.botsv2_label` (ground truth, thesis only)

## Ingest normalization

Entry point: `server/ingest/botsv2_normalizer.py`  
Parsers: `server/botsv2_parsers/parsers.py` (11 sourcetype families)

Each parser produces a `ParsedRow` with:
- Graph triple: `subject_type/id/name`, `object_type/id/name`, `edge_type`
- Network: `src_ip`, `dest_ip`, `src_port`, `dest_port`
- Content fields: HTTP, DNS, process, Sysmon, Suricata, registry fields

The normalizer wraps `ParsedRow` into a `NormalizedEvent` (Pydantic) and publishes to `edr_fanout`. Content fields travel in `properties["botsv2_fields"]`.

## ML scoring (ml-edge-scorer)

- Consumes `normalized_events` from RabbitMQ
- `feature_row.py` builds 42-column feature vector from `NormalizedEvent`
- `model_loader.py` loads both temporal models from `/app/ml-edge-scorer/models/` (volume-mounted from `server/ml-engine/botsv2/models/`)
- Scores written as edge properties in Neo4j; alerts published to `ml_alerts` queue
- Batch config: prefetch 50, write batch 50, flush 2.0s, 3.0s startup delay

**Thresholds:**  
- Headline (`lgbm_xt_temporal`): alert if score ≥ 0.9  
- Honest (`lgbm_xt_temporal_no_st`): alert if score ≥ 0.7  

## Rule engine

36 YAML rules in `server/rule-engine/rules/`.  
Two detection modes: `selection` (single-edge match) and `sequence` (ordered causal chain with time window, per-root-process FSM).

**MITRE ATT&CK coverage:** 11 tactics — Execution (9), Defense Evasion (10), Persistence (4), Privilege Escalation (5), Credential Access (2), Discovery (3), Lateral Movement (2), C2 (5), Collection (1), Exfiltration (2), Impact (1).

## Quick start

```bash
cd server
docker compose up -d
docker compose --profile simulator run --rm simulator --scenario botsv2 --limit 5000 --rate 500

# http://localhost:3000        dashboard
# http://localhost:8000/docs   API swagger
# http://localhost:7474        Neo4j browser (neo4j / edr-thesis)
# http://localhost:15672       RabbitMQ admin (guest / guest)
```
