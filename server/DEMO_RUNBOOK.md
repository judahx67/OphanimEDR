# EDR Demo Runbook

A step-by-step guide for bringing up the full stack and observing the rule-based
detection pipeline process real DARPA THEIA E3 provenance data.

## Prerequisites

- Docker Desktop running
- DARPA dataset at `j:/THESIS-EDR/darpa_data/data/theia/ta1-theia-e3-official-1r.json.0`
- Neo4j Browser at http://localhost:7474 (neo4j / edr-thesis) — opens after step 1
- Dashboard at http://localhost:3000 — start with `npm run dev` inside `server/dashboard/`

---

## Quickstart (one command)

```powershell
# From the project root — starts all services + replays 30k events
.\scripts\deploy.ps1 -Mode server -Replay 30000
```

To also open the dashboard dev server in a new window:
```powershell
.\scripts\deploy.ps1 -Mode full -Replay 30000
```

---

## Manual step-by-step

### 1 — Bring up the pipeline

```powershell
.\scripts\deploy.ps1 -Mode server
# OR equivalently:
docker compose -f server/docker-compose.yml up -d
```

Six services start:

| Container         | Role                                               |
|-------------------|----------------------------------------------------|
| edr-rabbitmq      | Message bus                                        |
| edr-neo4j         | Provenance graph store                             |
| edr-ingest        | CDM normalizer → NormalizedEvent                   |
| edr-graph-builder | NormalizedEvent → Neo4j MERGE                      |
| edr-rule-engine   | NormalizedEvent → rule FSM → Incident nodes        |
| edr-api           | FastAPI (Neo4j-backed) served at :8000             |

The `simulator` container is **not** started by default — run it on demand.

Verify all are up:
```bash
docker compose -f server/docker-compose.yml ps
```

Wait until rabbitmq and neo4j show `(healthy)`.

---

### 2 — Replay real DARPA data

```bash
docker compose -f server/docker-compose.yml --profile simulator run --rm simulator \
    --scenario theia --limit 30000 --rate 2000
```

What happens:
- Reads CDM18 JSON lines from the bind-mounted THEIA file
- Unwraps `line["datum"]` and publishes to `raw_events`
- `ingest` normalizes ~17k causal edges out of 30k raw datums (rest are entity defs + noise events)
- `graph-builder` MERGE's nodes/edges into Neo4j
- `rule-engine` runs the FSM simultaneously — fires `Incident` nodes when attack patterns match

Expected output:
```
THEIA loader done: 32230 datums sent (events=30000) in ~52s
```

---

### 3 — Watch the pipeline

Tail any service:
```bash
docker logs -f edr-ingest        # normalization progress
docker logs -f edr-graph-builder # neo4j write batches
docker logs -f edr-rule-engine   # INCIDENT [HIGH] PowerShell C2 Dropper ...
docker logs -f edr-api           # HTTP request log
```

Expected after 30k events:
- **ingest**: `normalized ~17k, skipped ~13k`
- **graph-builder**: `~1800 nodes, ~17k edges`
- **rule-engine**: incidents for rules that matched (depends on dataset window)

---

### 4 — View incidents in the dashboard

Open the dashboard at http://localhost:3000, then navigate to **Incidents**.

Each incident row shows:
- Severity badge (CRITICAL / HIGH / MEDIUM)
- Rule name + ATT&CK technique ID
- Status (NEW / INVESTIGATING / RESOLVED)
- Click to expand: the full causal edge chain that triggered the rule

The **Dashboard** home page shows:
- Total nodes/edges in the graph
- Incident count + new alerts counter
- Node type breakdown bar chart
- Incidents by severity bar chart

---

### 5 — Explore the graph (Neo4j Browser)

Open http://localhost:7474 (neo4j / edr-thesis).

Useful queries:

```cypher
// How many nodes/edges?
MATCH (n) RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC

// All incidents
MATCH (i:Incident) RETURN i.rule_name, i.severity, i.title, i.created_at
ORDER BY i.created_at DESC

// Causal chain around an incident's root node
MATCH path = ({uuid: '<root_node_id>'})-[*1..3]-()
RETURN path LIMIT 100

// Process fork tree
MATCH p = (parent:Process)-[:FORK*1..3]->(child:Process)
RETURN p LIMIT 50

// Which processes connected to external sockets?
MATCH (p:Process)-[:CONNECT]->(s:Socket)
WHERE NOT s.name STARTS WITH 'LOCAL'
  AND NOT s.name STARTS WITH 'NA'
RETURN p.name, s.name ORDER BY p.name
```

---

### 6 — Reset between runs

```bash
# Wipe the graph (keeps constraints/indexes)
docker exec edr-neo4j cypher-shell -u neo4j -p edr-thesis \
    "MATCH (n) DETACH DELETE n"

# Purge in-flight messages
docker exec edr-rabbitmq rabbitmqctl purge_queue raw_events
docker exec edr-rabbitmq rabbitmqctl purge_queue normalized_events

# Restart stateful workers so in-memory caches are clean
docker compose -f server/docker-compose.yml up -d --force-recreate \
    ingest graph-builder rule-engine
```

---

### 7 — Build images after code changes

```powershell
# Rebuild all Docker images
.\scripts\build.ps1 -Target docker

# Or with no-cache (slower, use when dependencies change)
.\scripts\build.ps1 -Target docker -Clean

# Then restart affected service
docker compose -f server/docker-compose.yml up -d --force-recreate rule-engine
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No incidents appearing | Rule engine not connected to queue yet when replay started | Restart rule-engine, purge queues, re-run simulator |
| `"NA:0"` mega-hub in graph | Normalizer name-resolution regression | Check `normalizer.py` — `remoteAddress == "NA"` sentinel must produce a skip |
| FORK children all resolve to `swapper/0` | Normalizer reading wrong CLONE field | THEIA CLONE puts child in `predicateObject`, not `predicateObject2` |
| API returns 500 on `/api/incidents` | Neo4j Incident constraint missing | Restart `edr-api` — it creates the constraint on startup |
| Simulator hangs on startup | RabbitMQ not ready | Wait for `rabbitmq` to show `(healthy)` in `docker compose ps` |
| Graph shows fewer FORKs than expected | Replay capped before fork storm | Use `--skip-events 20000 --limit 30000` to jump past boot phase |
