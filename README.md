# Ophanim EDR

Graph-based endpoint detection built on a provenance graph. Telemetry is normalised into a
Neo4j provenance graph, then two detection layers run over it in parallel: **L1**, a Sigma-inspired
YAML rule engine that catches enumerated tactics, and **L2**, learned anomaly detectors — a FLASH
(GraphSAGE + Word2Vec) scorer and an Orthrus (GAT) scorer running head-to-head on the same
substrate. Flagged subgraphs go to an LLM for an incident narrative.

Undergraduate thesis project (UIT/VNU-HCM). The report is submitted; this repo is the archived
system. Reported numbers and how they were produced live in [`docs/provenance/`](docs/provenance/).

---

## Layout

| | |
|---|---|
| `server/api/` | **Backend** — FastAPI over Neo4j. Incidents, causal chains, `/compare`, Sigma/Wazuh export, multi-provider LLM narratives. |
| `server/dashboard/` | **Frontend** — React + TypeScript + Vite, served by nginx. |
| `server/ml-engine/` | **ML** — offline experiments and trained weights. `theia/` (DARPA TC E3), `optc/` (DARPA OpTC), `botsv2/` (Splunk BOTSv2, earlier iteration). |
| `server/pipeline/` | ingest · graph-builder · rule-engine as supervisord children in one container. |
| `server/theia-gnn-scorer/`, `server/theia-orthrus-scorer/` | L2 live scorers (FLASH and Orthrus). |
| `server/theia-replay/` | Streams DARPA TC E3 THEIA into RabbitMQ. |
| `server/llm-analyzer/`, `server/rule-engine/`, `server/wazuh/` | narrative generation, L1 rules, Wazuh integration. |
| `deploy/` | PowerShell wrappers around docker compose. |

---

## Start it

```bash
cd server
cp .env.example .env          # optional — LLM keys; the stack starts without them
docker compose up -d
```

| | |
|---|---|
| http://localhost:3000 | dashboard (`/compare` = FLASH vs Orthrus) |
| http://localhost:8000/docs | API swagger |
| http://localhost:7474 | Neo4j browser — `neo4j` / `edr-thesis` |
| http://localhost:15672 | RabbitMQ admin — `guest` / `guest` |

Default services: `rabbitmq`, `neo4j`, `pipeline`, `theia-gnn-scorer`, `theia-orthrus-scorer`,
`api`, `dashboard`. Allow ~20 GB RAM for the two scorers, or start without them.

From the repo root, `.\deploy\deploy.ps1` does the same, waits for healthchecks, and tails the logs.
`-Mode down` tears it back down.

### Optional profiles — these need data you supply

```bash
docker compose --profile llm up -d llm-analyzer      # needs GEMINI_API_KEY in server/.env

docker compose --profile theia-sim run --rm theia-replay \
    --file ta1-theia-e3-official-6r.json.8 --limit 20000 --rate 500
```

`theia-replay` mounts `../external/Flash-IDS` — the DARPA TC E3 THEIA corpus, which is not in this
repo. Place it there (or edit the mount) before using that profile. Without it the stack runs, it
just has nothing to ingest.

---

## Data that isn't here

Raw corpora (DARPA TC E3 THEIA, DARPA OpTC, Splunk BOTSv2) and the feature caches derived from them
are not tracked — they are tens of GB. **Trained weights are tracked** under
`server/ml-engine/*/trained_weights/` and `server/ml-engine/botsv2/models/`; see
[`CANONICAL.md`](server/ml-engine/theia/trained_weights/CANONICAL.md) for which weight set backs
which reported number. The caches (`_cache_*.pkl`, `_feat_*.npz`, `*.parquet`) are rebuilt by the
`prepare_cache.py` / featurize scripts on first run, given the raw data.

---

## Documentation

**[`docs/provenance/`](docs/provenance/)** — the final THEIA/OpTC results.
[`results-frozen.md`](docs/provenance/results-frozen.md) is every metric that entered the thesis,
each traced to a log file, with an explicit strength-of-evidence marker per cell.
[`offline-reexecution-manifest.md`](docs/provenance/offline-reexecution-manifest.md) is the
2026-06-14 re-run log (all cells digit-identical),
[`provenance-baseline-260614.md`](docs/provenance/provenance-baseline-260614.md) maps weights to
scripts, and [`demo-runbook.md`](docs/provenance/demo-runbook.md) is the recorded-demo script.

**[`docs/defense-decisions.md`](docs/defense-decisions.md)** and
**[`docs/decisions/`](docs/decisions/)** — why each design choice and each magic number is what it
is: detection paths, feature schema, labelling, model choice, thresholds. Written during the
BOTSv2 iteration (May 2026) and dated accordingly, but the components they document — the rule
engine, the thresholds, the labelling rules — are the ones still shipping.

Both sets are archival: they describe the state at submission and are not maintained. A few
cross-references inside them point at planning documents that were removed in this cleanup.
