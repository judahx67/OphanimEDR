# Ophanim EDR

Ophanim EDR finds attacks on an endpoint. The system reads system telemetry.
It builds a provenance graph from that telemetry. It then runs two detection
layers on the graph.

Layer 1 applies rules. Each rule is a YAML file in the Sigma style. The rules
find known attack steps.

Layer 2 applies two learned models. The models find anomalies. The first model
uses FLASH, which combines GraphSAGE and Word2Vec. The second model uses
Orthrus, which is a graph attention network. Both models read the same graph.
Therefore a direct comparison of the two models is possible.

After a detection, a large language model writes a short report. The report
explains the incident to the analyst.

This repository holds the system of an undergraduate thesis at UIT, VNU-HCM.
The thesis is complete. The code is an archive. It is not in active
development. The directory `docs/provenance/` records all reported results.

---

## Components

| Directory | Function |
|---|---|
| `server/api/` | The backend. FastAPI reads the Neo4j graph. It serves incidents, causal chains, the comparison view, and rule export. |
| `server/dashboard/` | The frontend. React and TypeScript. Vite builds it. Nginx serves it. |
| `server/ml-engine/` | The machine learning code. It holds the offline experiments and the trained weights. |
| `server/pipeline/` | One container. Supervisord runs the ingest, graph-builder, and rule-engine workers in it. |
| `server/theia-gnn-scorer/` | The live FLASH model. |
| `server/theia-orthrus-scorer/` | The live Orthrus model. |
| `server/theia-replay/` | It sends the DARPA TC E3 THEIA data to RabbitMQ. |
| `server/llm-analyzer/` | It writes the incident report. |
| `server/wazuh/` | The Wazuh agent integration. |
| `deploy/` | A PowerShell script. It starts and stops the stack. |

The `ml-engine` directory contains the work on three data sets:

| Directory | Data set |
|---|---|
| `theia/` | DARPA TC E3 THEIA. This is the primary data set. |
| `optc/` | DARPA OpTC. |
| `botsv2/` | Splunk BOTSv2. This is an earlier iteration. |

---

## How to start the system

```bash
cd server
cp .env.example .env
docker compose up -d
```

The file `.env` holds the API keys for the language models. The system starts
without these keys. In that condition, the report function stays off.

The system opens four addresses:

| Address | Function |
|---|---|
| http://localhost:3000 | The dashboard. Open `/compare` to see FLASH against Orthrus. |
| http://localhost:8000/docs | The API documentation. |
| http://localhost:7474 | The Neo4j browser. The user is `neo4j`. The password is `edr-thesis`. |
| http://localhost:15672 | The RabbitMQ console. The user and the password are `guest`. |

The command starts seven services: `rabbitmq`, `neo4j`, `pipeline`,
`theia-gnn-scorer`, `theia-orthrus-scorer`, `api`, and `dashboard`.

The two model services need approximately 20 GB of memory. Start the system
without them if the machine has less memory.

From the root directory, the script `.\deploy\deploy.ps1` does the same steps.
It also waits for each health check. It then shows the logs. The parameter
`-Mode down` stops the system.

### Optional profiles

Two profiles are available. Each profile needs data that this repository does
not contain.

```bash
docker compose --profile llm up -d llm-analyzer
```

This profile starts the report function. It needs the key `GEMINI_API_KEY` in
the file `server/.env`.

```bash
docker compose --profile theia-sim run --rm theia-replay \
    --file ta1-theia-e3-official-6r.json.8 --limit 20000 --rate 500
```

This profile sends recorded data through the system. The service reads the
DARPA TC E3 THEIA data from the directory `../external/Flash-IDS`. Put the data
in that directory before you use this profile. You can also change the mount
path in the compose file.

---

## Data that this repository does not contain

The repository does not contain the raw data sets. The DARPA TC E3 THEIA data,
the DARPA OpTC data, and the Splunk BOTSv2 data are too large. The repository
also does not contain the caches that the scripts calculate from that data.
The scripts calculate these caches again on the first run.

The repository does contain the trained weights. Look in
`server/ml-engine/*/trained_weights/` and in `server/ml-engine/botsv2/models/`.
The file [`CANONICAL.md`](server/ml-engine/theia/trained_weights/CANONICAL.md)
shows which weights produce which result.

---

## Documentation

The directory [`docs/provenance/`](docs/provenance/) records the results.

| File | Content |
|---|---|
| [`results-frozen.md`](docs/provenance/results-frozen.md) | Each result in the thesis. Each result has a link to a log file. Each result also has a mark that shows the strength of the evidence. |
| [`offline-reexecution-manifest.md`](docs/provenance/offline-reexecution-manifest.md) | The log of the re-run on 2026-06-14. Each result was identical. |
| [`provenance-baseline-260614.md`](docs/provenance/provenance-baseline-260614.md) | The relation between each set of weights and each script. |
| [`demo-runbook.md`](docs/provenance/demo-runbook.md) | The procedure for the recorded demonstration. |

The file [`docs/defense-decisions.md`](docs/defense-decisions.md) and the
directory [`docs/decisions/`](docs/decisions/) give the reason for each design
decision. They cover the detection paths, the feature schema, the label rules,
the model selection, and the thresholds. The author wrote these documents in
May 2026, during the BOTSv2 iteration. The components that they describe are
still in the system.

Both sets of documents are an archive. They show the condition of the project
at submission. No person maintains them. Some links in these documents point
to planning documents. Those documents are not in this repository.
