# Ophanim-EDR Demo Runbook

A 5-minute script for showing the real DARPA THEIA E3 provenance pipeline.

## Prerequisites

- Docker Desktop running
- The DARPA file at `j:/THESIS-EDR/darpa_data/data/theia/ta1-theia-e3-official-1r.json.0` (already bind-mounted)
- Neo4j Browser open at http://localhost:7474 (login: `neo4j` / `ophanim-edr`)

## 1 — Bring up the pipeline

```bash
cd j:/THESIS-EDR/server
docker compose up -d
```

Four services start: `rabbitmq`, `neo4j`, `ingest`, `graph-builder`. The simulator is *not* started by default — it's gated behind the `simulator` profile so you can run it on demand.

Wait ~10 seconds for rabbitmq and neo4j to become healthy, then verify:

```bash
docker compose ps
```

All four should show `Up (healthy)` or `Up`.

## 2 — Replay real DARPA data

```bash
docker compose run --rm simulator --scenario theia --limit 30000 --rate 5000
```

What this does:
- Reads lines from the bind-mounted `/data/theia.json` (the THEIA file).
- For each line it unwraps `line["datum"]` and publishes the inner CDM datum to RabbitMQ `raw_events`.
- `--limit 30000` caps the run at **30k Event datums** (entity definitions don't count).
- `--rate 5000` throttles the simulator to ~5000 datums/sec.
- `--skip-events N` (optional) fast-forwards past the first N event datums while still publishing their entity definitions — useful if you want to jump to a richer window of activity.

Expected: ~45–60 seconds end-to-end. Final log line looks like:

```
THEIA loader done: 32230 datums sent (events=30000, events_skipped=0) in 52.1s
Datum type breakdown: {'...Event': 30000, '...FileObject': 1248, '...Subject': 151, '...NetFlowObject': 227, ...}
```

## 3 — Watch it land in Neo4j

Tail both workers in two terminals to show the pipeline is alive:

```bash
docker logs -f ophanim-ingest
docker logs -f ophanim-graph-builder
```

Expected numbers after the replay finishes:
- **ingest**: `received=~32k normalized=~17k skipped=~15k` (skipped = entity defs + non-causal events like OPEN/CLOSE/MPROTECT)
- **graph-builder**: `consumed=~17k edges_created=~17k` and a final `Graph: {'nodes': ~1800, 'edges': ~17k}`

## 4 — Tell the story with curated Cypher queries

Open [neo4j-demo-queries.cypher](neo4j-demo-queries.cypher) and paste queries into the Neo4j Browser **one at a time**. Each query is designed to show one specific story:

| # | Query | Story |
|---|---|---|
| 1 | Node/edge counts | "Here's what the dataset contains" |
| 2 | Process tree (FORK) | "Who forked whom, with real command lines like `sudo ./theia_toggle recording on`" |
| 3 | EXEC edges | "Which processes loaded which binaries" |
| 4 | Network CONNECT | "Four distinct remote endpoints — 128.55.12.10:53 (DNS), internal LAN traffic" |
| 5 | Sensitive file writes | "sshd writing utmp/wtmp, bash writing .bash_history — classic audit targets" |
| 6 | Fork → connect | "Classic EDR pivot: find children that talked to the network" |
| 7 | Causal ancestry | "Walk provenance backward from a target process" |
| 8 | Blast radius | "Everything whoopsie (Ubuntu crash reporter) touched" |
| 9 | Busiest processes | "Why a naive LIMIT 100 looks like one big hub" |
| 10 | Clean subgraph | **The one to screenshot.** Causal skeleton only — no MMAP/READ noise. |

**Why not just `MATCH ()-[]->() RETURN * LIMIT 100`?**

Because LIMIT 100 grabs whatever the planner returns first, which is dominated by high-volume noise edges: one python process MMAP'ing dozens of shared libraries, or sshd READ'ing every line of `/etc/passwd`. A single hub with 100 rays is visually useless. Every query in the runbook constrains both the *edge types* and the *starting points* so the returned subgraph is small, causal, and tells a story.

## 5 — Reset between runs

```bash
# Wipe the graph (keeps constraints/indexes)
docker exec ophanim-neo4j cypher-shell -u neo4j -p ophanim-edr "MATCH (n) DETACH DELETE n"

# Purge any in-flight messages
docker exec ophanim-rabbitmq rabbitmqctl purge_queue raw_events
docker exec ophanim-rabbitmq rabbitmqctl purge_queue normalized_events

# Recreate workers so their in-memory caches are clean
docker compose up -d --force-recreate ingest graph-builder
```

## Troubleshooting

- **Graph looks like "NA:0" mega-hub** → normalizer name-resolution regression. Check `normalizer.py:resolve_object` still handles `remoteAddress == "NA"` sentinel.
- **FORK children all resolve to `swapper/0`** → normalizer is looking up the child UUID in the wrong field. THEIA's CLONE events put the child in `predicateObject`, not `predicateObject2`.
- **Nodes have no label in the Browser sidebar** → graph-builder MERGE is missing the static label interpolation. Every MERGE must be `MERGE (n:{label} {uuid: ...})` with the label substituted at query-build time.
- **Simulator hangs on startup** → rabbitmq isn't ready yet. Wait for `docker compose ps` to show rabbitmq as healthy before running the simulator.
- **Graph shows fewer FORKs than expected** → you may be hitting the 30k event cap before the fork storm (around line 3M in the file). Use `--skip-events 20000 --limit 30000` to jump past the boot phase.
