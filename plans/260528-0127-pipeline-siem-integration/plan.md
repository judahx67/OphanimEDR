# Plan — Full Pipeline + Wazuh SIEM Integration

**Goal:** assemble data ingress → detection with our own GNN model. Wazuh = telemetry
transport (collector+server) feeding **our** ingress; detection = our rule-engine + GNN +
LLM-produced rules. LLM context engine turns sparse GNN seeds into narrated incidents.

Sibling reference: [`data-schema-and-examples.md`](./data-schema-and-examples.md) — read first.
Prior context: [`../260525-0105-flash-e3-pivot/plan.md`](../260525-0105-flash-e3-pivot/plan.md).

## Decisions locked (2026-05-28)
1. **Collector = auditd + Sysmon-for-Linux** (my call). Mature, field-rich, Wazuh ships
   decoders for both, gives cmdLine/path/parent — the tokens the model needs.
2. **Wazuh full stack, used as ingest/transport ONLY.** Agent collects → manager
   forwards → **our** ingress. We do not build on Wazuh's dashboard logic for detection.
3. **Wazuh native rules NOT used for detection.** Their ruleset would alert/block and
   contaminate the experiment — we want attacks to proceed so our pipeline detects them.
   Capture **every** event via `<logall_json>yes</logall_json>` (archives.json), not just
   rule-matched alerts. Detection is entirely ours.

---

## Detection layers (revised)

The model is a **sparse-seed graph anomaly detector, not a per-event classifier**
(schema doc §5). Split detection by strength — **Wazuh contributes none of it**:

| Layer | Engine | Granularity | Role |
|---|---|---|---|
| **L1 signatures** | **our `rule-engine/`** (36 FSM/Sigma-inspired YAML) + **LLM-produced rules** | per-event + causal sequence | the single-event case the GNN can't do; closed-loop new rules from incidents |
| **L2 anomaly** | **GNN node-scorer** (our v2/v3) | per-node, in graph window | novel/OOV behavior via topology |
| **fusion** | **LLM context engine** | per-incident | narrate + MITRE map + triage + **emit new L1 rules** |

→ **"Broken single-event scoring" resolved architecturally:** per-event detection routes
to `rule-engine/`, never the GNN. GNN only scores nodes inside an accumulating provenance
graph window → seeds. Retraining does not and cannot fix per-event (inherent to the task).

---

## Target architecture

```
live Linux endpoint
  └─ auditd + Sysmon-for-Linux
       └─ Wazuh agent ──► Wazuh manager  (logall_json=yes; native rules ignored)
                            └─ archives.json (ALL events)
                                 └─ bridge: tail archives.json ─► RabbitMQ(raw_events)
                                      └─ ingest/normalizer  → (actor, obj, action∈EVENT_*, exec, path)
                                           ├─ rule-engine/  (L1: FSM signatures + LLM rules) ─► incidents
                                           └─ graph-builder ─► Neo4j (provenance graph)
                                                └─ GNN scorer (L2: windowed subgraph) ─► seed nodes
                                                     └─ 2-hop causal expansion ─► candidate incident
                                                          └─ llm-analyzer (context engine)
                                                               ├─► narrative + MITRE + triage ─► api ─► dashboard
                                                               └─► NEW rule (YAML) ─► rule-engine/ (closed loop)
```

Reuse as-is: `ingest/`, `graph-builder/`, `neo4j`, `api/`, `dashboard/`, `llm-analyzer/`,
`rabbitmq`, `rule-engine/`. New: Wazuh stack + archives→RabbitMQ bridge, live normalizer,
GNN windowed scorer (replaces `ml-edge-scorer` per-edge), LLM→rule emitter.

---

## Phases

### Phase 1 — Wazuh stack + ingest bridge
- Deploy Wazuh manager+indexer+dashboard (docker, alongside existing compose).
- Enroll agent on the Linux endpoint; enable auditd + Sysmon-for-Linux integration.
- `logall_json=yes`; treat archives.json as the firehose. Bridge service tails it →
  RabbitMQ `raw_events`. (No reliance on Wazuh `alerts.json` / native rules.)

### Phase 2 — Live normalizer (make-or-break)
- Map Wazuh-decoded auditd/Sysmon events → the model schema: `(actorID, SUBJECT_PROCESS,
  objectID, object_type, action∈EVENT_*, exec=cmdLine, path)`. Mapping table in schema doc §7.
- **Vocab-overlap gate:** verify benign live command lines land in the train Word2Vec
  vocab before trusting GNN scores. Domain shift = top risk. Qualitative demo only.

### Phase 3 — Detection layers
- **L1:** confirm `rule-engine/` runs on the live normalized stream (it already consumes
  `normalized_events`). This is the per-event/sequence detector.
- **L2:** GNN windowed scorer — maintain sliding provenance window in Neo4j, run 20-shard
  explain-away over the window on timer/threshold, emit **surviving nodes as seeds**
  (not per-event alerts) → 2-hop expansion → candidate incident.

### Phase 4 — LLM context engine (the contribution)
- Input: seed node + 2-hop subgraph + matched L1 signatures.
- Output: (a) narrative + MITRE ATT&CK + triage verdict; (b) **a new detection rule** in
  `rule-engine/` YAML format → closed loop so variants are caught by L1 next time.
  (YARA output for endpoint push = later, per `[[project-llm-enrichment-roadmap]]`.)
- LLM choice provisional (Gemini).

### Phase 5 — Model ownership ✅ DONE
- **v3 trained + promoted to default** (`trained_weights/theia_ours_v3`, 10 epochs/shard,
  reused v2 Word2Vec). Held-out 6r.8, identical eval harness:
  - ours v3:       P 0.9330 / R 0.9983 / F1 0.9646  (FP 1817)
  - paper shipped: P 0.9176 / R 0.9984 / F1 0.9563  (FP 2273)  ← verified `eval-shipped.log`
- **Honest framing: parity reproduction, not a categorical win.** Recall ~0.998 is
  structural (2-hop forgiveness in the metric). v3's ~1.5-pt F1 edge is fewer FPs for
  the same recall (tighter explain-away: 22.7k vs 34.9k flagged), within run-to-run
  variance — defensible as parity, NOT "beats the researchers". Same FLASH split (1r→6r.8).
  Default in `evaluate.py` + `benchmark.py`.

---

## Open questions (morning)
1. **LLM rule format** — emit our `rule-engine/` YAML (reuse `loader.py`/`engine.py` FSM,
   recommended) vs YARA vs Sigma? Decides the closed-loop plumbing.
2. **Where does the LLM-rule run** — live `rule-engine/` only, or also pushed to the
   endpoint (Wazuh active-response / YARA scan)?
3. Single host or multi-host demo? (affects graph windowing + Neo4j load)
4. Retire `ml-edge-scorer` per-edge BOTSv2 path, or keep for the legacy LGBM demo?

## Status
- ✅ FLASH/THEIA code migrated to tracked `server/ml-engine/theia/`.
- ✅ Data schema + examples documented (sibling doc) — **the headline morning deliverable**.
- ✅ SIEM plan revised to decisions 1-3 (Wazuh = transport only).
- ✅ v3 GNN trained + promoted to default — **parity** with paper weights (see Phase 5).
- ✅ **Phases 1-3 WIRED + verified end-to-end (2026-05-28)** on branch
   `feature/migrate-to-gnn-w2v-theia`. Offline CDM18 replay path (chosen over Wazuh-first
   for testability): `theia-replay → ingest(theia_normalizer) → graph-builder → Neo4j`,
   L1 `rule-engine` (own fanout queue), L2 `theia-gnn-scorer` (windowed 20-shard explain-away,
   v3 weights). Verified: 20k-edge replay of 6r.8 → 1410 THEIA nodes in Neo4j, 767 GNN seeds
   written, 26 L1 incidents, 0 errors. BOTSv2 simulator + ml-edge-scorer demoted to
   `--profile legacy`.
   - Fixed latent bug: rule-engine shared graph-builder's `normalized_events` queue
     (competing consumers → each saw half the stream). Each consumer now has its own
     fanout-bound queue. Also removed an orphan `normalized_events_scoring` queue leak.
   - NOTE: on a benign-dominated 20k slice the GNN over-flags (767/1410 seeds) — expected;
     the 0.93 precision needs the full attack-bearing graph. Wiring demo ≠ precision claim.
- ⬜ Phase 4 (LLM closed loop) deferred — needs open Q1 (rule format) + Q2 (where it runs).
- ⬜ Wazuh live front-end (Phase 1 live capture) still future — replay stands in for now.
