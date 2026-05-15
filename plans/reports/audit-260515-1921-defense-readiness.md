# Defense-Readiness Audit — 2026-05-15

**Scope:** Brutally honest, ranked inventory of sloppiness across the full pipeline (model → ingest → graph → detection → demo) for thesis defense.
**Pivot in effect:** Pipeline is **binary classification (LightGBMXT per edge) → query the edge/subgraph from Neo4j → LLM explanation**. ActMiner causality/incremental-alignment framing is dropped. Findings are ranked under this new framing.

**Severity legend**
- **P0** — Defense-killer. Examiner will probe; current state has no defensible answer or actively produces wrong results.
- **P1** — Weakness an examiner is likely to probe. Answer exists but is shaky.
- **P2** — Sloppy but not a defense blocker. Fix for polish/credibility.
- **P3** — Cosmetic / docs drift.

Coverage note: I read every hot-path file end-to-end (ingest, parsers, graph-builder, ml-edge-scorer, model_loader, train.py, schema.py, llm-analyzer, rule-engine, simulator), but did **not** deeply audit `server/api/edr_server/database.py` (689 lines), the React dashboard, or attempt a clean-clone reproduction of headline numbers. Those are listed as **not audited** at the end and should be revisited.

---

## P0 — Defense killers

### P0-1. Live edge scorer ignores the F1-optimal threshold and uses an unjustified higher cutoff
- `server/ml-edge-scorer/main.py:60-61` hard-codes `ML_THRESHOLD_HEADLINE=0.9`, `ML_THRESHOLD_HONEST=0.7`.
- Trained `threshold.json` says **0.310** (headline) and **0.430** (honest) — F1-optimal on val with val_recall ≈ 0.989 / 0.990.
- `model_loader.py:52-57` loads the trained threshold into `FrozenModel.threshold` but `main.py` never reads it.
- Effect: the live system intentionally collapses recall in exchange for precision, with **no recorded justification, no measurement of the recall hit, and no audit trail**.
- Defense risk: "Your val_recall at the chosen threshold was 98.9%. Your live cutoff is ~3× higher. What's the live recall? Why?" → no answer.
- Action options:
  - (a) Switch live to the trained thresholds and accept the FP volume; or
  - (b) Re-derive a deployment threshold with an explicit objective (precision-at-fixed-alert-rate, or budget of N alerts/hour), document the choice, **publish that recall number**.

### P0-2. Every normalized event is published twice → every edge is written twice in Neo4j
- `ingest/main.py:96-98` binds the `normalized_events` queue to BOTH the direct exchange (routing_key=`normalized`) AND the fanout exchange `edr_fanout`.
- `ingest/main.py:133-145` publishes each normalized event to BOTH exchanges.
- Both deliveries land in the same `normalized_events` queue → graph-builder consumes the message **twice**.
- `graph-builder/main.py:241-246` uses `CREATE (s)-[r:{edge_type} ...]->(o)` and there's **no uniqueness constraint on `event_id`** (only on node `uuid`, see `_create_constraints` at line 94-114).
- Result: every BOTSv2 edge appears as **two parallel relationships** in Neo4j with the same `event_id`. All graph statistics, edge counts, alert counts, and dashboard visualisations are 2× inflated.
- Scorer: `ml-edge-scorer/main.py:97-104` does `MATCH ()-[r {event_id: row.event_id}]->()` — this matches BOTH duplicates and silently SETs the same score on both.
- Fix: bind `normalized_events` to one exchange only (drop the direct-exchange bind or stop the dual publish), AND add `REQUIRE r.event_id IS UNIQUE` (Neo4j 5.x supports relationship uniqueness constraints) so duplicates fail loud.

### P0-3. BOTSv2 simulator destroys causal ordering across sourcetypes
- `server/simulator/main.py` (`run_botsv2_loader` around line 580-616) iterates partitions **sequentially per sourcetype**, not interleaved by `_time`.
- All `stream_http` events are replayed, then all `suricata`, etc. Cross-sourcetype causal chains (Sysmon process spawn → stream_http exfil → suricata alert) are reconstructed **out of temporal order**.
- For the per-edge ML model this is mostly invisible (each edge scored independently). For the **thesis demo** — "causal chain visualisation" on the dashboard, the rule-engine FSM matcher, and any timeline narrative the LLM produces — this is wrong.
- The rule engine compounds the problem (P1-3 below) because its FSM uses **wall-clock** time not event-time, so partial states expire on the wrong axis.
- Fix: merge-sort partitions by `_time` during replay (a k-way iterator over partitions), and/or partition the labeled Parquet by `_time` instead of by sourcetype.

### P0-4. LLM analyzer uses Gemini, but CLAUDE.md and the module docstring claim Claude
- `server/llm-analyzer/main.py:21-22, 46-50` — imports `google.genai`, defaults to `gemini-2.0-flash`.
- Module docstring lines 1-11 say "Send the subgraph + alert context to **Claude** (via Anthropic SDK)". CLAUDE.md repeats the Claude claim in two places.
- "Uses prompt caching on the system prompt" (line 9) — Gemini's prompt caching has different mechanics from Anthropic's; doesn't match the implementation either.
- Defense risk: anyone who reads the repo sees the lie immediately. Either:
  - Switch back to Anthropic (the project is *named* for Claude Code; thesis explainability story is cleaner with one LLM choice and that choice documented), OR
  - Update docs/thesis to say Gemini and remove the prompt-caching claim.

### P0-5. THEIA, not BOTSv2, is still the default `SOURCE_FORMAT`
- `ingest/main.py:45` — `SOURCE_FORMAT = os.environ.get("SOURCE_FORMAT", "theia").lower()`.
- Thesis is on BOTSv2. A fresh `docker compose up` runs THEIA mode and rejects BOTSv2 messages.
- `docker-compose.yml` does override this (need to verify — see "Not audited"), but the default in code being THEIA telegraphs "this codebase was retrofitted, never rewritten." Examiner skimming the repo will land on this and lose trust.
- Fix: flip the default to `botsv2`, delete the synthetic `apt/benign/mixed` THEIA scenarios from `simulator/main.py` (~600 lines of dead code), and decide whether to retain `normalizer.py`/`TheiaNodeCache` at all.

---

## P1 — Likely-probed weaknesses

### P1-1. Feature schema is duplicated by hand in two modules
- Truth claimed in `server/ml-engine/botsv2/schema.py` (header: "single source of truth").
- Manual copy in `server/botsv2_parsers/parsers.py:20-78` with the explicit comment "kept in sync manually" (line 21).
- The live scorer imports from the *copy* (`feature_row.py:16`). If schema.py drifts and parsers.py doesn't, the scorer constructs feature rows the booster doesn't recognise — LightGBM tolerates missing columns by treating them as NaN, so the failure mode is **silent recall degradation, not a crash**.
- `model_loader.predict_proba` does not assert `set(self.feature_names) == set(model_feature_columns())` at startup, so drift is undetected.
- Fix: make `botsv2_parsers` import from `botsv2/schema.py` directly (move schema.py up into the parsers package, or vendor a single `schema_core.py` both depend on). Add a startup assertion in the scorer.

### P1-2. Rule-engine's role is undefined under the new thesis framing
- The pipeline pivot is "ML → LLM explain". Rules don't appear in that story.
- But `rule-engine` is still a first-class compose service and writes `Incident` nodes to Neo4j with severity, MITRE tactic, etc. — exactly the artefact the dashboard surfaces.
- CLAUDE.md says rules are used as positive training labels for ML, but `iocs.yaml` and `label.py` (not rule output) actually generate the labels.
- Question an examiner asks: "Why are there two parallel detection paths in Neo4j (rule-Incident nodes AND ML-Incident nodes from llm-analyzer)? Which is canonical? Why disagree?"
- Resolve by picking one and committing:
  - (a) Demote rules to a *baseline comparison* — generate them offline once, compare against ML alerts, drop the runtime rule-engine container.
  - (b) Keep both at runtime and explicitly frame as ensemble; quantify rule-vs-ML agreement.
  - (c) Delete the rule engine entirely from runtime; keep YAML files as documentation of which behaviours the model should catch.

### P1-3. Rule-engine FSM has a state-keying bug
- `engine.py:130` keys partial state by `(rule_id, subj_id)` where `subj_id` is the *current* event's subject.
- For multi-step rules where step ≥ 2 is performed by a forked child (see "active_subject_id" tracking at line 149-152), the state was inserted under the *root* subject's id at line 163, but on next event we look it up using the *child's* subject id — miss.
- The guard at line 135 (`state.active_subject_id == subj_id or state.step == 0`) is dead because the dict lookup already failed.
- Net: multi-stage chains crossing process boundaries cannot be detected. If the goal is to derive ground-truth labels from this engine, single-condition rules work but `sequence`-mode rules silently never fire past step 1.
- Fix: key state by `rule_id` only and scan all candidate states on each event, or maintain a secondary index `active_subject_id → set[(rule_id, root_subj_id)]`.

### P1-4. ml-edge-scorer drops scoring failures with no DLQ
- `main.py:265` — `basic_nack(..., requeue=False)` on any exception. No dead-letter queue declared.
- Ingest does the same (`ingest/main.py:155`).
- If a parser bug or upstream malformed event surfaces, scored events vanish silently. No way to count or replay losses.
- Defense risk: "What's your end-to-end loss rate?" → no telemetry.
- Fix: declare a `*.dlq` queue and route nack'd messages there, log the rejection reason, expose a counter on `/health`.

### P1-5. Edge-scorer's write race vs graph-builder is mitigated by a 3-second sleep, not by retry
- `main.py:114` — `WRITE_DELAY_SECS=3.0`. The buffer flush waits 3 seconds in the hope that graph-builder has already written the edge.
- If the edge isn't there yet, the `MATCH` returns 0 rows and the score is **silently lost** (line 127-131 logs `matched=N` but never re-buffers misses).
- Under high burst load (the BOTSv2 replay rate is 200-500/s), 3 seconds may not be enough; under low load it adds unnecessary latency.
- Fix: drive the scorer off a Neo4j-native pattern instead — e.g., scorer writes to a `:PendingScore` node keyed by event_id; a Cypher trigger or a follow-up sweeper attaches it to the edge when both exist. Or: change graph-builder to emit a "wrote edge X" event and scorer subscribes.

### P1-6. `botsv2_label` ground-truth is plumbed end-to-end as a graph property
- `ingest/botsv2_normalizer.py:114` — `props["botsv2_label"]` lands on the edge as a Neo4j property.
- This is fine for dashboard ground-truth comparison, but examiner will check: does anything downstream **read** this label and risk leaking it back into a "score"? Need to grep all readers and assert no model/rule consumes `botsv2_label` as input.
- Independent check: the BOTSv2 features schema (`schema.py:170-179`) lists `scenario`, `_time`, `host`, `src_ip`, etc. as `LEAKY_COLS` but **does not list `label`** because label is the target, not a feature. The live scorer doesn't see `label` at all (feature_row.py never reads it). So this is probably safe — but `iocs.yaml`-based label.py needs verification that it doesn't condition labelling on `scenario` only (it almost certainly does — that's how BOTSv2 labels were assigned originally; this is *unavoidable label leakage at the dataset level*, an entire defense-narrative issue worth pre-empting).

### P1-7. Train-time category alignment trusts string-vs-NaN distinction, comment lies
- `train.py:97-99` comment says "coerce to str before categorizing so np.nan doesn't get a category code" — but the code doesn't actually do str coercion. Pandas handles NaN correctly by default (NaN stays NaN, not a category), so the behaviour is correct, but the comment is wrong and an examiner reading carefully will flag the discrepancy.
- Fix: delete the misleading comment or actually do the coercion explicitly.

### P1-8. "Honest" model's framing is brittle
- The story "sourcetype is partly a routing label so we publish a no-sourcetype model too" is good. But:
  - `dest_port`, `src_port` are still kept as features. These are *also* partly attacker-infrastructure proxies (a high-port destination during s400 APT is informative because the attacker chose it, not because the port number is intrinsically suspicious). Same critique as sourcetype.
  - `http_uri`, `http_user_agent` are kept and have similar identity-leak risk for BOTSv2 (attacker tools have signature UAs).
- Defense risk: "If sourcetype is too leaky to keep, why are these less leaky?" — pre-empt by either documenting the trade-off explicitly or running a third ablation (`no_st_no_ports_no_ua`).

---

## P2 — Sloppiness that erodes credibility

- **P2-1.** `ingest/main.py:111` allocates `TheiaNodeCache()` even in BOTSv2 mode. Dead state.
- **P2-2.** `ingest/main.py` dual-publishes (root cause of P0-2) was clearly written before the scorer got its own `normalized_events_scoring` queue (`ml-edge-scorer/main.py:200-201`). The fanout was needed back when scorer shared the same queue. Now redundant.
- **P2-3.** `ml-edge-scorer/main.py:9-12` docstring claims it reads from `normalized_events`. It actually reads from `normalized_events_scoring`. Wrong docstring.
- **P2-4.** `graph-builder/main.py:127` defines `NON_REFLEXIVE` set inside the hot path; should be module-level constant. Trivial but indicative.
- **P2-5.** `rule-engine/engine.py:216` — `endpoint_id` defaults to `"theia-e3"`. Dead THEIA tail.
- **P2-6.** `rule-engine/engine.py:223` — `confidence: 1.0` hard-coded. Defensible only if every rule is precision=1; in practice rules vary (regex `(?i)bash` over command_line will fire on benign `bash -c "ls"`).
- **P2-7.** Many ad-hoc `_inspect*.py` / `_show_*.py` / `_verify_fe.py` underscore scripts in `ml-engine/botsv2/`. Useful during development, embarrassing during a defense walkthrough. Either move to `_scratch/` and `.gitignore`, or delete.
- **P2-8.** Hard-coded thresholds, model names, queue names scattered across services with no central config. A 1-page `config.md` listing every magic number and its provenance would pre-empt "where does this 0.9 come from" questions.
- **P2-9.** `simulator/main.py` carries `apt/benign/mixed` synthetic generators (~500 lines) that no longer appear in the thesis narrative. Delete or move to `archive/`.

---

## P3 — Cosmetic / docs drift

- **P3-1.** `botsv2_parsers/parsers.py:9` says it "mirrors the featured-schema graph triple + content fields defined in `server/ml-engine/botsv2/schema.py`" — re-states the duplication problem (P1-1).
- **P3-2.** README/CLAUDE.md references to `lgbm_xt_stratified` as "reference model 0.9981 AUC" — verify the model artefact is actually committed (`ls server/ml-engine/botsv2/models/` shows the directory exists; no test_metrics.json check done here).
- **P3-3.** `[6] EagleEye — ECCV 2020` in CLAUDE.md is flagged as "verify this citation is intentional/relevant" — still unresolved. Drop it from the related-work table if not used.
- **P3-4.** Inconsistent NodeType casing across modules (PascalCase in `botsv2/schema.py`, UPPER in `ingest/schema.py`). The `_NODE_TYPE_MAP` in `feature_row.py:21-31` papers over it. Pick one convention.

---

## Not audited in this pass — open follow-ups

1. **`server/api/edr_server/database.py` (689 lines)** — the largest single file. Cypher queries for the dashboard live here. Probable issues: N+1 queries, unfiltered MATCH-all on large graph (Neo4j browser will time out), label inconsistency (Process node vs all 9 labels).
2. **React dashboard** — never opened. Whatever the dashboard renders is what the committee will judge. Run `pnpm dev` and click through every page in incident-flagged state.
3. **Reproducibility from clean clone** — did not run `train.py --split temporal` and compare to committed 0.9877 ROC-AUC. Without this, the headline number is "trust me" data.
4. **`label.py` + `iocs.yaml`** — labelling is upstream of every metric. If labels are scenario-conditioned, the temporal-split metric is overstated. Need to read `label.py` end-to-end.
5. **`evaluate.py`** — full evaluation script not read; permutation-importance plots are headline material.
6. **`extract_features.py` (1125 lines)** — the parser dispatch was extracted into `botsv2_parsers/parsers.py`, but FE-specific transforms here weren't audited. Diff `botsv2_parsers/parsers.py` against the FE script to confirm the live scorer's `_raw` → feature path is byte-equivalent to the training path.
7. **`server/pipeline/`** (untracked) — supervisord-based container consolidation from the in-progress `plans/260514-2021-docker-consolidation/`. If you adopt it, P0-2's dual-publish bug must be fixed first or the consolidated container will write duplicates internally.
8. **Per-scenario recall on s400 APT (64.2%)** — biggest known model weakness. CLAUDE.md attributes it to "temporal domain shift." Examiner will probe; have an answer ready (or push that recall up).

---

## Recommended ordering of fixes (1+ month budget)

**Week 1 — Stop the bleeding** (P0-1, P0-2, P0-4)
- Fix dual-publish + add edge-uniqueness constraint. Re-run a small replay; verify edge counts match event counts.
- Decide and document the live threshold; commit the rationale to a `docs/decisions/` file.
- Reconcile Gemini-vs-Claude across code and docs.

**Week 2 — Causal correctness & detection-path coherence** (P0-3, P0-5, P1-2, P1-3)
- Merge-sort BOTSv2 replay by `_time`; remove THEIA dead code from the live path.
- Decide rule-engine's future (delete / baseline / ensemble) and execute.
- Fix the FSM state-keying bug if rules survive.

**Week 3 — Trust & reproducibility** (P1-1, P1-4, P1-5, P1-6, audit items 3 + 4 + 6)
- Collapse the duplicated feature schema; add startup assertions in the scorer.
- Add DLQs everywhere.
- Reproduce the 0.9877 number from clean clone; archive the run.
- Read `label.py`, document the labelling pipeline, write the "label leakage at dataset level" disclosure.

**Week 4 — Polish** (P2-*, dashboard click-through, prepare defense Q&A doc)
- Walk every dashboard page in incident state.
- Write a 2-page "decisions doc" listing every magic number / threshold / hyperparameter and the one-line rationale.
- Delete dead code (synthetic THEIA scenarios, `_inspect*.py`, unused services).

---

## Unresolved questions

1. **Is the rule engine staying in runtime?** This drives whether P1-2 and P1-3 are fixes or deletions.
Rule engine is not fleshed out right now but it's staying, we should probably bundle it as part of server. The server/ folder itself needs to be reorganized to be more modular 
2. **Live threshold philosophy** — precision-target or volume-target? Committee will ask; you need a one-line answer.
Precision target is more defensible because it ties to an explicit operator pain point (false alert volume), but it may require tuning to hit the target. Volume target is easier to hit but less explainable.
3. **Are the per-scenario recall numbers (s400 64.2%) part of the headline claim, or a known weakness you'll volunteer?** Framing affects how aggressively you need to fix.
No idea 
4. **Is the dashboard the canonical demo surface, or do you intend to demo through `neo4j browser` + API swagger?** The amount of dashboard work depends on this.
Canonical but it already looks pretty good, we just need to hide the 2 modern themes and only keep the clean no background theme 
5. **Anthropic vs Gemini** — which is the documented LLM choice? Resolves P0-4.
Will decide when I eventually go to tune the LLM prompts
6. **Is BOTSv2 the only dataset for the thesis?** If so, delete THEIA from the codebase entirely; if not, the dual-mode ingest needs proper testing on both paths. 
Yes, BOTSv2 only. THEIA code is dead and should be deleted.
