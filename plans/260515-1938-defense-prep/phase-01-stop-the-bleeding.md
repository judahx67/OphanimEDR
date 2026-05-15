# Phase 01 — Stop the Bleeding

**Priority:** highest. These are the items that, if left alone, mean the demo shows wrong numbers and reviewers spot lies in the docs.

**Covers audit findings:** P0-1, P0-2, P0-4 (docs only), P0-5.

---

## 1. Fix dup-edge bug (P0-2)

**Root cause:** `ingest/main.py` dual-publishes every normalized event (direct + fanout), and the `normalized_events` queue is bound to both exchanges. Graph-builder consumes each event twice. `graph-builder/main.py` uses `CREATE` with no `event_id` uniqueness constraint, so Neo4j stores two parallel relationships per event.

**Changes:**
- `server/ingest/main.py`
  - Drop the direct-exchange publish at lines 133-138; keep the fanout publish only.
  - Drop the direct-exchange bind at line 96; `normalized_events` queue stays, but it binds ONLY to `edr_fanout`.
  - `RAW_QUEUE` keeps its direct binding (simulator → ingest path is one-to-one, no fanout needed).
- `server/graph-builder/main.py`
  - Change the consume queue to read from `normalized_events` bound to `edr_fanout` (matches new ingest topology).
  - Add to `_create_constraints`: `CREATE CONSTRAINT IF NOT EXISTS FOR ()-[r:EDGE_TYPE]-() REQUIRE r.event_id IS UNIQUE` — but Neo4j 5.x relationship-uniqueness needs one constraint per relationship type. Loop over all 14 edge types.
  - If we keep `CREATE` semantics: a duplicate event_id will now throw and the batch will fail. Switch to `MERGE` on relationship by event_id so the second delivery is a no-op (idempotent), and at-least-once redelivery from RabbitMQ is safe.

**Success criteria:**
- Replay 1000 BOTSv2 events. `MATCH ()-[r]->() RETURN count(r)` ≤ 1000.
- `MATCH ()-[r]->() WITH r.event_id AS id, count(*) AS c WHERE c > 1 RETURN count(*)` returns 0.

---

## 2. Replace hard-coded threshold with derived precision-target threshold (P0-1)

**Decision:** precision-target. Pick a target precision and derive the threshold on val.

**Open sub-decisions for the user (will ask before implementing):**
- Target precision: 0.95? 0.99? 0.999? Affects how much recall we publish.
- Apply target to both models, or only the headline? (Honest model has lower ceiling.)

**Changes:**
- `server/ml-engine/botsv2/train.py`
  - Extend `pick_threshold` to optionally pick by `precision_target` instead of F1. Persist both: F1-optimal threshold (existing) and precision-target threshold + the val precision/recall at each.
- `server/ml-engine/botsv2/threshold_calibration.py` — new small script: load val predictions from an existing model, sweep thresholds, output the min-threshold satisfying target precision, with recall and alert rate. Run once per model, commit the result into `threshold.json` under a new `deployment` key.
- `server/ml-edge-scorer/model_loader.py` — already reads `threshold.json`. Add `self.deployment_threshold` field.
- `server/ml-edge-scorer/main.py`
  - Delete `ML_THRESHOLD_HEADLINE` / `ML_THRESHOLD_HONEST` env defaults.
  - Use `headline_model.deployment_threshold` / `honest_model.deployment_threshold` directly.
  - Log the chosen thresholds + their val recall on startup so it shows up in the demo console.
- `docs/decisions/threshold-choice.md` — new short doc: "We chose precision target X% because [reason]. At that precision, val recall is Y%. Live alert rate on demo replay is Z/min."

**Success criteria:**
- `threshold.json` contains both F1-optimal and deployment thresholds with metrics.
- Scorer logs `deployment threshold: headline=0.XX (val_precision=0.99, val_recall=0.YY)`.
- Decisions doc exists and is ≤ 1 page.

---

## 3. Reconcile LLM-choice documentation (P0-4 docs-only portion)

**Decision:** code stays Gemini for now. Make the docs honest.

**Changes:**
- `server/llm-analyzer/main.py` — module docstring lines 1-11: replace "Claude (via Anthropic SDK)" with "Gemini (via google-genai SDK)". Remove the "prompt caching on the system prompt" line (Gemini caches differently; we're not using its explicit cache API).
- `CLAUDE.md` — two references to "Claude Sonnet narratives" → "Gemini narratives" with a footnote: "LLM choice is provisional pending prompt-tuning; may switch back to Anthropic."
- No code changes to llm-analyzer logic.

**Success criteria:**
- `grep -ri "claude" server/llm-analyzer/` returns no functional/documentation mismatch.
- CLAUDE.md is internally consistent.

---

## 4. Purge THEIA (P0-5)

**Decision:** BOTSv2-only. Delete THEIA entirely.

**Deletions:**
- `server/ingest/normalizer.py` (343 lines, THEIA-only).
- `server/simulator/main.py` — strip `apt`/`benign`/`mixed`/`theia` scenarios and the CDM helpers. Keep only `botsv2` path. ~600 lines deleted.
- `server/ingest/main.py` — remove `SOURCE_FORMAT` env, `TheiaNodeCache` allocation, the if/else branch in `on_message`. Single BOTSv2 path.
- `server/ingest/schema.py` — review for THEIA-specific fields; trim if any.
- `archive/` — move THEIA dataset references / scripts into `archive/theia-pre-pivot/` if anything's there (per memory `[[project-theia-dataset]]`).
- Any `--scenario theia` references in `scripts/deploy.ps1`, `docker-compose.yml`, README, CLAUDE.md.

**Verify post-deletion:**
- `docker compose up -d` still starts cleanly.
- `docker compose --profile simulator run --rm simulator --scenario botsv2 --limit 100` still produces edges in Neo4j.
- No import-error tracebacks in any service log.

**Success criteria:**
- `grep -ri "theia\|cdm18\|cdm20\|TheiaNodeCache" server/` returns only matches in `archive/` or memory files.
- `wc -l server/**/*.py` drops by ≥ 900 lines.

---

## Todo

- [ ] (1.a) Audit dual-publish fix — small-scale test in dev branch
- [ ] (1.b) Switch ingest to fanout-only publish; update graph-builder queue binding
- [ ] (1.c) Add per-edge-type uniqueness constraints in graph-builder
- [ ] (1.d) Switch CREATE → MERGE on relationship by event_id (idempotent under redelivery)
- [ ] (1.e) Verify with 1000-event replay; check edge count parity
- [ ] (2.a) Ask user: target precision value, and whether to apply to both models
- [ ] (2.b) Write `threshold_calibration.py`
- [ ] (2.c) Re-derive thresholds, commit new `threshold.json`
- [ ] (2.d) Update model_loader + main.py to use deployment threshold
- [ ] (2.e) Write `docs/decisions/threshold-choice.md`
- [ ] (3.a) Update llm-analyzer docstring
- [ ] (3.b) Update CLAUDE.md LLM references
- [ ] (4.a) Delete `server/ingest/normalizer.py`
- [ ] (4.b) Strip synthetic scenarios from `simulator/main.py`
- [ ] (4.c) Strip `SOURCE_FORMAT` switching from `ingest/main.py`
- [ ] (4.d) Remove THEIA references from compose / scripts / docs
- [ ] (4.e) Verify clean compose-up + small replay

---

## Risks

- **Idempotency rewrite (1.d)** is the riskiest single change. `MERGE` with all the SET clauses may behave unexpectedly. Test in isolation before committing.
- **Threshold recalibration (2.b–c)** requires val predictions for both models. If those aren't already cached, we'll need to either rerun a fast eval or load val parquet + predict_proba. Cheap but adds wall time.
- **THEIA deletion (4.\*)** is large and touches many files. Do it as ONE commit per service, not a single mega-commit, so bisect is possible if something breaks.

---

## Unresolved (decide before starting items 2 + 4)

1. **Target precision value** for the deployment threshold. My recommendation: 0.99 for headline, 0.95 for honest. Reason: honest model's lower AUC means 0.99 would push recall near zero; 0.95 keeps it usable.
2. **THEIA archive vs hard-delete** — should the THEIA code go to `archive/` (preserves history outside main) or be fully deleted (git history still has it)? My recommendation: hard-delete; git history is enough.
