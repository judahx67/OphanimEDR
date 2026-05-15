# Phase 03 — Trust & Reproducibility

**Covers audit findings:** P1-1 (schema dedup), P1-4 (DLQ), P1-5 (score-write race), P1-6 (label leak audit), open follow-ups 3 + 4 + 6 from the audit, and the s400 recall question.

**Prerequisite:** Phase 02 complete. Causal ordering correct, rule engine sound — without these, reproducibility numbers measure a broken pipeline.

---

## 1. Collapse the duplicated feature schema (P1-1)

**Problem:** `botsv2_parsers/parsers.py:20-78` is a hand-copy of `ml-engine/botsv2/schema.py`. Drift = silent recall degradation.

**Fix:** one schema module, two importers.

**Changes:**
- Move enum + constant definitions into `server/botsv2_parsers/schema_core.py` (pure-Python, no Polars/pandas deps).
- `server/ml-engine/botsv2/schema.py` — re-export the core from `schema_core` and add the ML-only bits (LEAKY_COLS, model_feature_columns, etc.) that depend on it.
- `server/botsv2_parsers/parsers.py` — `from .schema_core import NodeType, EdgeType, NUMERIC_FEATURES, ...`.
- ML-engine container needs `botsv2_parsers` on PYTHONPATH at training time too (current train.py runs locally outside containers — need to verify import path).

**Add startup guard in ml-edge-scorer:**
- `server/ml-edge-scorer/model_loader.py` — after loading each booster, assert `set(model.feature_names) == set(model_feature_columns())`. Crash loudly on mismatch.

**Success criteria:**
- Only ONE definition of NUMERIC_FEATURES / CATEGORICAL_FEATURES / NodeType / EdgeType in the codebase.
- Schema assertion fires (logs + exits) if a model's feature_names.json drifts from the live schema.

---

## 2. DLQ everywhere (P1-4)

**Problem:** ingest and scorer both `basic_nack(requeue=False)` on errors → silent drops, no telemetry.

**Changes:**
- Declare per-consumer DLQs: `raw_events.dlq`, `normalized_events.dlq`, `normalized_events_scoring.dlq`, `ml_alerts.dlq`.
- Wire each consumer's queue with `x-dead-letter-exchange` arg pointing to the DLQ.
- On error path, log the exception type + first 200 chars of body, then nack with requeue=False (which now routes to DLQ).
- Add a `/healthz` HTTP endpoint to each consumer service exposing `errors_total`, `drops_total`, `dlq_depth`.

**Success criteria:**
- Inject a malformed message; observe it land in the DLQ within seconds.
- `/healthz` exposes per-service counters; dashboard can show them.

---

## 3. Eliminate the score-write race (P1-5)

**Problem:** scorer sleeps 3s and hopes the edge exists. Misses are silently lost.

**Approach A (chosen):** Re-MATCH-with-retry. Scorer's flush returns the set of `event_id`s that did NOT match; those go back into a small retry buffer with exponential backoff (max 3 retries, total ≤ 30s). After max retries, write a `:OrphanScore` node so the score isn't lost and we can audit how many drift orphans accumulate.

**Changes:**
- `server/ml-edge-scorer/main.py` — change `_WRITE_SCORES_BATCH_CYPHER` to RETURN the matched event_ids. Reconcile in Python: unmatched → retry queue.
- Track `orphan_scores_total` metric.

**Success criteria:**
- Under bursty replay (500 ev/s, 60s), orphan_scores ≤ 0.1% of scored events.
- No score is dropped silently — every score either lands on its edge or surfaces as an orphan node.

---

## 4. Label-pipeline audit (P1-6, open follow-up 4)

**Problem:** Labels drive every metric. Need to read `label.py` end-to-end and prove the label is NOT scenario-conditioned in a leaky way (or document the leak honestly).

**Changes (read-only):**
- Read `server/ml-engine/botsv2/label.py` + `iocs.yaml` end-to-end.
- Produce `docs/decisions/labelling.md` documenting:
  - Exact labelling rule (IOC match logic).
  - What `iocs.yaml` contains (host names, IPs, file paths, etc.).
  - Whether `scenario` is used directly in labelling (likely yes — flag explicitly).
  - The "leakage at dataset level" disclosure for the defense.

**Success criteria:**
- Decisions doc exists; user can read it and answer "how were labels assigned?" without looking at code.

---

## 5. Clean-clone reproducibility check (open follow-up 3)

**Process:**
1. Fresh clone of repo (separate worktree).
2. `python train.py --split temporal` (assuming featured parquet exists; if not, also run featurization).
3. Verify printed ROC-AUC ≈ 0.9877 (within ±0.001).
4. Same for `--split temporal --drop-feature sourcetype`, expecting ≈ 0.9135.
5. Commit a `make repro` target in a `Makefile` (or `scripts/reproduce-headline.ps1`).

**Success criteria:**
- Two reproducible numbers, archived run logs in `plans/reports/reproduction-260515-{date}.log`.
- One-command reproduction documented in README.

---

## 6. `extract_features.py` vs live parsers byte-equivalence (open follow-up 6)

**Problem:** Training-time parser logic lives in `extract_features.py` (1125 lines); live-scoring parser logic lives in `botsv2_parsers/parsers.py` (900 lines). They were forked. If they diverged, scores trained on one feature distribution are served on another.

**Approach:** for a sample of 1000 BOTSv2 events of each sourcetype:
- Parse with extract_features's dispatch.
- Parse with botsv2_parsers's dispatch.
- Diff the resulting feature dicts.

**Changes:**
- `server/ml-engine/botsv2/_verify_fe_vs_parsers.py` (already an underscore-script slot exists; reuse the pattern).
- Document any non-trivial differences in `docs/decisions/parser-equivalence.md`.

**Success criteria:**
- Zero functional difference on the sample, OR all differences are documented and assessed as benign.

---

## 7. s400 APT recall investigation (open follow-up 8 from audit)

**Problem:** 64.2% recall on s400_taedonggang_apt vs 99.98% on s200. CLAUDE.md says "temporal domain shift" — need to verify.

**Approach:**
- Pull val predictions on s400-labeled rows. Look at the score distribution.
- Per-sourcetype breakdown WITHIN s400 — is it concentrated in a few sourcetypes?
- Cross-check: stratified-split recall on s400 (oracle mix). If stratified hits 95%+ and temporal hits 64%, the domain-shift story is correct. If stratified also misses, the model genuinely doesn't have signal.

**Defense framing options:**
- (a) "Acknowledged limitation — APT is naturally harder; our threshold trades recall for precision."
- (b) "Fixed by adding feature X" (requires actual work, depends on root cause).
- (c) "s400 is the temporal-shift demonstration in the thesis, not a failure" — credible only if we can show the stratified upper bound is also lower than s200.

**Changes:**
- `server/ml-engine/botsv2/_investigate_s400.py` — eval-time investigation script.
- `docs/decisions/s400-recall.md` — root cause + chosen framing.

**Success criteria:**
- Decisions doc names the root cause and the chosen framing. Examiner can be answered in one breath.

---

## Todo

- [ ] (1.a) Extract `schema_core.py`; refactor both schema.py and parsers.py to use it
- [ ] (1.b) Add startup feature-schema assertion in model_loader
- [ ] (2.a) Declare DLQs and dead-letter-exchange args on each consumer queue
- [ ] (2.b) Add `/healthz` to each consumer service
- [ ] (3.a) Implement re-MATCH-with-retry in ml-edge-scorer
- [ ] (3.b) Add OrphanScore node-write fallback + metric
- [ ] (4.a) Read label.py + iocs.yaml
- [ ] (4.b) Write labelling decisions doc
- [ ] (5.a) Clean-clone reproduction; archive log
- [ ] (5.b) Add `make repro` / `scripts/reproduce-headline.ps1`
- [ ] (6.a) Write FE-vs-parsers diff script
- [ ] (6.b) Document any differences
- [ ] (7.a) s400 investigation script
- [ ] (7.b) Write s400 decisions doc

---

## Risks

- **Schema refactor (item 1)** can silently break training (if model_feature_columns returns a different order, booster won't load). Mitigation: train one tiny smoke model after the refactor and diff its feature_names.json against the existing one.
- **Reproducibility (item 5)** depends on data being present locally. If the featured Parquet isn't checked in (it isn't), reproduction requires also running featurization — multi-hour. Plan accordingly.
