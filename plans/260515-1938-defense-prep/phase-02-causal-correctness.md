# Phase 02 — Causal Correctness & Rule Engine

**Covers audit findings:** P0-3 (replay ordering), P1-2 (rule-engine framing), P1-3 (FSM state-keying bug).

**Prerequisite:** Phase 01 complete (THEIA gone, no dup edges).

---

## 1. Merge-sort BOTSv2 replay by `_time` (P0-3)

**Problem:** `simulator/main.py:run_botsv2_loader` iterates partitions sequentially per sourcetype. Cross-sourcetype causal chains arrive out of order.

**Approach:** k-way merge across the per-sourcetype Parquet files, ordered by `_time`. Implement as a generator that opens all partitions, reads one batch each, and yields rows in heap-sorted `_time` order.

**Changes:**
- `server/simulator/main.py` — replace the partition loop with a k-way merge iterator. Helper module `server/simulator/_botsv2_merge.py` keeps `main.py` readable.
- Rate limiting stays as-is (event/sec on the merged stream).

**Success criteria:**
- Replay 10k events, dump (`_time`, `sourcetype`) pairs. Sequence is monotonically non-decreasing on `_time`. Multiple sourcetypes are interleaved (not block-sorted by sourcetype).

---

## 2. Rule-engine framing & runtime survival (P1-2)

**Decision:** rule-engine stays as runtime detector, paired with ML. Frame as **complementary, not competing**: rules catch known patterns deterministically; ML catches statistical anomalies. LLM analyzer narrates ML alerts; rule incidents already carry MITRE labels.

**Defense narrative to make explicit:**
- Two `:Incident` node sources, distinguishable by `source` property: `"rule-engine"` vs `"ml-llm"`.
- Dashboard surfaces both with provenance.
- "Why both?" answer: rules = deterministic recall on the 11 known tactics covered by the 36 YAML files; ML = generalization to behaviour the rules don't enumerate. Quantified by **rule-vs-ML agreement table** generated offline (Phase 03).

**Changes:**
- `server/rule-engine/main.py` — make the `:Incident` write include `source: "rule-engine"` (currently doesn't). Match `llm-analyzer`'s `source: "ml-llm"` convention.
- `docs/decisions/detection-paths.md` — new short doc explaining the two-path framing.
- Dashboard incident list (Phase 04 work) — show source badge per incident.

**Success criteria:**
- Every `:Incident` node has a non-null `source` property.
- Decisions doc explains the two paths in ≤ 1 page.

---

## 3. Fix FSM state-keying bug (P1-3)

**Problem:** `rule-engine/engine.py:130` keys partial states by `(rule_id, current_event.subject_id)`. After step 1, when control passes to a forked child, the next event's subject is the child — state lookup misses.

**Fix options:**
- (a) Key by `rule_id` only; scan all states per event (O(rules × states), fine at our scale).
- (b) Maintain a secondary index `active_subject_id → set[(rule_id, root_subject_id)]`. More efficient but more code.

**Recommendation: (a)** — at 36 rules and burst ≤ 100 active states, the scan is trivial. Simpler.

**Changes:**
- `server/rule-engine/engine.py` — rewrite `process_event` to:
  1. Scan all `self._states.values()` where `state.rule_id == rule.id`.
  2. For each, test if current event matches `conditions[state.step]` AND `event.subject.id == state.active_subject_id`.
  3. Advance / fire as before.
  4. Separately, try to seed a new state from `conditions[0]`.
- Add a unit test that exercises a 2-step rule across a FORK boundary.

**Success criteria:**
- Unit test passes: 2-step rule (parent EXEC `/tmp/x` → child CONNECT `attacker.com`) fires on a synthetic trace.
- At least one of the existing sequence-mode rules in `rules/*.yml` fires on a relevant scenario replay (smoke test).

---

## 4. Wall-clock-vs-event-time in FSM expiration (P2-bordering-P1)

**Problem:** `engine.py:106-114` expires partial states using `time.time() - state.last_event_ts > window`. During replay, `time.time()` doesn't match event timestamps.

**Fix:** track `state.last_event_ts` as the event's `timestamp` (ns) and use the latest seen event's timestamp as "now". Convert ns → s when comparing to `window`.

**Changes:**
- `server/rule-engine/engine.py` — switch to event-time-based expiration.
- Pass each event's timestamp into `_expire_old_states` as the "current time".

**Success criteria:**
- Same unit test as item 3, but with timestamps spread across hours of event-time but compressed into seconds of wall time. Rule still fires within the event-time window.

---

## Todo

- [ ] (1.a) Write `_botsv2_merge.py` k-way iterator
- [ ] (1.b) Wire into `run_botsv2_loader`; remove sequential partition loop
- [ ] (1.c) Validation: 10k-event dump, verify monotonic `_time`
- [ ] (2.a) Add `source: "rule-engine"` to rule-engine incident writes
- [ ] (2.b) Write `docs/decisions/detection-paths.md`
- [ ] (3.a) Rewrite `engine.process_event` with state-scan model
- [ ] (3.b) Add unit test for cross-FORK 2-step rule
- [ ] (3.c) Smoke-test a real sequence-mode rule on replay
- [ ] (4.a) Switch expiration to event-time
- [ ] (4.b) Add second unit test for time-compressed replay

---

## Risks

- **k-way merge memory** — opening all partitions at once: BOTSv2 has 85+ sourcetypes; reading one batch each may push memory. Mitigation: cap simultaneous open partitions, or pre-merge into one time-sorted Parquet at dataset-build time.
- **FSM rewrite (item 3)** may break the few rules that currently DO fire (single-condition rules work today). Add a regression test using existing rule outputs from the current replay as the "before" baseline.

---

## Unresolved

- Should we **pre-merge BOTSv2 into one time-sorted Parquet** as a dataset-build artifact rather than merging at replay time? Pros: replay code stays simple, no memory question. Cons: one more dataset artifact to manage.
