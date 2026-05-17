# Project Status

Master tracker. One page. Updated as state changes. Links out for detail.

**Thesis:** *Applying Causality Tracking and Incremental Alignment for Graph-Based Threat Hunting* — pivot 2026-05-15: now binary classification + LLM explanation on the BOTSv2 provenance graph.

---

## Where the project is right now

| Layer | State |
|---|---|
| Pipeline | Running. ingest → graph-builder → rule-engine → ml-edge-scorer → llm-analyzer all healthy |
| ML model (deployed) | `lgbm_xt_temporal_no_st` (honest, no sourcetype) — **99.77% precision, 23 FP/1M test events** |
| ML model (comparison) | `lgbm_xt_temporal` (headline, with sourcetype) — stored but does not alert |
| Rule engine | 36 YAML rules; FSM cross-process keying fixed; event-time expiration |
| LLM analyser | Gemini 2.0 Flash; 1-hop subgraph; dedup TTL 5min; alerts only on honest model |
| Dashboard | Working; multi-root subgraph; meaningful edge detail; sparse-context hint |
| Defense docs | 5 decisions docs + binder; all magic numbers justified |

---

## Active focus

Defense-prep phases 01–04 → **done**. Next active work is **Phase 5: LLM enrichment** — queued, see [`memory/project_llm_enrichment_roadmap.md`](C:/Users/juda/.claude/projects/J--THESIS-EDR/memory/project_llm_enrichment_roadmap.md).

---

## Recent significant changes

| Date | Change | Why |
|---|---|---|
| 2026-05-17 | Scorer flipped to **honest-only** alerting | Headline model has 305× more FPs; AUC was misleading. See [model-choice.md](decisions/model-choice.md) |
| 2026-05-17 | Documented brewertalk.com FP class | 49.7% of demo alerts hit victim's own infra — exactly the documented 0.608 precision manifesting |
| 2026-05-17 | Multi-root subgraph (subject + object) | 1-hop on socket-only was meaningless; now passes both endpoints |
| 2026-05-17 | Subgraph endpoint accepts query-param node_id | FastAPI path routing broke on `/` and `?` in socket UUIDs |
| 2026-05-16 | FSM cross-process keying + event-time expiration | Rule chains crossing FORK boundaries now advance; replays respect causal windows |
| 2026-05-16 | Score-write retry buffer + `:OrphanScore` fallback | No score silently dropped; verified live |
| 2026-05-16 | Dead code purge (449 lines) | `rule-engine/rules.py` legacy + 5 dev scripts |

---

## Where things live

### Code
- [`server/`](../server/) — all services (compose root)
- [`server/ml-engine/botsv2/`](../server/ml-engine/botsv2/) — training, schema, threshold calibration
- [`server/ml-edge-scorer/`](../server/ml-edge-scorer/) — live scoring
- [`server/rule-engine/`](../server/rule-engine/) — YAML rules + FSM matcher
- [`server/llm-analyzer/`](../server/llm-analyzer/) — Gemini narrative service

### Docs (project)
- [`docs/STATUS.md`](STATUS.md) — this file
- [`docs/defense-decisions.md`](defense-decisions.md) — single-page index of every design choice with the number that justifies it
- [`docs/decisions/`](decisions/) — five decisions docs:
  - [`model-choice.md`](decisions/model-choice.md) — honest-only deployment + AUC paradox
  - [`threshold-choice.md`](decisions/threshold-choice.md) — F1-optimal threshold, brewertalk FP class
  - [`feature-schema.md`](decisions/feature-schema.md) — 42-column schema, leaky-col audit
  - [`labelling.md`](decisions/labelling.md) — IOC labelling, leakage disclosure
  - [`s400-recall.md`](decisions/s400-recall.md) — APT temporal domain shift
  - [`detection-paths.md`](decisions/detection-paths.md) — rule-engine + ML two-path framing
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) — detailed component architecture (519 lines, reference)
- [`docs/CONTEXT.md`](CONTEXT.md) — historical handoff (AutoGluon → manual rebuild)

### Docs (thesis)
- [`docs/thesis/index.md`](thesis/index.md) — chapter index
- [`docs/thesis/ml-pipeline-spec.md`](thesis/ml-pipeline-spec.md) — full ML spec
- [`docs/thesis/system-architecture.md`](thesis/system-architecture.md) — current stack
- [`docs/thesis/chapter-01..06.md`](thesis/) — chapter drafts

### Plans
- [`plans/260515-1938-defense-prep/`](../plans/260515-1938-defense-prep/) — four-phase prep plan; all phases done
- [`plans/reports/`](../plans/reports/) — readiness audits, walkthroughs

### Memory (persists across sessions)
- `~/.claude/projects/J--THESIS-EDR/memory/MEMORY.md` — index of all memories
- Key entries: `project_ml_spec`, `project_llm_enrichment_roadmap`, `project_model_false_positive_pattern`, `project_thesis_pivot`

---

## Headline metrics (for examiner answers)

| Number | What | Source |
|---|---|---|
| **0.9977** | Test precision of deployed model | `models/lgbm_xt_temporal_no_st/test_metrics.json` |
| **0.187** | Test recall of deployed model | same |
| **23** | False positives in 1M test events | same (confusion matrix) |
| **0.9530** | AUC of headline (comparison) model | `models/lgbm_xt_temporal/test_metrics.json` |
| **0.6080** | Headline model precision (why we don't deploy it) | same |
| **36** | YAML detection rules | `server/rule-engine/rules/` |
| **42** | Model feature count | `server/ml-engine/botsv2/schema.py` |
| **5.2M** | Training dataset size (173K positive) | `data/split_summary.json` |
| **300s** | LLM dedup window | `server/llm-analyzer/main.py` env |

---

## Known open items

| Item | Status |
|---|---|
| LLM enrichment (MITRE feed, multi-LLM, graph pre-processing, YARA output) | Next active phase |
| k-way merge replay (Phase 02 deferred) | Deferred — risky pre-defense |
| `server/` reorganization (Phase 04 deferred) | Deferred — risky pre-defense |
| DLQs on consumer queues (Phase 03 item 2) | Deferred — robustness only |
| Clean-clone reproducibility script (Phase 03 item 5) | Deferred — multi-hour rerun |
| `extract_features.py` vs live parsers byte equivalence audit | Open audit item |

---

## How to update this file

Keep it under 200 lines. When something material changes (model swap, new alerting logic, new decision doc, phase complete):
1. Update the "Where the project is right now" table
2. Add a row to "Recent significant changes"
3. If a new decisions doc was written, add it to "Docs (project)"
4. If a metric changed, update "Headline metrics"

Avoid duplicating doc content — link to it instead.
