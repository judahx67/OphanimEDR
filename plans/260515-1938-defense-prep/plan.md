# Defense Preparation Plan

**Goal:** Take the project from "sloppy vibe-coded" to defensible. Every decision revisited; every magic number justified; demo path bulletproof.

**Source:** [audit-260515-1921-defense-readiness.md](../reports/audit-260515-1921-defense-readiness.md)

**Locked decisions (from audit Q&A, 2026-05-15):**
- BOTSv2-only — delete all THEIA code.
- Rule engine stays as a runtime detector — needs structuring, not deletion.
- Live threshold = precision-target (re-derive on val to hit a chosen target precision; document the live recall that falls out).
- Demo surface = dashboard. Hide the two "modern" themes, keep the clean no-background theme only.
- LLM choice (Anthropic vs Gemini) — deferred until prompt tuning. Docstrings/CLAUDE.md still need to be reconciled with the current Gemini code.
- `server/` reorganization — defer until after P0/P1 fixes land. THEIA deletion is the only pre-fix structural change.

**Open question carried into the work:**
- Per-scenario recall on s400 APT (64.2%). Needs investigation in Phase 3 with concrete recommendation.

---

## Phases

| # | Phase | Status | Covers |
|---|---|---|---|
| 01 | [Stop the bleeding](phase-01-stop-the-bleeding.md) | pending | P0-2 dup edges, P0-1 threshold, P0-4 docs reconcile, P0-5 THEIA purge |
| 02 | [Causal correctness & rule-engine](phase-02-causal-correctness.md) | pending | P0-3 replay ordering, P1-2 rule-engine framing, P1-3 FSM bug |
| 03 | [Trust & reproducibility](phase-03-trust-and-reproducibility.md) | pending | P1-1 schema dedup, P1-4 DLQ, P1-5 score-write race, label.py audit, clean-clone reproduction, s400 investigation |
| 04 | [Dashboard, polish, server/ reorg](phase-04-polish-and-reorg.md) | pending | Theme trim, dashboard click-through, dead-code deletion, server/ reorganization, decisions doc |

---

## Working agreement

- Each phase file has its own todo checklist and success criteria.
- I propose changes; user reviews diff before commit.
- Every P0/P1 fix gets one focused commit (conventional-commits) so the defense-prep history is legible.
- Don't roll into the next phase until the prior phase's success criteria are met.
