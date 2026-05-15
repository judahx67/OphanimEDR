# Phase 04 — Dashboard Polish, Dead Code, `server/` Reorganization

**Covers:** dashboard theme trim, dashboard demo-flow click-through, dead-code deletion, `server/` reorganization, decisions-doc compilation.

**Prerequisite:** Phases 01–03 complete and stable. Reorganization on top of broken code creates ambiguity about whether a fix is real or an accidental side-effect of moving files.

---

## 1. Dashboard themes — trim to one (user decision)

**Decision:** keep only the clean no-background theme; hide the two modern themes.

**Changes:**
- `server/dashboard/src/pages/` (or theme provider — needs locating) — remove the two modern theme options from the picker.
- If themes are switchable at runtime, remove the toggle from settings UI entirely. Single theme = simpler demo.

**Success criteria:**
- No theme toggle visible.
- Every page renders in the clean theme on first load.

---

## 2. Dashboard demo-flow click-through

**Audit step previously deferred:**
- Run `docker compose up -d` (post-Phase-01 fixed state) + a 5000-event replay.
- Click every page in incident-flagged state.
- Note every visual bug, broken link, slow query, console error.
- Produce `plans/reports/dashboard-walkthrough-260515-{date}.md`.

**Likely fixes:**
- N+1 Cypher queries in `api/edr_server/database.py` (689 lines, not audited yet).
- Incident-detail page may not handle the new dual `source` property (Phase 02 item 2).
- Causal-chain viz: now that replay is time-ordered (Phase 02 item 1), the chain should render correctly — verify.

**Success criteria:**
- Dashboard walkthrough doc lists zero P0 bugs.
- One pass with a non-author tester (the user) — they can demo without coaching.

---

## 3. Delete dead code

**Targets (from audit P2-*):**
- `server/ml-engine/botsv2/_inspect.py`, `_inspect_featured.py`, `_show_eval.py`, `_show_perm.py`, `_verify_fe.py` — keep only if used by a phase-3 script; otherwise delete or move to `server/ml-engine/botsv2/_scratch/` and `.gitignore`.
- `server/rule-engine/rules.py` (185 lines, "legacy hardcoded rules (dead code, kept as reference)" per CLAUDE.md) — delete. YAML is the source of truth.
- Anything left from THEIA after Phase 01 — second pass.

**Success criteria:**
- `git ls-files server/ | xargs grep -L .` shows no obviously-dead files.

---

## 4. `server/` reorganization

**Goal:** modular package layout that reads cleanly to an examiner.

**Proposed structure (subject to user review):**

```
server/
├── compose/                 # docker-compose.yml, env templates, deploy scripts
├── shared/                  # schema_core, ProvenanceNode, NormalizedEvent — all shared types
├── services/
│   ├── ingest/
│   ├── graph-builder/
│   ├── rule-engine/
│   ├── ml-edge-scorer/
│   ├── llm-analyzer/
│   ├── api/
│   └── simulator/
├── ml/
│   ├── botsv2/              # current ml-engine/botsv2/
│   ├── parsers/             # current botsv2_parsers/
│   └── decisions/           # link to docs/decisions/ for ML-specific calls
├── dashboard/
└── pipeline/                # consolidated container artifacts (if adopted)
```

**Changes:**
- Move files; update imports; update Dockerfiles; update docker-compose paths.
- One commit per service (NOT one mega-commit). Bisect-friendly.

**Success criteria:**
- `docker compose up -d` and 1000-event replay still work after every commit.
- Examiner skimming `server/` can match each folder to a sentence in the thesis.

**Important:** evaluate the in-progress `plans/260514-2021-docker-consolidation/` plan before reorganizing — its supervisord-pipeline container assumes the current flat layout. Either land that consolidation first OR fold it into this reorg.

---

## 5. Decisions doc compilation

**Build the defense binder:**

Collect all `docs/decisions/*.md` written during Phases 01–03 (threshold-choice, detection-paths, labelling, parser-equivalence, s400-recall, plus any new ones), plus a fresh `docs/decisions/feature-schema.md` (why these 39 features, why drop these as leaky), into a single `docs/defense-decisions.md` index.

**Each decision should answer:**
- What is the decision?
- What alternatives were considered?
- Why this one?
- What numbers / measurements justify it?

**Success criteria:**
- Every magic number / threshold / hyperparameter in the codebase appears in this doc with a one-line rationale.
- User can defend any one of them from this doc in under 30 seconds.

---

## Todo

- [ ] (1.a) Locate theme config; remove two modern themes
- [ ] (2.a) Run replay + dashboard click-through; produce walkthrough report
- [ ] (2.b) Fix dashboard P0 bugs found in walkthrough
- [ ] (3.a) Audit and delete underscore-prefixed dev scripts
- [ ] (3.b) Delete `rule-engine/rules.py` legacy
- [ ] (3.c) Second-pass THEIA deletion sweep
- [ ] (4.a) Get user sign-off on proposed reorg structure
- [ ] (4.b) Decide: land docker-consolidation first or fold it in
- [ ] (4.c) Execute reorg, one commit per service
- [ ] (5.a) Write `feature-schema.md` decisions doc
- [ ] (5.b) Compile `docs/defense-decisions.md` index
- [ ] (5.c) User walkthrough of the binder — fix gaps

---

## Risks

- **Reorg + dashboard work simultaneously** is the most likely place to break things at the wrong time (i.e., a week before defense). Lock the reorg early in the phase; spend the last week ONLY on demo polish.
- **Docker-consolidation plan** (separate, in-progress) interacts with this reorg. Two plans touching `server/` paths at once = merge hell. Resolve dependency before starting item 4.

---

## Unresolved

- Does the docker consolidation (`plans/260514-2021-docker-consolidation/`) ship before or after this reorg? My recommendation: ship it first (it's a self-contained packaging change), then reorganize on top.
- Should `docs/defense-decisions.md` also include the thesis-title revision? Title still references "Causality Tracking and Incremental Alignment" but the pivot dropped that framing. Either update the title or scope the title to a related-work positioning rather than a claim.
