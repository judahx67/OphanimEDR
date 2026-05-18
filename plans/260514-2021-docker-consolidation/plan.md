# Docker Consolidation

Collapse 4 RabbitMQ-worker containers (ingest, graph-builder, rule-engine, ml-edge-scorer) into a single `pipeline` container to reduce RAM footprint on laptop hardware. Keep data services (rabbitmq, neo4j) and UI (api, dashboard) untouched.

## Goals

- Cut steady-state RAM by ~400–600MB
- 5 always-on containers instead of 7
- No throughput regression vs current stack
- No code changes inside worker modules beyond making each runnable from one parent process

## Non-goals

- Refactoring worker logic (asyncio merge — deferred to a follow-up if needed)
- Touching the ML models or training pipeline
- Windows-agent work (separate decision pending)

## Architecture

```
rabbitmq ─ neo4j ─ pipeline ─ api ─ dashboard
                      │
                      └─ supervisord runs 4 python main.py processes:
                         ingest · graph-builder · rule-engine · ml-edge-scorer
```

Profiles unchanged: `simulator`, `llm`.

## Phases

| # | File | Status |
|---|---|---|
| 01 | [phase-01-pipeline-container.md](phase-01-pipeline-container.md) | pending |
| 02 | [phase-02-compose-refactor.md](phase-02-compose-refactor.md) | pending |
| 03 | [phase-03-validation.md](phase-03-validation.md) | pending |

## Dependencies

- Existing worker `main.py` entrypoints stay intact
- `ml-edge-scorer` still needs models volume mount — moves to pipeline container
- Build contexts: ingest and ml-edge-scorer build from `server/` root; graph-builder and rule-engine from their own dirs. Unified Dockerfile must handle both.

## Rollback

`git revert` the compose change. Old per-service Dockerfiles stay on disk during phase 01–02 and only get deleted in a follow-up commit after phase 03 passes.
