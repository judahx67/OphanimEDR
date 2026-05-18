# Phase 03 — Validation

## Overview

Confirm the consolidated stack matches the old stack on throughput, correctness, and RAM. If validation fails, rollback is `git revert` + the old per-service Dockerfiles still on disk.

Priority: P0 · Status: pending

## Test Procedure

1. **Baseline (before merging):** on the old stack, run a fixed replay and record:
   - `docker stats --no-stream` — RSS for each container
   - Events/sec at `pipeline` inputs (rabbitmq mgmt UI: `normalized_events` consume rate)
   - Final Neo4j node + edge counts
   - Incident count
   - ML score coverage (% edges with `botsv2_ml_score` set)

   ```bash
   docker compose --profile simulator run --rm simulator \
     --scenario botsv2 --limit 50000 --rate 500
   ```

2. **New stack:** same command, same dataset window, same limit. Record the same metrics.

3. **Pass criteria:**
   - Total RAM (sum of `docker stats` RSS) drops by ≥300MB
   - Events/sec within ±10% of baseline
   - Node/edge counts within ±0.5% (allow noise from non-deterministic ordering)
   - Incident count exact match (rules are deterministic given same input ordering — if it drifts, investigate)
   - ML score coverage within ±1%

4. **Crash test:** kill one supervisord child inside the pipeline container; verify supervisord restarts it and the other 3 stay running.
   ```bash
   docker compose exec pipeline supervisorctl stop rule-engine
   docker compose exec pipeline supervisorctl start rule-engine
   ```

## Todo

- [ ] Capture baseline metrics on old stack
- [ ] Switch to new stack, run same replay
- [ ] Compare against pass criteria
- [ ] Crash-test supervisord recovery
- [ ] If pass: delete old per-service Dockerfiles in a follow-up commit
- [ ] If fail: document gap, decide rollback vs fix-forward

## Success Criteria

All 5 pass criteria met + crash test recovers cleanly.

## Cleanup (post-pass)

Separate commit after green:
- Delete `server/ingest/Dockerfile`, `server/graph-builder/Dockerfile`, `server/rule-engine/Dockerfile`, `server/ml-edge-scorer/Dockerfile`
- Keep the `main.py` and module files — they're imported by the pipeline image
- Update `CLAUDE.md` Services table to reflect the consolidated `pipeline` service
