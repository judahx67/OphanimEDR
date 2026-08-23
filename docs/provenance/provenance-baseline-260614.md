# Provenance Baseline — 2026-06-14 (pre-rerun freeze)

Ground truth captured BEFORE the Docker vhdx delete + full re-execution. The rerun must reproduce
these (or supersede with a documented reason). Read-only reference.

- **git HEAD:** `0e4c7d67635265eebaf3690d823e674e76e53667` (branch `feature/comparative-study`)
- **Working tree:** uncommitted incl. scorer write-back fix (theia-{gnn,orthrus}-scorer/main.py),
  results-frozen §F.7, this plan. See `git status`.

## Canonical weights (loaded by code/compose) — md5

| Dir | Role | Loaded by | git | md5 (key file) |
|---|---|---|---|---|
| `theia_ours_v3` | w2v (FLASH + Orthrus features) | both scorers, compose, c3, train_orthrus | tracked c897f6c | `word2vec_theia_E3.model` = `eaad90716a325ef510f138644cb65676` |
| `theia_orthrus_v1` | Orthrus prod (GAT+decoder) | orthrus scorer, compose, c3 | tracked c897f6c | enc `7199618a45fbe726f3ee56b4518b081e` · dec `55eb80827661149f508e96660732b265` · meta `34b4cf1b2a3bcab104d1dde3171ff733` |
| `theia_orthrus_s1/s2/s3` | Orthrus C3 multi-seed (F.4) | c3_budget_sweep, multi-seed C3 | tracked 155f730 | (md5 in 3d) |
| `theia_lgbm` | A2 node-type LGBM boosters | `_verify_lgbm.py`, `_eval_process_level.py` | ⚠️ UNTRACKED | t0 `2f6547d3791b371e5babe3c64db73259` · t1 `84cad074897e5035dc50272caa767eb6` · t2 `e976e9a8773851171c82a142a6a704a8` |
| `theia_novel` | A5/A6/A7 novelty | `train_lgbm_novel.py` | tracked 58dd58e | `lgbm_xt_novel_E3.pkl` = `6b4c768db9aa63c8cdc15dd1df540058` |

## Resolved ambiguities (the artifacts the user couldn't place)

- **`theia_ours_v2`** — older w2v dir; its `word2vec_theia_E3.model` is **byte-identical** to v3's
  (`eaad9071…`). v3 is a superset (adds per-graph `lword2vec_gnn_theia*_E3.pth`). v2 = redundant,
  UNTRACKED. A2's number is unaffected by v2-vs-v3. **Action:** repoint `_verify_lgbm.py` /
  `_eval_process_level.py` to v3; archive v2.
- **`orthrus_theia_e3`** — first Orthrus train (Jun 8 17:14), md5 `c51e05b5…` ≠ v1 `7199618a…`.
  Superseded by `theia_orthrus_v1` (Jun 9). No code loads it. UNTRACKED orphan. **Action:** archive.
- **`theia_lgbm`** — A2 boosters re-created Jun 13 04:25 (F.6 re-run, restored from commit `a11bddd`).
  Real and load-bearing but **never re-committed**. **Action (production-blocking):** commit so the A2
  headline traces to a versioned artifact.
- **4× `_reproduce_flash_gnn.*`** (`.log` cited / `.log.orig` pre-F.6 original / `.out` / `_rerun.out`)
  — only `.log` is canonical (B4). Others = scratch. **Action:** move to `_scratch/`.
- **15× `_feat_*.npz` / `_*.out`** — regenerable feature caches + run scratch. **Action:** `_scratch/`.

## Production-blocking provenance gaps found
1. **A2 (headline 2-hop-inflation cell) depends on UNTRACKED weights** (`theia_lgbm`, `theia_ours_v2`).
   Must be committed/standardized before this is presentation-grade.
2. Mixed bare-name vs full-path log refs in results-frozen.md (6 flagged) — normalize in 3b.
