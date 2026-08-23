# THEIA trained_weights — canonical artifacts (2026-06-14)

Single source of truth for which weights dir each experiment uses. Established from evidence
(code refs + git history + md5), not memory. See `plans/.../provenance-baseline-260614.md`.

| Dir | Canonical for | Loaded by | Notes |
|---|---|---|---|
| `theia_ours_v3` | w2v features (A1a GNN, A2 LGBM, A3/A4 content, Orthrus, C3) | both live scorers, _verify_gnn/_verify_lgbm/_eval_process_level, c3_*, train_orthrus | has `word2vec_theia_E3.model` + per-graph `lword2vec_gnn_theia*_E3.pth` GNN shards. **THE canonical w2v.** |
| `theia_orthrus_v1` | Orthrus prod detector (§4.2, C3 base) | orthrus scorer, c3_composition_control | GAT encoder + edge-action decoder, benign-p99 threshold |
| `theia_orthrus_s1/s2/s3` | Orthrus C3 multi-seed variance (F.4) | c3_budget_sweep, multi-seed C3 | seeded retrains; cite the ρ RANGE 0.79–0.85 |
| `theia_lgbm` | A2 node-type LGBM boosters | _verify_lgbm, _eval_process_level | restored from `a11bddd`, committed `c445760` |
| `theia_novel` | A5/A6/A7 novelty | train_lgbm_novel | |

## Superseded / archived (moved to `_superseded/`, no code references them)
- `theia_ours_v2` — older w2v dir; its `word2vec_theia_E3.model` is **byte-identical** to v3's
  (md5 `eaad9071…`) but it lacks the GNN shards. Scripts repointed v2→v3 on 2026-06-14.
- `orthrus_theia_e3` — first Orthrus train (Jun 8), superseded by `theia_orthrus_v1` (Jun 9). md5 differs.
