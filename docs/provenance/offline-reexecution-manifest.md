# Offline Suite Re-execution Manifest (full re-run, 2026-06-14)

Scope: re-execute EVERY offline cell from `results-frozen.md` and diff each metric against its
frozen log. Production/presentation-grade. Multi-session grind — update STATUS as cells complete.

- **Env:** `J:\THESIS-EDR\RESEARCH\.venv\Scripts\python.exe` (lgbm 4.6.0, torch 2.11.0+cpu, gensim 4.4.0)
- **Path drift to watch:** THEIA scripts now live in `server/ml-engine/theia/`; several frozen logs are
  cited under `external/Flash-IDS/`. Confirm script location per cell before running.
- **Verify rule:** re-run to a `*_rerun2.log`, diff the metric line(s) vs the frozen value below.
  PASS = digit-identical (or documented supersession). Record actual.

## ✅ COMPLETE (2026-06-14) — ALL CELLS DIGIT-IDENTICAL
Every cited number in results-frozen.md re-executed this session and reproduced digit-for-digit
(THEIA A1a/A1b/A2/A3-A4/A5-A8, OpTC B1/B2/B3/B4/B4-GraphSAGE/B5, C3 base+budget+3-seed, PCSA §G GO +
§H NO-GO, F.6 labels) + the live demo (FLASH 1139 / Orthrus 300). Heavy cells (A2, B4, B5) re-run
from raw. Trained models (B4-GraphSAGE, C3 seeds, PCSA) reproduce exactly → seeds are fixed. No cell
differed. Repro is now one-command (broken-by-default paths fixed, CANONICAL.md added). Logs: each
cell's `_*_rerun2.log` on disk under server/ml-engine/{theia,optc}/.

## STATUS legend: ⬜ todo · 🟡 running · ✅ pass(digit-match) · ⚠️ differs(investigate) · ⏭ superseded

| Cell | Frozen value | Script (cwd) | Command | Out log | Status |
|---|---|---|---|---|---|
| A1a GNN ours | RAW F1 0.768 (.813/.727) | theia/_verify_gnn.py | `python _verify_gnn.py` (default now v3) | _verify_gnn_rerun2.log | ✅ digit-identical (2026-06-14, [R] cache-reuse; acc .9377/RAW .7678/2hop .9646) |
| A1b GNN shipped | RAW F1 0.836 (.722/.993) | theia/_verify_gnn.py | `THEIA_WEIGHTS=external/Flash-IDS/trained_weights/theia THEIA_GNN_CACHE=.../_verify_gnn_feats.flash.pkl python _verify_gnn.py` | _verify_gnn_shipped_rerun2.log | ✅ digit-identical (2026-06-14; acc .8668/RAW .8360/2hop .9563) |
| **A2 LGBM** | **RAW 0.0055 (P.068/R.003) / 2hop 0.986** | theia/_verify_lgbm.py | `python _verify_lgbm.py` | _verify_lgbm_rerun2.log | ✅ digit-identical (2026-06-14, from-raw featurize, needed 8GB free RAM) |
| A3/A4 content | PR-AUC 0.990/0.999 ; proc 1.0 (n=3) | theia/_eval_process_level.py | `python _eval_process_level.py` | _eval_process_level_rerun2.log | ✅ digit-identical (2026-06-14; NODE .9903/.9994, PROC 1.0000) |
| A5/A6/A7/A8 novelty | PR-AUC .542/.504/≈0 ; k=1 .982 | theia/_eval_novel.py, train_lgbm_novel.py | `python _eval_novel.py` ; `python train_lgbm_novel.py` | _eval_novel_rerun2.log, _train_lgbm_novel_rerun2.log | ✅ all digit-identical (2026-06-14; A5 .5421/.9668, A6 .5040/.9570, A7 ≈0, A8 k=1 .9819 seeds-fixed) |
| F.6 deblob/labels | 25,291 NetFlow / 23 proc / 5 file | theia/_probe_labels.py | `python _probe_labels.py` | (stdout) | ✅ digit-identical (2026-06-14; NetFlow 25,291 / Process 23 / File 5 / mal 25,319) |
| B1 content sup LOHO | PR-AUC .0035/.0167/.0040 | optc/train_content_supervised.py | `python train_content_supervised.py` | _train_content_supervised_rerun2.log | ✅ digit-identical (2026-06-14; all 3 folds NODE+PROC) |
| B2 TF-IDF | ROC .501/.550/.553 | optc/eval_content_tfidf_process.py | `python eval_content_tfidf_process.py` | _eval_content_tfidf_process_rerun2.log | ✅ digit-identical (2026-06-14; LOHO .501/.550/.553, within-host 0501 node .8777/proc .6341) |
| B3 novelty LOHO-clean | node .0136 / ROC .945 / 10.1× | optc/novelty_content_optc.py | `FEAT_MODE=loho python novelty_content_optc.py` (default "fixed"=transductive 168×, do NOT cite) | _novelty_content_optc_loho_rerun2.log | ✅ digit-identical (2026-06-14; 0501 .0136/.9452/10.1×, 0201 .8093) |
| **B4 GNN repro** | **0501 RAW 0.020 / 2hop 0.989** | optc/reproduce_flash_gnn.py (NOT underscore) | `python reproduce_flash_gnn.py` (arg-less, all 3 hosts, from raw _optc_gt) | _reproduce_flash_gnn_rerun2.log | ✅ all 3 hosts digit-identical from raw (2026-06-14; 0051 .011/.456, 0201 .006/.437, 0501 .020/.989; ~8.7GB RAM for 0501) |
| B4 GraphSAGE | RAW .011/.060/.015 | optc/train_gnn_supervised.py | `python train_gnn_supervised.py` | _train_gnn_supervised_rerun2.log | ✅ all folds digit-identical (2026-06-14; .0111/.0597/.0146 RAW, .8521/.8841/.9816 2hop; trained, seeds fixed) |
| **B5 process verdict** | **FLASH 24/99, 857 FP** | optc/eval_process_level.py | `python eval_process_level.py` (from raw, 3 models) | _eval_process_level_optc_rerun2.log | ✅ digit-identical (2026-06-14; FLASH 24/99, A 18/99, B 14/99; F1 .0440/.1111/.0489) |
| **C3 composition floor** | within-Process ρ 0.79–0.85 (v1 base 0.849) | theia/c3_composition_control.py | `python c3_composition_control.py` | _c3_composition_rerun2.log | ✅ ρ=0.849 digit-match (2026-06-14) |
| C3 budget sweep | containment ≥96% p90–p99 (viol 4/1/0/30) | theia/c3_budget_sweep.py | `python c3_budget_sweep.py` | _c3_budget_sweep_rerun2.log | ✅ all rows digit-identical (2026-06-14) |
| C3 multi-seed | ρ 0.790–0.849 (4 runs) | theia/c3_composition_control.py (ORTHRUS_WEIGHTS env) | `ORTHRUS_WEIGHTS=trained_weights/theia_orthrus_s{N} python c3_composition_control.py` | _c3_seed{1,2,3}_rerun2.log | ✅ all digit-identical (2026-06-14; s1 .792, s2 .808, s3 .790; +v1 base .849 = range .790–.849) |
| **PCSA pilot (§G GO)** | AUROC ~0.955 pilot | optc/pcsa_pilot.py | `python pcsa_pilot.py` | _pcsa_pilot_0501_rerun2.log | ✅ digit-identical (2026-06-14; mean-pool .955±.005, baseline .838, GATE=GO) |
| **PCSA cross (§H NO-GO)** | oracle×cross 0.545, detector×cross 0.594 | optc/pcsa_scorer.py | `python pcsa_scorer.py` | _pcsa_scorer_rerun2.log | ✅ digit-identical (2026-06-14; oracle×cross .545±.011, detector×cross .594, 0501 within .950→cross .545) |

## OpTC dependency chain (discover before B-cells)
The `.out` files imply an order: `_train_w2v` → `_featurize` → `_prepare_cache` → `_train_{selfsup,supervised}`
→ eval. Caches: `_feat_*.npz`. Confirm whether each B-cell regenerates or reuses caches (reuse = faster
but cache provenance must be checked, per results-frozen [R] caveat).

## Demo (Docker) — DONE this session ✅
§F.7 reproduced digit-for-digit: FLASH 1139 / Orthrus 300 / 6323 nodes, both scorers, 0 restarts.
Two bugs fixed + committed (d3ff4c6): pipeline Dockerfile dead COPY, scorer write deadlock.

## Unresolved / per-cell discovery TODO
- Exact command + cwd for every `TBD` cell (read script header/argparse before running).
- A1a/A1b: how the ours-vs-shipped weights are selected (flag? separate script?).
- Whether reruns should standardize w2v v2→v3 (md5-identical, so number-invariant) before or after diff.
