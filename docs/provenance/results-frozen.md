# Results — Frozen Baseline (Sprint 0)

**Date frozen:** 2026-06-03 · **Branch:** `feature/comparative-study`
**Rule:** every cell traces to a log file on disk. No number enters the thesis that is not below.
All detection metrics are **RAW (no 2-hop)** unless the column says "2-hop".

> **Strength-of-evidence legend (read before trusting any cell).** Three distinct activities, NOT
> equivalent — do not call all of them "verified":
> - **[T] transcription-checked** — the report number matches the number printed in its log. This
>   confirms report↔log fidelity only; the experiment was **not** re-executed and a log can faithfully
>   record a methodologically wrong result. *Almost every cell below is [T].*
> - **[R] re-executed (cache-dependent)** — re-ran the inference on 2026-06-03, but **reused a
>   pre-existing feature cache** whose provenance is assumed from its filename, not validated. Only the
>   THEIA shipped GNN (A1b) is [R]. A full rebuild-from-raw is still outstanding (§D).
> - **[I] independently reproduced from raw** — none yet.
>
> 2-hop = neighborhood-forgiveness post-processing (a flagged node "covers" GT within 2 graph hops).
> It is shown only to quantify the inflation it produces; it is **not** a detection result.
>
> **F1 caveat:** every "F1" below for the FLASH GNN is computed at a **fixed, hardcoded operating point
> `CONF=0.53`** in the explain-away loop — it is RAW-at-CONF-0.53, not a threshold-free property. The
> FLASH explain-away emits a *binary* per-node verdict, so a native PR-AUC is not available without
> modifying the mechanism; the CONF sensitivity sweep (§F) is the appropriate substitute and shows how
> far the headline F1 moves with the threshold.

---

## A. THEIA E3 (DARPA TC, secondary node-level PoC)

Test graph: 344,768 nodes · GT malicious = 25,319–25,359 · processes = 12,937 (malicious-proc = 23).
GT is a ~99.7% netflow/file blob — node-level numbers are flow/file detection, NOT process detection.

| # | Method | Unit | Metric | RAW | 2-hop | Log |
|---|---|---|---|---|---|---|
| A1a | FLASH GNN (**ours**, `theia_ours`) **[T]** | node | F1 (P/R) @CONF0.53 | **0.768** (0.813/0.727) | 0.965 | `external/Flash-IDS/_verify_gnn.log` |
| A1b | FLASH GNN (**shipped**, `theia`) **[I]** | node | F1 (P/R) @CONF0.53 | **0.836** (0.722/0.993) ⚠️ threshold-sensitive, see §F.1 | 0.956 | `_verify_gnn_shipped.log` + rebuild-from-raw `_verify_gnn_shipped_rebuild.log` |
| A2 | FLASH LGBM (node-type booster) **[I]** | node | F1 | **0.0055** (P0.068/R0.003) | 0.986 | `external/Flash-IDS/_verify_lgbm.log` · re-run 2026-06-13 `server/ml-engine/theia/_verify_lgbm_rerun.log` (digit-identical, re-featurized from raw 1748s; boosters restored byte-exact from commit `a11bddd`, w2v md5-identical across v2/v3/external) |
| A3 | Supervised content (w2v30), temporal split | node | PR-AUC / ROC | **0.990 / 0.999** | — | `external/Flash-IDS/_eval_process_level.log` |
| A4 | Supervised content (w2v30), temporal split | process | PR-AUC | 1.000 ⚠️ **n=3 mal-proc**, R=0.333 (TP1/FP0/FN2) | — | same as A3 |
| A5 | Benign-only novelty, IsolationForest | node | PR-AUC / ROC | **0.542 / 0.967** | — | `external/Flash-IDS/_eval_novel.log` |
| A6 | Benign-1r novelty, LGBM-density | node | PR-AUC / ROC (lift 6.9×, base 0.073) | **0.504 / 0.957** | — | `external/Flash-IDS/_train_lgbm_novel.log` |
| A7 | Benign-only novelty | process | PR-AUC | **≈0** (0.0014–0.0019, ROC≤0.49) | — | `external/Flash-IDS/_eval_novel.log` |
| A8 | Few-shot supervised content (k-curve, **5 seeds**) | node | PR-AUC | k=1 **0.982±0.016** → k=all 0.990 | — | `external/Flash-IDS/_eval_novel.log` |

**THEIA reading:** honest node-level content detection is real (A3 0.99, A5/A6 ~0.95 ROC) but it detects
the **netflow/file blob**, not processes. Process-level is either statistically empty (A4, n=3) or ≈0 (A7).

⚠️ **Framing correction (surfaced by the §F.1 CONF sweep — do NOT repeat the old claim).** The earlier
line "GNN RAW 0.768/0.836 vs 2-hop 0.96 = the 2-hop trick" is **not safe for the THEIA GNN.** The sweep
shows that at a better operating point (CONF=0.30) the shipped GNN reaches RAW F1 **0.960 ≈ the 2-hop
0.956** — i.e. on THEIA the GNN's 2-hop "gain" is mostly a *bad-threshold artifact*, not neighborhood
inflation. THEIA node GT is a netflow blob and w2v+GNN genuinely separates netflow nodes, so RAW is
already strong. **The clean, defensible 2-hop-inflation cases are the node-type LGBM (A2, RAW 0.006 →
2-hop 0.986) and the OpTC GNN (B4, RAW 0.02 → 2-hop 0.99)** — where RAW is at chance regardless of
threshold. The thesis must make the inflation argument with A2/B4, not the THEIA GNN. (Caveat: the
*ours* weights, A1a, were not swept; do not assert ours is/ isn't threshold-recoverable without its own
sweep.)

---

## B. OpTC (DARPA, **primary** — process/incident unit)

99 malicious processes total across 3 hosts (0051=8, 0201=58, 0501=33). Base rates 0.06–1.7%.

### B1. Process-level go/no-go — supervised content, LOHO (cross-host)
| fold | unit | PR-AUC | base | ROC | lift | Log |
|---|---|---|---|---|---|---|
| 0051 | process | 0.0035 | 0.0044 | 0.274 | 0.8× | `server/ml-engine/optc/_train_content_supervised.log` |
| 0201 | process | 0.0167 | 0.0173 | 0.481 | 1.0× | same |
| 0501 | process | 0.0040 | 0.0045 | 0.420 | 0.9× | same |
| 0501 | node | 0.0061 | 0.0014 | 0.742 | 4.6× | same |

### B2. Confounder: TF-IDF content (8k feats), process-level
| regime | host | ROC | PR-AUC | lift | Log |
|---|---|---|---|---|---|
| LOHO (cross-host) | 0051/0201/0501 | 0.501 / 0.550 / 0.553 | ≈base | ~1.0–1.1× | `server/ml-engine/optc/_eval_content_tfidf_process.log` |
| within-host 70/30 | 0201 | 0.690 | 0.027 | 1.7× | same |
| within-host 70/30 | 0501 | 0.634 (node 0.878) | 0.067 | 13.5× (node 33×) | same |

### B3. Benign novelty (LOHO) — ⚠️ headline SUPERSEDED by the LOHO-clean w2v re-run (F.5)
| host | unit | w2v scope | PR-AUC | ROC | lift | Log |
|---|---|---|---|---|---|---|
| 0501 | node | all-hosts (transductive — vocab saw 0501 incl. attack tokens) | 0.227 | 0.958 | 168.6× ❌ do not cite | `server/ml-engine/optc/_novelty_content_optc.log` |
| 0501 | **node** | **train-hosts-only (honest)** | **0.0136** | **0.945** | **10.1×** | `server/ml-engine/optc/_novelty_content_optc_loho_w2v.log` |
| 0051/0201/0501 | process | either | ≤0.018 | ≤0.70 (≈chance) | — | same |

### B4. Topology GraphSAGE (LOHO), and FLASH GNN repro — RAW vs 2-hop
| method | host | RAW F1 | 2-hop F1 | Log |
|---|---|---|---|---|
| Supervised GraphSAGE | 0051/0201/0501 | 0.011 / 0.060 / 0.015 | 0.852 / 0.884 / 0.982 | `server/ml-engine/optc/_train_gnn_supervised.log` |
| FLASH GNN (shipped) **[I]** | 0501 | 0.020 | 0.989 | `server/ml-engine/optc/_reproduce_flash_gnn.log` · re-run 2026-06-13 all 3 hosts metric-line-identical (only wall-clock differs; original preserved as `.log.orig`) |

### B5. Process-level global verdict (3-host, RAW)
| model | recalled | FPs | Log |
|---|---|---|---|
| FLASH (shipped) | 24/99 (24.2%) | 857 | `server/ml-engine/optc/_eval_process_level_optc.log` |
| Model A (self-sup) | 18/99 (18.2%) | 242 | same |
| Model B (sup LOHO) | 14/99 (14.1%) | 334 | same |

**OpTC verdict (locked NO-GO, robust):** cross-scenario process detection ≈ chance across w2v-content,
TF-IDF-content, and topology-GNN. Within-scenario node-level flow signal survives the clean-vocab
re-run only in attenuated form (B3 0501 node: lift 10.1×, ROC 0.945 — the 168×/PR-AUC 0.227 was a
transductive-vocabulary artifact, see F.5).
RAW→2-hop (B4) shows the published-F1 inflation mechanism directly (0501 0.02→0.99).

---

## C. Discrepancies found during freeze (Sprint 0 corrections)

1. **RESOLVED 2026-06-03 — `0.836` shipped-weights THEIA GNN re-run, log produced.**
   On freeze, the only `_verify_gnn.log` showed **0.768** (our `theia_ours` weights). The `_verify_gnn.py`
   script had been deleted; it was recovered from commit `bd28c4a`, restored to
   `server/ml-engine/theia/_verify_gnn.py` (with a one-line env-configurable cache edit), and re-run
   against shipped weights (`trained_weights/theia`) + the existing `_verify_gnn_feats.flash.pkl` cache.
   Result reproduced: **RAW F1 0.836** (P 0.722 / R 0.993), 2-hop 0.956 → `_verify_gnn_shipped.log`.
   **Honesty note for the thesis:** shipped beats ours on RAW F1 *only via recall* (0.993 vs 0.727) at
   lower precision (0.722 vs 0.813); our weights are *better* at the trained node-type task (shard-0 acc
   0.938 vs 0.867). Report both; do not cherry-pick 0.836 without the precision/recall context.
   ⚠️ **Scoped by F.1b (2026-06-11):** the precision statement holds only @CONF 0.53 — at CONF 0.30
   shipped has both higher P and F1. The threshold-free survivors are node-type accuracy and ours'
   operating-point robustness (F1 spread 0.02 vs 0.29). See F.1b before citing this note.

2. **Plan "Verified Inventory" paths were wrong** (corrected here):
   - THEIA GNN weights/scripts/logs live in `external/Flash-IDS/`, **not** `server/ml-engine/theia/`.
   - Weights dir is `external/Flash-IDS/trained_weights/theia_ours` (singular — 20 GNN shards +
     `word2vec_theia_E3.model`), **not** `theia_ours_v2`/`theia_ours_v3`.
   - `server/ml-engine/theia/trained_weights/` contains only `theia_novel` (the novelty LGBM).

3. **THEIA process-level PR-AUC 1.0 (A4) is statistically empty** — only 3 malicious processes in the
   test split, recall 0.333. Freeze it WITH the n=3 caveat; never cite the 1.0 unqualified.

## D. Outstanding for Sprint 0 close (require user approval / action)
- [ ] Commit untracked scripts + reports + logs, incl. restored `_verify_gnn.py` + `_verify_gnn_shipped.log` (user must approve the commit).
- [x] ~~Resolve discrepancy #1~~ — DONE 2026-06-03: shipped re-run reproduced RAW F1 0.836 (see §C.1).
- [x] ~~EagleEye [6] citation~~ — RESOLVED 2026-06-11: dropped (pruning paper, mis-citation; no
  chapter cites it; key retired without renumbering).

## E. Bonus already satisfied
- A8 carries **5-seed CIs** (k=1 0.982±0.016) — partially satisfies the Sprint 2 "≥3 seeds + CIs" rule
  for the THEIA few-shot curve.

## F. Operating-point sensitivity + cache-provenance validation (post-critique, 2026-06-03) — DONE
Addresses self-critique C3 (F1 is RAW-at-a-fixed-threshold) and C2 (cache provenance assumed).

**F.1 CONF sweep — shipped weights, RAW (no 2-hop)** · `external/Flash-IDS/_verify_gnn_conf_sweep.log`
Recall is ~constant (~0.99); precision (hence F1) moves entirely with the operating point:

| CONF | flagged | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|---|
| 0.30 | 26,875 | 25,070 | 1,805 | 289 | 0.9328 | 0.9886 | **0.9599** |
| 0.40 | 29,664 | 25,113 | 4,551 | 246 | 0.8466 | 0.9903 | 0.9128 |
| 0.53 | 34,885 | 25,182 | 9,703 | 177 | 0.7219 | 0.9930 | **0.8360** (headline) |
| 0.60 | 39,707 | 25,289 | 14,418 | 70 | 0.6369 | 0.9972 | 0.7773 |
| 0.70 | 49,895 | 25,297 | 24,598 | 62 | 0.5070 | 0.9976 | 0.6723 |

**Findings:** (1) The 0.836 headline is **not operating-point-robust** — RAW F1 ranges **0.67–0.96**
over a plausible CONF range, and CONF=0.53 is *not* even F1-optimal. A single-number RAW-F1 headline is
therefore indefensible; report the P/R behavior (recall pinned ~0.99, precision the free variable) or a
threshold-free summary, and disclose that no principled threshold-selection rule was used (picking
CONF=0.30 would be oracle tuning on test). (2) At CONF=0.30 RAW F1 (0.960) ≈ 2-hop F1 (0.956), which
**undercuts the 2-hop-inflation narrative for the THEIA GNN** (see the §A framing correction).

**F.1b CONF sweep — OUR weights (`theia_ours_v3`), RAW (no 2-hop)** ·
`server/ml-engine/theia/_verify_gnn_conf_sweep_ours.log` (committed; also at
`external/Flash-IDS/`) (2026-06-11, reviewer R7) — DONE.

| CONF | flagged | TP | FP | FN | P | R | F1 |
|---|---|---|---|---|---|---|---|
| 0.30 | 20,996 | 18,079 | 2,917 | 7,280 | 0.8611 | 0.7129 | 0.7800 |
| 0.40 | 21,649 | 18,219 | 3,430 | 7,140 | 0.8416 | 0.7184 | 0.7751 |
| 0.53 | 22,684 | 18,443 | 4,241 | 6,916 | 0.8130 | 0.7273 | **0.7678** (= A1a exactly ⇒ run validated) |
| 0.60 | 23,348 | 18,475 | 4,873 | 6,884 | 0.7913 | 0.7285 | 0.7586 |
| 0.70 | 25,709 | 19,783 | 5,926 | 5,576 | 0.7695 | 0.7801 | 0.7748 |

**Findings:** (1) **Ours is operating-point-ROBUST where shipped is elastic** — F1 range 0.759–0.780
(spread 0.02) vs shipped 0.672–0.960 (spread 0.29) over the identical CONF grid; the shipped
"advantage" exists only via threshold elasticity on the GT-blob recall (its recall is pinned ~0.99
everywhere; ours is 0.71–0.78). (2) The §C.1 "ours more precise" framing is **operating-point-scoped**:
at CONF 0.30 shipped has BOTH higher precision (0.933 vs 0.861) and F1 (0.960 vs 0.780) — across the
sweep shipped Pareto-dominates on F1. What survives threshold-free: ours' node-type accuracy
(0.938 vs 0.867, the trained task) and ours' threshold robustness. §3.4 narrative updated accordingly
(2026-06-11); never cite "ours more precise" without "@CONF 0.53".
⚠️ **Weights-provenance trap found during this run:**
`external/Flash-IDS/trained_weights/theia_ours` is a **stale pre-v3** weight set (May 25; GNN shard
hashes differ from `server/ml-engine/theia/trained_weights/theia_ours_v3`, w2v identical). A first
sweep against it gave @0.53 F1 0.751 / P 0.610 / R 0.978 — *not* A1a (0.768/0.813/0.727, shard-0
acc 0.9377 = v3). A1a's weights are **theia_ours_v3**; do not use the external `theia_ours` dir.

**F.2 Rebuild-from-raw validation — shipped weights, fresh cache** · `_verify_gnn_shipped_rebuild.log`
Re-featurized from the raw 6r.8 graph (2514 s, NOT the `.flash.pkl`), shipped w2v, CONF=0.53:
RAW F1 **0.8360** (TP 25,182 / FP 9,703 / FN 177), node-type acc 0.8668, 2-hop 0.956 — **identical**
to the cached run. → The `.flash.pkl` cache is faithful (not mislabeled); **A1b upgraded [R] → [I]**
(independently reproduced from raw, end-to-end). Determinism (CPU w2v + GCN forward) makes the exact
match expected, not coincidental. Confirmation-bias concern (C2) substantially closed.

**F.3 Label-agnostic temporal-cut sensitivity (2026-06-10) — A3 robust, A4 superseded** ·
`server/ml-engine/theia/_eval_process_level_agnostic_cut.log` · split-integrity audit
`../reports/audit-260610-0132-dataset-split-integrity.md`. The A3/A4 temporal cut was
label-informed (median of malicious first-seen ts). Re-run with CUT_MODE=agnostic (median of ALL
ts): NODE content PR-AUC **0.9929** / ROC 0.9992 (≈ unchanged ⇒ A3 robust to the cut rule);
PROCESS-level now has all 23 GT processes in the test half: PR-AUC **0.0489**, R 0.043 (TP1/FN22).
**Use the agnostic-cut numbers as the A3/A4 headline** — A4's old n=3 / PR-AUC 1.0 cell is
superseded by a statistically meaningful process-floor measurement (n=23, ≈0.05).
⚠️ OpTC scope note (same audit): the OpTC w2v is trained on all 3 hosts (FLASH-faithful,
transductive w.r.t. LOHO) — conservative for the negatives. ~~B3's 168× lift carries the
disclosure until the train-hosts-only re-run lands~~ → the re-run landed (F.5): the 168× was a
transductive-vocabulary artifact; honest lift is 10.1×. A5 (IF_benign) is transductive
(label-selected benign of the eval graph); prefer A6 as the clean novelty cell.

**F.5 OpTC LOHO-clean w2v re-run (2026-06-11) — B3's 168× headline RETIRED** ·
`server/ml-engine/optc/_novelty_content_optc_loho_w2v.log` · per-fold w2v trained on the two
TRAIN hosts only (`train_word2vec.py W2V_HOSTS/W2V_OUT`, models `w2v_optc_loho{0051,0201,0501}`),
all hosts re-featurized per fold (`_feat_*_loho*.npz`), novelty re-run with `FEAT_MODE=loho`.
Result on the one positive cell (0501 node): PR-AUC **0.227 → 0.0136**, lift **168.6× → 10.1×**,
ROC 0.958 → 0.945, R@100fp 0.095 → 0.000. Reading: ROC (average ranking) is robust, but the
top-of-ranking precision was carried by the transductive vocabulary — which had seen 0501's
tokens *including the attack day's* — i.e. test-information leakage through featurization, the
exact mechanism audit O2 flagged. The honest claim is now "an order-of-magnitude lift (10×) with
strong ROC but precision too low for alerting." Negative folds unchanged (0051 1.4×, 0201 2.5×
node; process ≈ chance everywhere). The thesis's Ch2/Ch5/claims citations of 168× all corrected
to the clean numbers with the artifact disclosed.

**F.4 C3 multi-seed variance + flag-budget sweep (2026-06-11) — single-run caveat RETIRED** ·
3-seed retrain logs `server/ml-engine/theia/_orthrus_seed{1,2,3}_{train,c3}.log`; budget sweep
`_c3_budget_sweep.log` (script `c3_budget_sweep.py`); synthesis tables in
`../reports/control-260609-0146-orthrus-composition-floor-c3.md`. Headlines: within-Process
ρ = **0.790–0.849** (mean 0.81, 4 runs — cite the range, never "0.85 single run"); Process
containment ≥96% at matched budgets p90–p99 (violations 4/1/0), strict in 3/4 seeds at p99;
floor coarseness limit disclosed (p99.5: floor flags 0 processes, detector 30 — tie-truncation
artifact, ρ unchanged); socket flood replicates every seed (43–60%) with seed-unstable flag
volume 315–660 and threshold 5.86–7.51 = Bilot SC5 reproduced first-hand; the floor is
deterministic (identical 93 flags every run).

**F.6 Load-bearing 2-hop cells independently reproduced + harness audited (2026-06-13)**
Closes the [T]-only gap on the thesis's two headline inflation cells. (1) **A2 → [I]:** full re-run
from raw (re-featurized 344,768 nodes, 1748 s; boosters restored byte-exact from commit `a11bddd`
after they were found missing from the working tree; w2v md5-identical across theia_ours_v2/v3/
external) → every TP/FP/FN digit identical to the frozen log. (2) **B4 → [I]:** full 3-host re-run,
all metric lines identical (only timings differ). (3) **Harness audit:** our `get_adjacent` +
2-hop adjustment (`FPL = FP − two_hop_gp; TPL = TP ∪ (FN ∩ two_hop_tp)`) is semantically verbatim
FLASH's own `Get_Adjacent`/`helper` in `OpTC.ipynb`/`Theia.ipynb`/`Cadets.ipynb`; the explain-away
loop and CONF=0.53 are FLASH's own. One benign deviation: FLASH normalizes conf as `(c−min)/max`,
ours `(c−min)/(max−min)` — both map min→0 and are monotone, so the flagged set at the headline
`conf>0.0` is provably identical; the logged 0.0→0.98 sweep shows threshold-insensitivity besides.
(4) **GT-blob re-probed from raw** (`_probe_labels.py`): 25,291/25,319 NetFlow, 23 SUBJECT_PROCESS,
5 FILE — the "~99.7% blob" wording is conservative (99.89%). (5) **Head-to-head (767/14) is a
snapshot, not reconstructable:** live graph (2026-06-13) holds 5,819 scored nodes from later
same-day replays; scorers overwrite `scored_at` (last-write-wins) so the 1,410-node cohort is gone.
Current state **replicates the claim at larger N**: FLASH 1,022 seeds / **0 of 160 Process** (995
File flood) vs Orthrus 125 seeds / **29 Process**. Cite the doc numbers as "20k-replay snapshot,
see build doc" or re-snapshot after a user-approved clean wipe+replay; do not present 767/14 as
the current graph state.

**F.7 Faithful `/compare` re-snapshot — write-back gap closed (2026-06-14)** · screenshot
`plans/260602-1410-pcsa-thesis-reframe/visuals/compare-260614-120k-faithful.png`; report
`../reports/snapshot-260614-0145-faithful-compare-writeback.md`. **Both live scorers had a
label-guessing write bug:** seeds were persisted via `MATCH (n:\`{guessed_label}\` {uuid})` where the
label was guessed from the CDM type of the edge; when the guess disagreed with graph-builder's label
the SET silently no-op'd. Fix (`theia-{gnn,orthrus}-scorer/main.py`): write the scored batch against
each label's existing uuid-uniqueness index (a uuid matches under exactly one), no guessing. After a
**user-approved clean wipe + single 120k replay** (`ta1-theia-e3-official-6r.json.8`, deterministic
score), persisted DB counts now **equal the scorers' own logs**: 6,323 nodes, FLASH **1,139** seeds,
Orthrus **300** seeds. ⇒ the F.6(5) "125 Orthrus / 1,022 FLASH" figures were themselves write-back
artifacts (Orthrus undercounted 58%, mostly Sockets 15→79 and File 80→191); Process was always
faithful (matched 100%). **Faithful per-tier contrast:** Process FLASH **0/160** vs Orthrus **29/160**;
Socket FLASH 0/199 vs Orthrus **79/199 = 40%**; File FLASH 1,112/2,184 (51%) vs Orthrus 191/2,184 (9%);
Memory FLASH 27/3,780 vs Orthrus 1. **Framing:** the faithful Socket rate (40%) is a *flood*, not
"precise" — it corroborates the F.4 composition-floor flood (43% standard split), it does not restore
a precision headline. Only the Process tier (0 vs 29) + the descriptive "different objectives
distribute alerts differently" survive. Live counts are now reproducible (single-cohort wiped graph),
but `scored_at` is still last-write-wins, so cite as "120k clean-replay snapshot, 2026-06-14"; the
citable rigor still lives in F.4 (offline held-out C3), platform stays an architecture claim.

**F.8 20k live pipeline characterization — separate window, not current graph state (2026-06-17)** ·
report `plans/reports/benchmark-260617-2243-e2e-pipeline-theia.md`. After the platform was narrowed to
the THEIA-only demo and both live scorers used periodic re-scoring, a clean 20k-edge run of
`ta1-theia-e3-official-6r.json.8` produced a final graph of **1,410 nodes / 20,000 edges** with
File 875, Memory 469, Process 59, Socket **7**. The systems numbers for this specific window are:
replay **32.8 s**, graph-builder **20,000/20,000** edges persisted, graph-builder throughput
**250--300 edges/s**, **600** conflict requeues resolved, L1 **17** firings merged into **3** Incident
nodes, FLASH **767** seeds in **13.3 s**, Orthrus-style **14** seeds in **11.9 s**. Framing: these
figures are valid as an **n=1 live pipeline characterization** and as a window-specific contrast
between scorers. They do **not** supersede F.7's 120k faithful `/compare` snapshot
(FLASH **1,139** / Orthrus **300**) and must not be cited as the current graph state or as a
detection precision/recall result. The likely reason the 20k Orthrus count is much smaller is the
window composition: only **7 Socket** nodes, whereas the 120k snapshot has **199 Socket** nodes and
exposes the Orthrus-style Socket flood.

## G. Sprint 1 — PCSA pilot gate (2026-06-04) — **GO** [I] · ⚠️ SUPERSEDED by §H (the GO did not generalize)
Report `../reports/report-260604-0010-pcsa-pilot-gate.md` · script `server/ml-engine/optc/pcsa_pilot.py`
· log `server/ml-engine/optc/_pcsa_pilot_0501.log` (19 s, CPU). Host OpTC 0501, frozen self-sup FLASH
GraphSAGE, oracle GT seeds (410) + type-matched benign seeds (410), k=2 capped causal assembly.

| representation | silhouette | open-set AUROC (3 splits) |
|---|---|---|
| mean-pool embedding | **+0.347** | **0.955 ± 0.005** |
| anomaly-weighted pool | +0.344 | 0.954 ± 0.003 |
| node-type-hist baseline (control) | +0.315 | 0.838 ± 0.013 |

Gate (silh>0.2 AND AUROC>0.7) cleared ⇒ **GO**. Two non-negotiable caveats carried into S2:
(G.1) **Composition floor** — the node-type-ratio guard fired; a trivial 4-d type-histogram already
scores AUROC 0.838, so the embedding's *marginal* lift is **+0.117 AUROC / +0.032 silhouette** (real,
since embedding > control, but modest). Every S2 PCSA number reports the composition baseline as its
honest floor; the claim is the *lift over composition*, never the raw 0.955.
(G.2) **Oracle-seed ceiling** — seeds are GT nodes; the live pipeline seeds from the noisy novelty
detector (0501 node PR-AUC 0.227), so the operating AUROC will be lower. Re-measure with detector seeds
first in S2. Also: anomaly-pool adds nothing (0.954 vs 0.955) ⇒ **mean-pool only** for the MVP (KISS).

## H. Sprint 2 — full matrix (2026-06-04) — **effective NO-GO for learned PCSA** [I]
Report `../reports/report-260604-0050-pcsa-s2-matrix.md` · `server/ml-engine/optc/pcsa_scorer.py` +
`pcsa_common.py` · log `_pcsa_scorer.log` (44 s). The §G GO was the one favourable cell.

**H.1 Decomposition (test 0501)** [emb | type-hist floor]: oracle×within 0.950|0.846 ·
oracle×cross **0.545**|0.353 · detector×cross **0.594**|0.380 (detector prec 0.276). → within→cross
collapses to chance; noisy seeds keep it at chance.
**H.2 Host matrix (within | cross):** 0051 0.526|0.426 · 0201 0.549|0.633 · 0501 **0.950**|0.545.
Only 0501 separates; 0051/0201 ≈ chance even within-host ⇒ the pilot's 0.95 is **host-specific**.
**H.3 Ablations (0501 oracle×within):** PCSA k-means 0.953 · raw-kNN **0.973** · node-only (no
assembly) 0.589. → **assembly does all the work; the learned k-means-prototype step is net-negative**
and (per H.1/H.2) does not transfer.
**H.4 Reconstruction (0501, GT seed):** assembled subgraph 0.222 GT-dense (mean 13.4 GT nodes/subgraph)
⇒ seeding on a TP recovers a GT-rich region — supports *triage/assistant* framing, not detection.

**Verdict:** follow the plan's pre-committed NO-GO branch (no goalpost-moving). **S3 → heuristic
(ActMiner-style) causal assembly + deployed platform; drop the learned prototype model.** The model
contribution becomes a *measured limit / honest negative*: causal assembly from a TP seed recovers
GT-rich subgraphs (H.4), but learned subgraph→prototype alignment is host-specific (H.2), mostly
compositional (H.1 floor), dead cross-scenario (H.1), and not better than kNN (H.3). This reproduces the
thesis's honest-negative throughline at the ALIGNMENT layer. No TTP labels in optc.txt ⇒ closed-set
attribution untestable (not attempted). **Decision flagged for student** (rescue via contrastive
fine-tune vs accept fallback — see report §Unresolved).
