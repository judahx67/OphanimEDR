# LightGBM-XT BOTSv2 — Snapshot v1 (2026-04-30)

Frozen, known-good state of the BOTSv2 ML pipeline at the end of Phase 7c. Treat this directory as **read-only**. If you change anything in the live project and want to roll back, this is what you roll back to.

## What's frozen

```
snapshots/2026-04-30_lightgbm_v1/
├── README.md                    this file
├── code/                        all pipeline scripts at their working state
│   ├── schema.py                Layer 2 column contract (50 cols / 39 features / 26 categorical)
│   ├── convert_parquet.py       Phase 1: Splunk CSV → Parquet
│   ├── label.py                 Phase 3: IOC string-matching → label/scenario columns
│   ├── extract_features.py      Phase 4: parser dispatch, graph triple extraction
│   ├── downsample.py            Phase 5: streaming 3M sample + temporal/stratified splits
│   ├── train.py                 Phase 6: LightGBMXT trainer (with --drop-feature ablation flag)
│   ├── evaluate.py              Phase 7: ROC, PR, perm-importance, per-scenario plots
│   ├── phase0_sanity.py         original Phase 0 sanity-check
│   ├── _inspect.py              eyeball labeled rows
│   ├── _inspect_featured.py     eyeball featured rows
│   ├── _verify_fe.py            FE row-count sanity check
│   ├── _show_eval.py            print eval summaries from saved JSON
│   ├── _show_perm.py            side-by-side permutation importance across all models
│   ├── iocs.yaml                IOC corpus per scenario
│   ├── requirements.txt         python deps (polars, lightgbm, pandas, sklearn, matplotlib, psutil, pyyaml, tqdm, pyarrow)
│   └── phase0_summary.json      Phase 0 anchor numbers
├── docs/                        plan + log + handoff docs
│   ├── botsv2-rebuild-from-zero.md
│   ├── botsv2-pipeline-log.md
│   └── CONTEXT.md
├── models/                      all 6 trained models with full eval packs
│   ├── lgbm_xt_temporal/                with sourcetype, temporal split (HEADLINE)
│   ├── lgbm_xt_temporal_no_st/          no sourcetype, temporal split (HONEST)
│   ├── lgbm_xt_stratified/              with sourcetype, stratified split (UPPER BOUND)
│   ├── lgbm_xt_stratified_no_st/        no sourcetype, stratified split
│   ├── lgbm_xt_temporal_smoke50000/     50k smoke test (debugging only)
│   └── lgbm_xt_temporal_smoke50000_no_st/  50k ablation smoke (debugging only)
├── data/                        the 3M sampled splits
│   ├── all.parquet                      3M rows, 50-col schema
│   ├── temporal/{train,val,test}.parquet 60/20/20 chronological
│   ├── stratified/{train,val,test}.parquet 60/20/20 random label-stratified
│   └── split_summary.json
├── datasets/
│   └── botsv2_features/                 188.5M rows × 50 cols, 102 sourcetype partitions (481 MB)
└── logs/                                run history (label, FE, downsample, train, eval)
```

## What's NOT frozen here (and why)

| Path | Size | Why excluded | How to recover |
|---|---|---|---|
| `J:\THESIS-EDR\datasets\botsv2_parquet\` | 3.7 GB | upstream, hasn't changed since 2026-04-25 | re-run `code/convert_parquet.py` against the raw CSVs at `J:\THESIS-EDR\datasets\botsv2\` (~30 min) |
| `J:\THESIS-EDR\datasets\botsv2_labeled\` | 3.7 GB | reproducible from `botsv2_parquet/` + `iocs.yaml` | re-run `code/label.py` (12.8 min, deterministic — verified bit-for-bit reproducible by Phase 0) |
| `J:\THESIS-EDR\datasets\botsv2_labeled_v1_pre_rebuild\` | 3.7 GB | the pre-rebuild labeling output, kept for one-time backup | already preserved in live tree |
| Raw CSVs at `J:\THESIS-EDR\datasets\botsv2\` | 98 GB | original Splunk export, immutable input | n/a, just don't delete |
| `archive/` | — | AutoGluon experimental code, separate snapshot story | already in live tree under `server/ml-engine/botsv2/archive/` |

## Headline results frozen in this snapshot

```
                        Stratified              Temporal
                ROC-AUC  Recall   Precision   ROC-AUC  Recall   Precision
With sourcetype  0.9981   1.000    0.995      0.9877   0.886    0.980
No sourcetype    0.9689   0.999    0.861      0.9135   0.874    0.713
                  ────                          ────
                 stratified upper bound        honest temporal measure
```

- **Headline (with sourcetype):** ROC-AUC 0.9877 temporal / 0.9981 stratified, F1 0.93/0.997.
- **Honest (without sourcetype):** ROC-AUC 0.9135 temporal / 0.9689 stratified.
- **Permutation importance:** `sourcetype` accounts for 89-93% of model importance. Removing it surfaces `protocol` (65%) as the next-tier shortcut, but the model also begins using `bytes_in`, `event_id`, `command_line`, and the new graph-triple columns (`subject_type`, `object_type`, `edge_type`) meaningfully.
- **Beat the prior:** AutoGluon prior's no-sourcetype temporal was 0.879 / recall 0.709. This rebuild lifts to 0.9135 / 0.874 — +3.5pp ROC-AUC, +16pp recall.

See [docs/botsv2-pipeline-log.md](docs/botsv2-pipeline-log.md) "Rebuild" section for the chronological log of how each phase ran, what broke, and how it was fixed.

## How to reproduce from this snapshot

Sequence (assumes a fresh Python 3.13 venv with `pip install -r code/requirements.txt`):

```
# Phase 1: 98GB CSV → 3.7GB Parquet (skip if botsv2_parquet/ exists)
python code/convert_parquet.py

# Phase 3: re-derive labels (skip if botsv2_labeled/ exists)
python code/label.py
# Output goes to J:/THESIS-EDR/datasets/botsv2_labeled_v2/ — rename to botsv2_labeled/ on success

# Phase 4: feature engineering (use frozen output below — skip this step)
# python code/extract_features.py
# (copy datasets/botsv2_features/ from this snapshot if you want to skip the 72-min run)

# Phase 5: sample + split
python code/downsample.py

# Phase 6: train
python code/train.py --split temporal
python code/train.py --split stratified
python code/train.py --split temporal --drop-feature sourcetype --tag no_st
python code/train.py --split stratified --drop-feature sourcetype --tag no_st

# Phase 7: evaluate
python code/evaluate.py --all
python code/evaluate.py --model lgbm_xt_temporal_no_st
python code/evaluate.py --model lgbm_xt_stratified_no_st
```

Total cold-start wall time, top-to-bottom: ~3 hours (most of it Phase 1 + Phase 4).
With the frozen `datasets/botsv2_features/` reused: ~25 min (Phase 5 + 4× Phase 6 + 4× Phase 7).

## Caveats and known limitations

1. **The 72% positive rate** in the training split (we kept all 2.15M malicious + sampled 850k benign) means absolute metrics like precision should not be compared apples-to-apples against the AutoGluon prior's 1.14%-positive results. ROC-AUC is invariant; F1/precision/recall need framing.
2. **`pan_traffic` and `suricata` recall is 1-6%** on temporal regardless of model configuration — a real BOTSv2 data limitation (those rows' only signal is IPs, which are excluded as IOCs). No model trained on this data can recover them.
3. **`s400_taedonggang_apt` recall on temporal is ~60%** — the APT scenario lives heavily in the broken sourcetypes above. Stratified mixing hides this; chronological splitting reveals it.
4. **`WinHostMon` parser had a bug** (multi-line KV regex non-greedy with `$` anchor only matched the first character of unquoted values). Affects 2 malicious rows total — not worth re-running Phase 4 to fix.

## Don't modify this directory

If you want to iterate further: copy this snapshot to a new dated directory and edit there, or work in the live `server/ml-engine/botsv2/` tree (which still has all these files). This snapshot is the "everything works, here are the numbers" rollback point.
