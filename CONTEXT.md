# BOTSv2 Manual Rebuild — Context Handoff

The experimental phase (AutoGluon, 4 trained models, 2 ablations) is complete. This document is the handoff for building the production model **manually**, picking only what worked and discarding the AutoGluon scaffolding.

For full experimental details see [`archive/INDEX.md`](archive/INDEX.md) and `J:\THESIS-EDR\docs\plans\botsv2-*.md`.

---

## Selected model

**Primary: LightGBMXT** — `lightgbm.LGBMClassifier` with `extra_trees=True` and `boosting_type='gbdt'`.

In the experiments, LightGBMXT consistently:
- Was the strongest *single* base model in the temporal-split ensemble (val ROC-AUC 0.9897, vs 0.9903 for the full 6-model weighted ensemble — within 0.06 pp of the ensemble for ~10× lower fit cost)
- Got the biggest non-RF/XT weight in the stratified ensemble (0.067)
- Fit in ~7 seconds on 500k × 35 features

**Parallel exploration: vanilla LightGBM** (no extra_trees). Slightly weaker on temporal val (0.9887 vs 0.9897) but trains in ~4 seconds and is structurally simpler. Worth comparing if `extra_trees` doesn't justify its complexity in the rebuild.

Both share the same library, same data pipeline, same evaluation. Cheap A/B.

### Hyperparameters that worked (from AutoGluon's `medium_quality` defaults)

```python
import lightgbm as lgb

# LightGBMXT
clf = lgb.LGBMClassifier(
    extra_trees=True,
    boosting_type="gbdt",
    objective="binary",
    metric="auc",
    n_estimators=10_000,        # AutoGluon caps via early stopping
    learning_rate=0.05,
    num_leaves=31,
    feature_fraction=1.0,       # AutoGluon's default in this preset
    min_data_in_leaf=20,
    n_jobs=6,                   # leave 2 cores for OS / VS Code
    random_state=42,
    verbose=-1,
)

# Train with early stopping on val ROC-AUC
clf.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    eval_metric="auc",
    callbacks=[lgb.early_stopping(stopping_rounds=200)],
    categorical_feature=cat_cols,  # critical — see "data prep" below
)
```

The `extra_trees=True` flag is what makes it "LightGBMXT" — it picks split thresholds randomly rather than greedy-best, which adds variance and reduces overfit. Without it, you get vanilla LightGBM.

**Skip these explicitly:**
- `LightGBMLarge` (val 0.9874, fit time 8s) — `learning_rate=0.03, num_leaves=128, min_data_in_leaf=3`. Slightly worse than XT and trains slower per round. AutoGluon kept it for ensemble diversity; for a single-model rebuild it's strictly dominated.
- The full WeightedEnsemble_L2 — adds 6 base models for a 0.6 pp val ROC-AUC lift. Not worth the maintenance/inference cost in a single-model rebuild.

---

## Data prep that worked

These are the non-obvious decisions from the experiment that you should carry forward verbatim:

### Drop leaky columns
```python
LEAKY_COLS = ["_time", "source", "host", "scenario", "src_ip", "dest_ip"]
```
- `_time, source, host` — temporal/identity leaks
- `scenario` — direct label leak (null = benign, else = the answer)
- `src_ip, dest_ip` — direct IOCs (e.g. `45.77.65.211`)

The model is forbidden from these. The thesis story depends on this.

### Drop low-value columns
```python
LOW_VALUE_COLS = ["logon_id", "parent_image", "suricata_alert_signature"]
```
AutoGluon flagged these as near-unique categoricals (i.e. each value appears once or twice — no learnable signal). Drop them up front to save memory and avoid feature-generator confusion.

### Truncate string columns
```python
MAX_STR_LEN = 100  # chars
```
- URIs and command lines can be 1000+ chars. Categorical-encoding them blows up memory.
- Truncating to 100 chars saves ~3-5× peak RAM with negligible signal loss (the discriminating substrings are at the start).
- Apply uniformly to **both** train and test — same preprocessing function, no skew.

### Convert object → category (for LightGBM)
```python
for c in df.columns:
    if df[c].dtype == "object":
        df[c] = df[c].astype("category")
```
- Saves another 3-5× memory.
- LightGBM handles categorical natively if you pass `categorical_feature=cat_cols` to `.fit()`.
- This eliminates one-hot encoding, which would explode the feature count.

### Subsample sizes that fit on 14 GB RAM
- train: 500k rows
- val: 250k rows
- test: 250k rows

Going higher OOMs RandomForest in AutoGluon. LightGBM scales better, but if you're staying memory-conservative, these caps are safe and produced ROC-AUC 0.96 on temporal anyway.

### Re-do the feature engineering
The old `archive/code/extract_features.py` produced 38 typed columns. **You said this needs redoing**, so design notes only:

- Per-sourcetype parsers worked well: JSON (stream_*, suricata), XML (Sysmon), CLF (access_combined), position-CSV (pan_traffic). Generic KV regex was the weak link.
- The canonical column allowlist (38 cols) bounded the union schema and kept memory predictable. **Keep this discipline** even if you redesign the parsers.
- 9.3 non-null features per malicious row average — most rows have many nulls. That's fine for LightGBM (handles NaN natively).
- 7% of malicious events were in unparseable sourcetypes (`WinHostMon` and Perfmon variants). If your rebuild handles these, you may recover up to ~150k more positive examples.

---

## Splits to produce (from labeled Parquet)

The `J:\THESIS-EDR\datasets\botsv2_labeled\` directory is preserved. Labels are stable across FE iterations because they come from `_raw` content matching, not from extracted features.

Two splits, both reported in the thesis:

1. **Temporal** — sort by `_time`, slice 60/20/20 chronologically. Snap split boundaries to the next strictly-greater `_time` so single-second tied events don't straddle two splits.
2. **Stratified** — random 60/20/20 with sampling stratified by label, fixed seed.

Stratified is the upper-bound comparison anchor; temporal is the headline. Reporting both is what makes the generalization gap visible.

### Sampling strategy that worked
- Keep **all** malicious rows (~2.15 M; experimental yield)
- Sample benign rows proportionally by sourcetype (largest-remainder rounding to hit a 5 M total exactly)
- Memory-conservative: stream malicious rows to a `mal_buffer.parquet` via PyArrow `ParquetWriter`, then make a second streaming pass for benign sampling. Never holds the full 188 M-row dataset in memory.

See `archive/code/downsample.py` for the streaming pattern — that worked, copy it.

---

## Evaluation discipline (from Phase 7)

Per-row metrics aren't enough. Always produce:

1. **ROC + PR curves on the test set** (matplotlib; basic).
2. **Confusion matrix** at the default 0.5 threshold.
3. **Per-scenario recall** (group test rows by `scenario` column among the malicious-labeled rows). The bimodal failure mode — s200 96 %, s400 56 % — was invisible from the aggregate recall number.
4. **Per-sourcetype recall** (top 12 by malicious count). Reveals which sourcetypes the model can and can't classify.
5. **Permutation feature importance** — ranks the 35 features by ΔROC-AUC when shuffled. **But interpret with caution**: the dominant feature gets inflated importance when correlated features exist (sourcetype showed 0.32 in the original, but ablation A showed the model still hit 0.879 ROC-AUC without it). Always run an ablation if a single feature dominates.

`archive/code/evaluate.py` has all of this — copy the plotting functions.

---

## Headline experimental numbers (your rebuild's baseline to beat)

```
Temporal split (the realistic measure):
  ROC-AUC   0.9609
  recall    82.7 %
  precision 92.9 %
  F1        0.875
  MCC       0.848

Stratified split (upper bound):
  ROC-AUC   0.9915
  recall    93.7 %
  precision 98.7 %
```

If your manual LightGBMXT-only rebuild lands within ~0.5 pp of these on temporal, the WeightedEnsemble_L2 was overkill — you've simplified without losing power.

If it lands materially below (>1 pp), the ensemble was earning its keep and you'll need to revisit.

---

## Pitfalls that bit us (don't repeat)

1. **Polars CSV reader chokes on multi-line `_raw` with `""` quote escaping.** Use PyArrow `csv.read_csv` with `invalid_row_handler='skip'`. We lost ~5 hours debugging the first attempt.
2. **AutoGluon's leaderboard's `score_test` column is recomputed against whatever DataFrame you pass.** It is NOT the test-set score. Real test-set ROC-AUC comes from `predictor.evaluate(test_pd)`. (Reviewer caught this in our docs.)
3. **`Failed to import torch` warnings on Python 3.13 venv** — no CUDA wheel exists. We fell back to CPU-only training. AutoGluon NN models excluded entirely. Not relevant for LightGBMXT (no torch dependency).
4. **xgboost / lightgbm / catboost are not pulled by `pip install autogluon.tabular`** — install separately. `pip install lightgbm` is enough for the rebuild.
5. **`_meta` column from Splunk exporttool sometimes missing** on individual rows (5-field instead of 6-field CSV). PyArrow with `invalid_row_handler='skip'` handles this; Polars doesn't.
6. **IOC `1502408189` is a 10-digit string AND a valid epoch second.** Sanity-checked: only 2 of 1.7 M s200-labeled rows match it without also matching a more specific IOC. Not noise. But: any future IOC that's also a valid timestamp/counter/ID needs the same sanity check.
7. **`Tor Browser 7.0.4` IOC matched zero rows** (likely because `MAX_STR_LEN=100` truncates the user-agent before the version). Useless IOC, drop from `iocs.yaml` if you re-use it.

---

## Live files (what stays in this directory)

```
botsv2/
├── CONTEXT.md                  this file
├── INDEX.md                    (none — see archive/INDEX.md)
├── convert_parquet.py          Phase 1: 98 GB CSVs → 3.7 GB Parquet (KEEP, reusable)
├── iocs.yaml                   IOC corpus (KEEP, sanity-checked)
├── requirements.txt            Python deps
├── archive/                    experimental code, models, results
└── (future: your new FE + train scripts)
```

Datasets at `J:\THESIS-EDR\datasets\` are preserved:
- `botsv2/` — raw CSVs (98 GB)
- `botsv2_parquet/` — Phase 1 partitioned (3.7 GB)
- `botsv2_labeled/` — Phase 3 with `label` + `scenario` columns (3.7 GB)

`botsv2_features/` was deleted because feature engineering will be redone.

---

## Recommended rebuild sequence

1. Re-do feature engineering (your call on parsers — note the design hints in "Re-do the feature engineering" above)
2. Re-run `archive/code/downsample.py` (or its successor) against the new featured Parquet to produce 5 M-row temporal + stratified splits
3. Write a small `train.py` using the LightGBMXT hyperparameters above, with the leaky/low-value column drops and the data prep discipline
4. Re-use `archive/code/evaluate.py`'s plotting functions for ROC/PR/confusion/per-scenario/per-sourcetype/feature-importance
5. Compare temporal-test metrics against the baseline (0.9609 / 82.7 % / 92.9 %)
6. If close enough, proceed to graph-augmentation work

If the rebuild diverges materially from the baseline, the ablations in `archive/models/` are reference points for diagnosing why.
