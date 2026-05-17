# Defense Decisions Binder

Every significant design choice in the pipeline, with the number or measurement that justifies it.

---

## 1. Detection architecture

**[→ detection-paths.md](decisions/detection-paths.md)**

Two parallel detectors write `:Incident` nodes distinguished by `source` property:

| Source | Mechanism | What it catches |
|---|---|---|
| `rule-engine` | 36 Sigma-inspired YAML FSM rules | Known tactics (11 MITRE tactics enumerated) |
| `ml-llm` | LightGBMXT per-edge scorer + Gemini narrative | Statistical anomalies the rules don't enumerate |

**Why both?** Rules provide deterministic, auditable ground truth on known patterns.
ML generalises to novel variants. LLM narrates ML alerts since rule incidents already carry MITRE labels.

---

## 2. Ground-truth labels

**[→ labelling.md](decisions/labelling.md)**

IOC substring match on `_raw` (Aho-Corasick) within per-scenario time windows.

| Scenario | IOC type | Key IOC | Model learns |
|---|---|---|---|
| s200 webapp attack | attack_signature | `updatexml` (SQL injection) | HTTP URI content |
| s300 ransomware | file extension | `.crypt` | Object name suffix |
| s400 APT | C2 IP | `45.77.65.211` | Network flow identity |
| s100 insider | — | none | Not labeled (0 positives) |

**Leakage disclosure:** `scenario` column dropped at training. `dest_ip` / `subject_name` / `object_name` dropped because they can embed the C2 IP directly. `external_ip` (direction-independent) kept as a non-leaky approximation.

---

## 3. Feature schema (42 columns)

**[→ feature-schema.md](decisions/feature-schema.md)**

- **4** graph-triple columns (`sourcetype`, `subject_type`, `object_type`, `edge_type`)
- **13** numeric columns (ports, HTTP fields, byte counts, process IDs, Suricata severity)
- **25** categorical columns (network identity incl. `external_ip`, HTTP, DNS, process, registry, Suricata)

**11 columns excluded as leaky** — see feature-schema.md for full list and rationale.

Single source of truth: `server/ml-engine/botsv2/schema.py`.
Startup guard in `ml-edge-scorer/model_loader.py` catches schema drift at deploy time.

---

## 4. Model choice and training

**[→ model-choice.md](decisions/model-choice.md)**

**Deployed for alerting:** `lgbm_xt_temporal_no_st` ("honest" — no sourcetype).
Test precision **0.9977**, recall 0.187, F1 0.315. Only **23 false positives in 1M test events.**

**Retained for comparison:** `lgbm_xt_temporal` (headline — with sourcetype). AUC 0.9530, but precision only 0.608 and **7,024 false positives in 1M events**. The high AUC comes from `sourcetype` acting as a categorical prior on label distribution (e.g. `apache_error` has 94% positive rate), not from better detection — per-sourcetype recall is identical between the two models.

**Both scores written to Neo4j**; only the honest model triggers alerts.

**Model:** `LightGBMClassifier(extra_trees=True, boosting_type='gbdt')` — LightGBMXT.

**Why LightGBM over GNN/embedding approaches?**
- No graph convolution needed: per-edge features already encode the provenance context.
- Training on 5.2M rows (173K positive) completes in ~67s on a laptop CPU.
- Interpretable via permutation importance; no black-box graph embedding.
- Competitive AUC (0.9530 temporal) with zero infrastructure overhead.

**Hyperparameters:** `n_estimators=10000`, early stopping 200 rounds, `is_unbalance=True`, `learning_rate=0.05`, `num_leaves=31`. Selected by early-stopping convergence, not grid search.

**Four variants:**

| Model | Split | AUC | Purpose |
|---|---|---|---|
| `lgbm_xt_temporal` | Temporal 60/20/20 | **0.9530** | Production headline |
| `lgbm_xt_temporal_no_st` | Temporal | 0.5544 | Honest (no sourcetype) |
| `lgbm_xt_stratified` | Stratified | 0.9999 | Capability upper bound |
| `lgbm_xt_stratified_no_st` | Stratified | 0.9853 | Honest upper bound |

**Why temporal split?** Reflects real deployment: train on past, defend the future.
Stratified AUC (0.9999) is the oracle upper bound showing the model can learn the patterns — the temporal gap is domain shift, not model capacity.

---

## 5. Temporal domain shift (s400 APT recall)

**[→ s400-recall.md](decisions/s400-recall.md)**

| Split | s400 recall | s200 recall |
|---|---|---|
| Stratified | ~91.7% | ~95.1% |
| Temporal | ~0% | ~99.98% |

**Root cause:** s400 training window has 2 positive rows (pan_traffic with C2 as `dest_ip`); test window has 18,624 (C2 as `src_ip`, direction reversed during exfiltration phase).

**Defense framing:** The temporal gap IS the thesis finding — provenance-graph classifiers trained on the early attack phase fail to generalise to later phases when C2 direction flips. `external_ip` mitigates but doesn't eliminate this. Continuous retraining or online adaptation is the open research direction.

---

## 6. Alert threshold

**[→ threshold-choice.md](decisions/threshold-choice.md)**

| Model | Threshold | Val precision | Val recall | Derivation |
|---|---|---|---|---|
| Headline | **0.05** | 0.754 | 0.252 | F1-optimal on temporal val |
| Honest | **0.05** | — | — | F1-optimal |

**Why not 0.99 precision?** At t=0.90, val precision collapses to 2.9% (97% false positives) due to domain shift — high-scoring benign events cluster in the attack time window. 0.99 precision yields zero recall.

**Alert volume control:** Dedup cache in `llm-analyzer` (5-min TTL per `(subj, obj, edge_type)`) prevents LLM flooding. Only first occurrence triggers Gemini; subsequent are counted and suppressed.

---

## 7. LLM narrative generation

**Model:** Gemini 2.0 Flash (free tier, ~1500 req/day). Choice is provisional; the prompt format and Neo4j write contract are model-agnostic.

**Subgraph scope:** 1-hop (direct neighbours of the flagged edge). 2-hop reached 67 nodes / 266 edges in practice — exceeds LLM context efficiently and obscures the relevant signal.

**Output schema:** JSON with `attack_hypothesis`, `mitre_technique`, `mitre_tactic`, `evidence_summary`, `confidence`, `analyst_action`, `false_positive_risk`.

**Rate limiting:** `GEMINI_PACING_SECONDS=2.0` between calls; `MAX_NARRATIVES_PER_RUN=50` cap per service restart. Dedup prevents repeated calls for the same pattern.

---

## Quick-reference: every magic number

| Number | What | Where | Rationale |
|---|---|---|---|
| 36 | YAML detection rules | `rule-engine/rules/` | All known BOTSv2 tactic coverage |
| 14 | Edge types | `schema.py` EdgeType | Full provenance edge vocabulary |
| 9 | Node types | `schema.py` NodeType | Full provenance node vocabulary |
| 42 | Model features | `schema.py` ALL_FEATURED_COLS | Graph triple + content fields (see §3) |
| 5.2M | Training dataset size | `downsample.py` | ~30× positive class, RAM ≤ 10GB |
| 173K | Positive (malicious) rows | `label.py` output | IOC-matched BOTSv2 events |
| 0.9530 | Temporal ROC-AUC | `test_metrics.json` | Production headline metric |
| 0.05 | Alert threshold | `threshold.json` | F1-optimal on temporal val |
| 0.9999 | Stratified ROC-AUC | stratified eval | Capability upper bound |
| 300s | Dedup window | `llm-analyzer` env | 5-min TTL per alert pattern |
| 1-hop | Subgraph depth | `llm-analyzer` | Context manageable; 2-hop overflows LLM |
| 10K | LightGBM estimators | `train.py` | Early-stopped at 205 rounds |
| 200 | Early-stopping rounds | `train.py` | Standard for LightGBM stability |
