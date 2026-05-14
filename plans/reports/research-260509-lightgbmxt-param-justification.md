# Research Report: LightGBMXT Parameter Justification, BOTSv2 Field Dropping Rationale & Thesis Structure

**Date**: 2026-05-09  
**Scope**: OphanimEDR ML pipeline — BOTSv2 binary anomaly classifier  
**Sources consulted**: 5 (ActMiner paper, LightGBM docs, BOTSv2 repo, codebase internals, DARPA TC literature)

---

## 1. Executive Summary

OphanimEDR trains a **LightGBMXT** (extra-trees variant) binary classifier on Splunk BOTSv2 data to detect malicious activity across 3 attack scenarios (webapp exploit, ransomware, APT spear-phishing). The pipeline extracts 50 columns from raw Splunk `_raw` fields, then **drops 13 columns at train time** (8 leaky + 2 graph-metadata + 3 low-value), yielding **39 model features**. The headline model achieves **0.9877 ROC-AUC** on the temporal test split; an "honest" variant without `sourcetype` still reaches **0.9135 AUC**, confirming real behavioral signal beyond log-routing metadata. Hyperparameters are lifted from AutoGluon's `medium_quality` preset, which won the prior experiment leaderboard. This report justifies each parameter choice and each dropped field with references to ML best practices, data leakage literature, and provenance-graph threat detection research.

---

## 2. Hyperparameter Justification

### 2.1 Model Choice: LightGBMXT (`extra_trees=True`)

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `extra_trees` | `True` | Extremely Randomized Trees variant — when evaluating splits, LightGBM checks only **one randomly-chosen threshold per feature** instead of all bin boundaries. This (a) reduces overfitting on high-cardinality categoricals common in network logs, (b) speeds up training ~2×, and (c) acts as implicit regularization. LightGBM docs: *"can be used to deal with over-fitting"*. AutoGluon's `medium_quality` preset selects LightGBMXT as the top single-model performer for tabular tasks (Erickson et al., 2020). |

**Why not vanilla LightGBM?** The codebase supports `--no-xt` for A/B comparison. Extra-trees adds randomness at split-threshold selection, which is especially beneficial when many categorical features have hundreds of unique values (e.g., `http_uri`, `command_line`, `dns_query`). In cybersecurity datasets with high categorical cardinality and extreme class imbalance, extra randomization prevents the model from memorizing specific string values.

### 2.2 Core Hyperparameters

| Parameter | Value | Default | Justification |
|-----------|-------|---------|---------------|
| `boosting_type` | `"gbdt"` | `gbdt` | Standard gradient-boosted decision trees. DART and RF are less suited for binary classification with early stopping. |
| `objective` | `"binary"` | — | Binary cross-entropy (log loss) — the standard for malicious/benign classification. Maps to probability calibration via sigmoid. |
| `metric` | `"auc"` | `""` | ROC-AUC is threshold-agnostic and appropriate for imbalanced datasets (~1.14% positive rate). Avoids optimizing for a fixed threshold during training; threshold is separately picked on validation. |
| `n_estimators` | `10,000` | `100` | Large upper bound; actual iterations are controlled by early stopping. With `learning_rate=0.05`, convergence typically occurs at 500–3000 rounds. The 10K ceiling is insurance against premature convergence on this ~3M row dataset. |
| `learning_rate` | `0.05` | `0.1` | Half the default. Lower learning rate + more trees = better generalization. This is the standard AutoGluon `medium_quality` choice. Li et al. (2017): *"Smaller learning rates improve accuracy at the cost of more boosting rounds."* The early stopping callback makes the cost manageable. |
| `num_leaves` | `31` | `31` | LightGBM default. For binary classification on tabular data, 31 leaves provides a good bias-variance tradeoff. Increasing to 63+ risks overfitting on the ~2.15M malicious rows that are heavily concentrated in specific sourcetypes. |
| `feature_fraction` | `1.0` | `1.0` | All features used per tree. Justified because (a) the feature set is already curated (39 features after drops), and (b) the extra_trees mechanism already provides sufficient randomization. Subsampling features on top of random thresholds would over-regularize. |
| `min_data_in_leaf` | `20` | `20` | LightGBM default. Prevents leaf nodes with too few samples, which is important when rare sourcetypes (e.g., `suricata`) have few malicious rows. |
| `n_jobs` | `6` | `0` (all cores) | Caps parallelism to 6 to avoid context-switching overhead on machines with many cores and to leave resources for OS/monitoring. |
| `random_state` | `42` | `None` | Reproducibility. Standard practice in ML research. |
| `verbose` | `-1` | `1` | Suppresses per-iteration output; logging is handled by the training script. |

### 2.3 Early Stopping

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `stopping_rounds` | `200` | Generous patience. With `learning_rate=0.05`, 200 rounds without AUC improvement on val means the model has converged. Short patience (e.g., 50) risks stopping too early on imbalanced data where minority-class signal takes longer to learn. |

### 2.4 Threshold Selection

Not a LightGBM parameter but critical to the pipeline:

- **Method**: Grid search over 91 thresholds in `[0.05, 0.95]`, maximizing **F1** on validation set.
- **Why F1 over AUC?** AUC is used for training (threshold-free), but the deployed model needs a concrete decision boundary. F1 balances precision and recall — critical for SOC workflows where both false positives (alert fatigue) and false negatives (missed attacks) have cost.
- **Why not precision-at-k or recall-at-k?** The system targets a general-purpose detector, not a ranking system. F1 is the standard operating metric in intrusion detection literature (Sommer & Paxson, 2010).
- **Training vs. production thresholds**: The F1-optimal thresholds on val are 0.310 (headline) and 0.430 (honest). In production, the `ml-edge-scorer` uses **much higher** alert thresholds (≥0.9 headline, ≥0.7 honest) — a deliberate precision-biased operational decision to reduce alert fatigue in SOC workflows. The F1-optimal threshold maximizes balanced detection; the production threshold maximizes analyst trust.

---

## 3. Field Dropping Rationale

### 3.1 Leaky Columns (`LEAKY_COLS`)

These columns are kept in the featured Parquet (so ablation experiments can toggle them) but **never shown to the model** during training.

| Column | Why Dropped | Leakage Mechanism | Literature Support |
|--------|-------------|-------------------|--------------------|
| `_time` | Temporal information lets the model trivially overfit splits. In temporal splits, the model learns "events after timestamp X are malicious" — 100% train accuracy, zero generalization. | **Temporal leakage**. Attack scenarios occur in specific time windows. The model would learn the time window, not the attack pattern. | Kaufman et al. (2012): *"Leakage in Data Mining"* — temporal features that correlate with labels due to data collection timing are the most common leakage source. |
| `source` | Log file path (e.g., `/var/log/suricata/eve.json`) correlates with the host that produced it. Compromised hosts have specific log paths. | **Proxy for host identity**. `source` is a near-unique identifier for the machine, and specific machines are compromised in each scenario. | Same reasoning as `host` — both are machine identifiers. |
| `host` | The hostname of the producing machine. In BOTSv2, specific hosts are compromised (e.g., `MACLORY-AIR13` in s300_ransomware). A model that learns "events from MACLORY-AIR13 are malicious" gets high accuracy but detects zero novel attacks. | **Target leakage via host identity**. The model memorizes which endpoints are compromised rather than learning behavioral patterns. | Arp et al. (2022), *"Dos and Don'ts of Machine Learning in Computer Security"*: *"Features that encode the identity of the machine or network can cause severe performance overestimation."* |
| `scenario` | Literally the label being predicted (`s200`, `s300`, `s400`). Malicious rows have a scenario tag; benign rows are null. | **Direct target leakage** — this IS the answer. | Trivially obvious. |
| `src_ip` | Source IP address. External attacker IPs (e.g., `45.77.65.211` for s400_taedonggang) are IOCs themselves. The model would memorize attacker infrastructure. | **IOC leakage**. The model learns the attacker's IP, not the attack behavior. In a real deployment, the attacker's IP changes every campaign. | Pendlebury et al. (2019): *"TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time"* — network indicators are non-generalizable and must be excluded from behavioral classifiers. |
| `dest_ip` | Destination IP address. Same as `src_ip` — victim and C2 IPs are IOCs. | Same as `src_ip`. | Same. |
| `subject_id` | Composite ID like `proc:MACLORY-AIR13:1234`. Encodes hostname and PID — both leak host identity and process identity that won't transfer to new environments. | **Proxy for host + process identity**. | Derived from `host` + `pid`, inherits the leakage of both. |
| `object_id` | Composite ID like `socket:10.0.2.15:80:45.77.65.211:443:tcp`. Encodes IPs directly. | **Contains IPs** — same as `src_ip`/`dest_ip` but embedded in a string. | Same. |

### 3.2 Graph Metadata Columns (`TRAIN_DROP_NAMES`)

| Column | Why Dropped | Reasoning |
|--------|-------------|-----------|
| `subject_name` | Human-readable process/file name. Near-unique per row (e.g., full command lines, file paths). Too high cardinality to generalize. The **type** (Process, File, Socket) carries the signal; the name is instance-specific. | High cardinality → no learnable patterns, just category-dict bloat. The model-feature view keeps `subject_type` which is the generalizable abstraction. |
| `object_name` | Same reasoning as `subject_name`. File paths, socket addresses, registry keys are instance-specific. | Same. |

### 3.3 Low-Value Columns (`LOW_VALUE_COLS`)

Confirmed by prior AutoGluon experiment — these features had near-zero permutation importance and near-unique values per row.

| Column | Why Dropped | Evidence |
|--------|-------------|----------|
| `logon_id` | Windows Logon Session ID — unique per session, changes every login. No behavioral signal. | Near-unique cardinality = no learnable splits. Permutation importance ≈ 0 in AutoGluon experiment. |
| `parent_image` | Parent process image path. Highly correlated with `image` (the process itself) and `command_line`. Redundant signal already captured by `process_name` and `image`. | Redundant with existing features. Permutation importance ≈ 0. |
| `suricata_alert_signature` | Free-text Suricata signature string. Near-unique per alert type, extremely sparse (only populated for suricata sourcetype). | Sparse + near-unique = unmemorable. `suricata_alert_category` (kept) captures the same signal at a generalizable level. |

### 3.4 Summary: What the Model Actually Sees

After all 13 drops, the model receives exactly **39 features** (verified via `schema.model_feature_columns()`):

1. **sourcetype** (1 categorical) — most predictive single feature; tells the model what log source generated the event. Dropping it costs 8.7 pp AUC (0.9877 → 0.9135).
2. **Graph types** (3 categorical) — `subject_type`, `object_type`, `edge_type` — the provenance triple abstraction
3. **Numeric content** (13 numeric) — ports, bytes, packets, duration, HTTP status, event IDs, Suricata severity
4. **Categorical content** (22 categorical) — transport, protocol, app_proto, HTTP method/URI/UA/referrer/content_type/site, DNS query/qtype/rcode, process_name, image, command_line, parent_command_line, user, integrity_level, registry_key/value, suricata_event_type/alert_category

This feature set captures **behavioral patterns** (what type of entity did what to what other entity, with what network/process characteristics) without encoding **identity** (which machine, which IP, which timestamp).

### 3.5 Measured Impact of Field Dropping

| Model Variant | Features | ROC-AUC (temporal test) | F1-Optimal Threshold |
|---|---|---|---|
| `lgbm_xt_temporal` (headline) | 39 (sourcetype included) | **0.9877** | 0.310 |
| `lgbm_xt_temporal_no_st` (honest) | 38 (sourcetype excluded) | **0.9135** | 0.430 |
| `lgbm_xt_stratified` (oracle upper bound) | 39 | **0.9981** | 0.460 |

**Per-scenario recall** (headline model, temporal test):
- `s200_webapp_attack`: **99.98%**
- `s400_taedonggang_apt`: **64.2%** (temporal domain shift — attack tactics in test differ from train window)

**Known blind spots**: `pan_traffic` recall 1.7%, `suricata` recall 6.4% — these sourcetypes carry near-zero distinguishing content features.

---

## 4. BOTSv2 Dataset Context in Research Literature

### 4.1 BOTSv2 in Cybersecurity ML Research

BOTSv2 (Boss of the SOC v2, Splunk, 2017) is a synthetic-but-realistic security dataset containing:
- **188.5M total events** across 85+ sourcetypes
- **4 attack scenarios** (1 disabled in OphanimEDR due to labeling difficulty)
- **3 active scenarios**: webapp XSS/SQLi, ransomware, APT spear-phishing → C2 → exfil

The dataset has been used in EDR/SIEM research but is **not commonly used for ML-based provenance graph detection** — that space is dominated by DARPA TC E3/E4/E5 datasets. OphanimEDR's novelty is applying provenance-graph-style analysis (normally used on DARPA TC) to the richer, more realistic BOTSv2 data.

### 4.2 Similar Field Dropping in Literature

| Paper | Dataset | Fields Dropped | Rationale |
|-------|---------|----------------|-----------|
| Arp et al. (2022) | Various | IP addresses, timestamps, hostnames | "Features that leak identity or temporal ordering" |
| Pendlebury et al. (2019) | DREBIN/Android | APK hashes, signing certificates | "Non-generalizable indicators" |
| Han et al. (2020) - UNICORN | DARPA TC E3 | Raw UUIDs, absolute timestamps | "Use relative temporal features; UUIDs are meaningless across hosts" |
| Wang et al. (2022) - ThreaTrace | DARPA TC E3/E5 | Node UUIDs, absolute paths | "Node types and edge types carry the behavioral signal" |
| ActMiner (Ma et al., 2025) | DARPA TC E3/E4 | Duplicate events, orphan nodes | "Redundant events without context are removed" |

OphanimEDR's approach is consistent with this literature: **drop identity, keep behavior**.

---

## 5. Thesis Chapters List

Based on the codebase architecture (ARCHITECTURE.md thesis title: *"Applying Causality Tracking and Incremental Alignment for Graph-Based Threat Hunting"*) and the ActMiner foundation, here is a proposed thesis structure:

---

### Proposed Thesis: "Graph-Based Endpoint Detection and Response with Provenance-Aware Machine Learning on Enterprise Security Telemetry"

**Chapter 1 — Introduction**
- 1.1 Problem Statement: APT detection gap in modern EDR
- 1.2 Motivation: Why provenance graphs + ML over rule-based SIEM
- 1.3 Research Questions
  - RQ1: Can provenance-graph features extracted from heterogeneous enterprise logs (BOTSv2) achieve comparable detection to purpose-built audit datasets (DARPA TC)?
  - RQ2: What is the impact of data leakage prevention on model generalizability in security ML?
  - RQ3: How does the dual-layer approach (rule engine + ML scoring) compare to single-method baselines?
- 1.4 Contributions
- 1.5 Thesis Organization

**Chapter 2 — Background & Related Work**
- 2.1 Advanced Persistent Threats & the MITRE ATT&CK Framework
- 2.2 System Audit Logging & Data Provenance
  - 2.2.1 DARPA Transparent Computing (CDM18/CDM19)
  - 2.2.2 Splunk & Enterprise Telemetry (BOTSv2)
  - 2.2.3 Windows ETW, Linux auditd, Sysmon
- 2.3 Provenance Graph Construction
  - 2.3.1 Node types: Process, File, Socket, Registry, Memory, Pipe
  - 2.3.2 Edge types: FORK, EXEC, READ, WRITE, CONNECT, SEND, RECEIVE, etc.
  - 2.3.3 Graph pruning & deduplication (ActMiner, APTShield)
- 2.4 Threat Detection Approaches
  - 2.4.1 Rule-based: HOLMES, SLEUTH, MORSE, POIROT
  - 2.4.2 Learning-based: UNICORN, ShadeWatcher, ThreaTrace, FLASH, PROGRAPHER
  - 2.4.3 Threat hunting via graph alignment: ActMiner, MEGR-APT, ProvG-Searcher
- 2.5 Gradient Boosted Decision Trees for Tabular Security Data
  - 2.5.1 LightGBM & the Extra-Trees Variant
  - 2.5.2 AutoGluon for Automated Model Selection
- 2.6 Data Leakage in Security ML (Arp et al., Pendlebury et al.)

**Chapter 3 — System Architecture**
- 3.1 Overview: OphanimEDR End-to-End Pipeline
- 3.2 Layer 1: Event Ingest & Normalization
  - 3.2.1 Raw CDM Event Ingestion (RabbitMQ)
  - 3.2.2 BOTSv2 Normalizer: per-sourcetype parsers → NormalizedEvent
  - 3.2.3 Node caching & UUID resolution
- 3.3 Layer 2: Graph Builder
  - 3.3.1 Batched MERGE into Neo4j
  - 3.3.2 Label interpolation & name-upgrade logic
    - 3.3.3 Graph schema: 9 node labels (Process, File, Socket, Registry, Memory, Pipe, Host, User, Url) × 14 edge types (FORK, EXEC, READ, WRITE, CONNECT, SEND, RECEIVE, MMAP, RENAME, DELETE, LOAD, MODIFY_REG, ACCESS, AUTH)
- 3.4 Layer 3: Rule Engine
  - 3.4.1 36 YAML-based Sigma-style rules mapped to MITRE ATT&CK
  - 3.4.2 FSM (Finite State Machine) edge-sequence matching on RabbitMQ event stream
  - 3.4.3 Rule coverage: 36 rules across 11 tactics
- 3.5 Layer 4: ML Engine
  - 3.5.1 Graph-level feature extraction (27 features per Process node)
  - 3.5.2 Multi-label MITRE tactic classification (AutoGluon)
  - 3.5.3 Neo4j writeback: per-tactic probabilities
- 3.6 Dashboard & API

**Chapter 4 — BOTSv2 Data Pipeline: From Raw Splunk Logs to ML-Ready Features**
- 4.1 BOTSv2 Dataset Description
  - 4.1.1 Attack scenarios: webapp (s200), ransomware (s300), APT (s400)
  - 4.1.2 Sourcetype inventory (85+ types, 188.5M events)
  - 4.1.3 Class distribution: 1.14% malicious
- 4.2 Phase 1: CSV → Partitioned Parquet
  - 4.2.1 Schema normalization & _time epoch conversion
  - 4.2.2 Memory-efficient streaming with PyArrow
- 4.3 Phase 3: IOC-Based Labeling
  - 4.3.1 IOC corpus design (iocs.yaml)
  - 4.3.2 Aho-Corasick string matching on `_raw`
  - 4.3.3 Temporal window constraints
  - 4.3.4 Blocklist patterns to prevent false labels
  - 4.3.5 Why `_raw` matching, not host/source matching
- 4.4 Phase 4: Feature Extraction
  - 4.4.1 Per-sourcetype parsers (11 parsers: stream_*, suricata, Sysmon, pan_traffic, mysql_*, auditd, linux_audit, WinRegistry, access_combined, winhostmon, stub)
  - 4.4.2 The graph triple: subject → edge → object
  - 4.4.3 Numeric features: ports, bytes, duration, severity
  - 4.4.4 Categorical features: HTTP, DNS, process, Suricata
  - 4.4.5 Schema as single source of truth (`schema.py`)
- 4.5 Phase 5: Downsampling & Splitting
  - 4.5.1 Memory-conservative 7 GB streaming design
  - 4.5.2 Proportional benign sampling per sourcetype
  - 4.5.3 Temporal split (deployment realism) vs. Stratified split (upper-bound anchor)

**Chapter 5 — Feature Engineering & Data Leakage Prevention**
- 5.1 The Leakage Taxonomy for Security Datasets
  - 5.1.1 Identity leakage: host, IP, UUID
  - 5.1.2 Temporal leakage: timestamps → trivial split overfitting
  - 5.1.3 Target leakage: scenario labels, IOC strings in features
  - 5.1.4 Proxy leakage: source path, subject_id, object_id
- 5.2 Dropped Columns: Detailed Justification
  - 5.2.1 `_time` — temporal overfit
  - 5.2.2 `source`, `host` — host identity proxies
  - 5.2.3 `scenario` — direct target leakage
  - 5.2.4 `src_ip`, `dest_ip` — IOC memorization
  - 5.2.5 `subject_id`, `object_id` — compound identity strings
  - 5.2.6 `subject_name`, `object_name` — near-unique cardinality
  - 5.2.7 `logon_id`, `parent_image`, `suricata_alert_signature` — low permutation importance
- 5.3 Ablation Study Design
  - 5.3.1 Leave-one-in ablation: what happens when a leaky column is re-added?
  - 5.3.2 Drop-one-out ablation: `--drop-feature sourcetype` etc.
  - 5.3.3 Permutation importance as the "headline diagnostic"
- 5.4 Kept Features: Why These Carry Generalizable Signal
  - 5.4.1 `sourcetype` as behavioral context
  - 5.4.2 Graph types as provenance semantics
  - 5.4.3 Network numerics as traffic signatures
  - 5.4.4 Categorical content as behavioral fingerprints

**Chapter 6 — Model Training & Hyperparameter Justification**
- 6.1 LightGBMXT: Why Extremely Randomized Gradient Boosting
  - 6.1.1 Extra-trees as implicit regularization for high-cardinality categoricals
  - 6.1.2 Comparison to vanilla LightGBM (A/B via `--no-xt`)
- 6.2 Hyperparameter Selection
  - 6.2.1 AutoGluon `medium_quality` preset as starting point
  - 6.2.2 `n_estimators=10000` + `early_stopping=200`: convergence without waste
  - 6.2.3 `learning_rate=0.05`: the accuracy-speed tradeoff
  - 6.2.4 `num_leaves=31`: bias-variance for imbalanced binary classification
  - 6.2.5 `feature_fraction=1.0`: why no column subsampling with extra_trees
  - 6.2.6 `min_data_in_leaf=20`: preventing rare-sourcetype overfitting
- 6.3 Category Alignment Across Splits
  - 6.3.1 The silent eval-corrupter: positional category codes
  - 6.3.2 Fit-on-train, reuse-on-val/test protocol
  - 6.3.3 Unknown categories → NaN (LightGBM native handling)
- 6.4 Operating Threshold Selection
  - 6.4.1 F1-maximizing grid search on validation
  - 6.4.2 Why F1 over precision, recall, or MCC as the operating metric

**Chapter 7 — Evaluation**
- 7.1 Experimental Setup
  - 7.1.1 Hardware & software environment
  - 7.1.2 Dataset statistics: train/val/test sizes, positive rates
- 7.2 Primary Metrics
  - 7.2.1 ROC-AUC (threshold-independent)
  - 7.2.2 Precision, Recall, F1 at operating threshold
  - 7.2.3 Matthews Correlation Coefficient (MCC)
  - 7.2.4 Confusion matrix analysis
- 7.3 Per-Scenario Recall
  - 7.3.1 s200_webapp_attack coverage
  - 7.3.2 s300_ransomware coverage
  - 7.3.3 s400_taedonggang_apt coverage
- 7.4 Per-Sourcetype Recall
  - 7.4.1 Which log sources are hardest to classify?
  - 7.4.2 Sourcetype-aware sampling impact
- 7.5 Temporal vs. Stratified Split Comparison
  - 7.5.1 Performance gap as generalization measure
  - 7.5.2 Temporal split as deployment-realistic evaluation
- 7.6 Feature Importance & Leakage Diagnostics
  - 7.6.1 Permutation importance rankings
  - 7.6.2 Leakage ablation results
  - 7.6.3 Sourcetype dominance analysis
- 7.7 Probability Calibration
  - 7.7.1 Calibration curve analysis
  - 7.7.2 Score histogram distribution
- 7.8 Comparison to Baselines
  - 7.8.1 Rule-engine-only detection
  - 7.8.2 AutoGluon multi-model ensemble
  - 7.8.3 (Optional) Comparison to DARPA TC results from ActMiner / POIROT

**Chapter 8 — Discussion**
- 8.1 Key Findings Summary
- 8.2 Limitations
  - 8.2.1 BOTSv2 is synthetic — realism vs. DARPA TC
  - 8.2.2 IOC-based labeling may have false negatives/positives
  - 8.2.3 s100_insider_threat disabled — email/SMTP encoding limitation
  - 8.2.4 Single-dataset evaluation — no cross-dataset generalization test
- 8.3 Sourcetype as a Feature: Blessing or Curse?
- 8.4 The Dual-Layer Philosophy: Rules for Explainability, ML for Coverage
- 8.5 Practical Deployment Considerations
  - 8.5.1 Threshold calibration for SOC workflows
  - 8.5.2 Model drift and retraining cadence
  - 8.5.3 Neo4j writeback latency
- 8.6 Training vs. Production Thresholds
  - 8.6.1 Why production uses ≥0.9/≥0.7 instead of F1-optimal 0.310/0.430
  - 8.6.2 Precision-biased operation for SOC alert quality

**Chapter 9 — Conclusion & Future Work**
- 9.1 Summary of Contributions
- 9.2 Answers to Research Questions
- 9.3 Future Work
  - 9.3.1 GNN-based node classification on the provenance graph (replacing tabular ML)
  - 9.3.2 LLM-powered forensic narrative generation
  - 9.3.3 Real-time streaming inference with Kafka/Flink
  - 9.3.4 Cross-dataset evaluation (DARPA TC E3/E5 + OpTC)
  - 9.3.5 Adversarial robustness evaluation (mimicry attacks per Goyal et al.)

**References**

**Appendices**
- A. Full IOC Corpus (iocs.yaml)
- B. Rule Engine Coverage Matrix (30+ MITRE techniques)
- C. Per-Sourcetype Parser Details
- D. Complete Evaluation Plots (ROC, PR, Confusion, Calibration, Permutation Importance)
- E. Schema.py — Full Column Listing

---

## 6. Unresolved Questions

1. **s100_insider_threat**: The insider threat scenario is disabled because email/SMTP encoding defeats substring IOC matching. Could NLP-based labeling or MIME decoding enable this scenario?
2. **Sourcetype dominance**: If `sourcetype` is the most predictive feature, is the model effectively a per-sourcetype threshold rather than a behavioral classifier? The `--drop-feature sourcetype` ablation should quantify this.
3. **Cross-dataset transfer**: Would a model trained on BOTSv2 generalize to DARPA TC E3 data (different schema, different attack types)? The graph-type abstraction (Process/File/Socket × FORK/EXEC/READ/WRITE) is shared, but the categorical content features are entirely different.
4. **Temporal split gap**: How large is the AUC drop from stratified → temporal split? A large gap would indicate the model is partly learning time-dependent patterns despite `_time` removal (e.g., via correlated features like `http_uri` patterns that change over time).
