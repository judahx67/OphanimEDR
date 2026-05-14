# Chapter 3 — Methodology

## 3.1 Dataset

**Splunk Boss of the SOC v2 (BOTSv2)**, released 2017. 188.5M raw events spanning 85+ sourcetypes across three active attack scenarios:

| Scenario | Description |
|---|---|
| s200 | Web application attack (XSS, SQLi against `brewertalk.com` MyBB forum) |
| s300 | Ransomware execution and file encryption |
| s400 | Taedonggang APT — spear-phishing → C2 → exfiltration |

A fourth scenario (s100 insider threat) was excluded because email/SMTP MIME-encoding defeats substring IOC matching.

The dataset ships **no per-event labels.** A community CTF scoring sheet with question–answer pairs accompanies the release. We derive per-event labels through IOC matching (Section 3.3).

## 3.2 Pipeline phases

| Phase | Output |
|---|---|
| 1. CSV → Parquet | `botsv2_parquet/` partitioned by `sourcetype`, ZSTD-compressed (~3.7 GB from 98 GB raw) |
| 2. IOC corpus | `iocs.yaml` — manually curated attacker IPs, domains, hashes, users, time windows per scenario |
| 3. Labeling | `botsv2_labeled/` — adds `label`, `scenario` columns via Aho-Corasick `_raw` matching |
| 4. Feature extraction | `botsv2_features/` — 50 extracted columns from 11 per-sourcetype parsers |
| 5. Downsample + split | 1.8M train / 600K val / 600K test (temporal) and stratified counterparts |
| 6. Train | LightGBMXT model + frozen booster artifacts |
| 7. Evaluate | ROC, PR, confusion matrix, per-scenario, per-sourcetype, permutation importance |

Each phase is checkpoint-resumable; the labeled Parquet is preserved across feature-engineering iterations because labels derive from `_raw` content, not extracted features.

## 3.3 IOC-based labeling

Each scenario in `iocs.yaml` lists attacker IPs, domains, file hashes, user accounts, host names, and a temporal window. An event is labeled malicious if its `_raw` contains any IOC string AND its `_time` falls within that scenario's window. Multi-pattern matching uses Aho-Corasick for efficiency over 188.5M rows.

We hand-validated 100 labeled-malicious rows per scenario to estimate label noise; see Chapter 7 for measured precision.

**Excluded from labels.** Per-IP-only matching is excluded (would match every benign event from the corporate network). `1502408189` (a literal IOC that is also a valid epoch) is sanity-checked to match other IOCs simultaneously. The string "Tor Browser 7.0.4" is dropped after matching zero rows — truncated user-agents lose the version suffix.

## 3.4 Feature engineering

The schema (`schema.py`) enumerates **50 extracted columns**: 4 graph-triple features, 13 numeric, 22 categorical, plus 11 leaky/identity columns retained for ablation but never shown to the model. After dropping leaky and low-value columns at train time, the model sees **39 features**.

Eleven per-sourcetype parsers handle the high-volume types: `stream_*`, `suricata`, `Sysmon`, `pan_traffic`, `mysql_*`, `auditd`, `linux_audit`, `WinRegistry`, `access_combined`, `WinHostMon`. Each emits a `ParsedRow` containing the graph triple (subject_type, edge_type, object_type) plus typed content fields. Missing fields are NaN; LightGBM handles natively.

## 3.5 Leakage prevention

Thirteen columns are dropped at training time:

| Group | Columns | Rationale |
|---|---|---|
| Leaky (8) | `_time`, `source`, `host`, `scenario`, `src_ip`, `dest_ip`, `subject_id`, `object_id` | Temporal/identity/IOC information that lets the model trivially overfit |
| Graph-metadata (2) | `subject_name`, `object_name` | Near-unique strings; type carries the signal, name is instance-specific |
| Low-value (3) | `logon_id`, `parent_image`, `suricata_alert_signature` | Near-zero permutation importance; redundant or sparse |

This drop list is consistent with established leakage taxonomy [Kaufman 2012] and security-ML best practice [Arp 2022 P4, Pendlebury 2019, Engelen 2021]. Identity features cause spatial bias (model memorizes which hosts/IPs are compromised); temporal features cause temporal bias (model memorizes when scenarios occur).

### 3.5.1 Why drop sourcetype — the headline-vs-honest pivot

Of the 39 features the model sees, `sourcetype` is the single strongest one.
It is also the feature with the weakest *causal* claim to predicting
maliciousness. We retain it in the **headline** model and drop it in the
**honest** model precisely to quantify how much of the headline performance
is the model exploiting a routing shortcut versus learning genuine behaviour.

**The argument for dropping it:**

1. **Sourcetype is a routing label, not behaviour.** In Splunk it is assigned
   at ingest by the universal forwarder's `inputs.conf` or by `props.conf`
   pattern rules — it identifies *which parser* should process the event, not
   *what the event means*. This is the canonical Arp et al. 2022 Pitfall P4
   (Spurious Correlations): a feature that encodes the collection environment
   rather than the phenomenon.

2. **Direct precedent in CICIDS port-drop.** Engelen, Rimmer & Joosen (IEEE
   S&P WTMC 2021) drop `Destination Port` from CICIDS2017 because it is a
   flow-defining identifier assigned by capture, not behaviour. `sourcetype`
   plays the same role on a structurally larger label space (85+ values vs
   65k ports), so the same reasoning applies.

3. **Quantified shortcut.** Headline ROC-AUC = 0.9877; honest ROC-AUC = 0.9135.
   The 8.7 percentage-point drop is what the model gives up when forced to
   ignore the routing label. Crucially, the honest variant still achieves
   0.9135 — confirming that real behavioural signal exists in the content
   features (ports, methods, URIs, process names, byte counts) and the
   headline gain is *enhanced* by sourcetype, not *driven* by it.

4. **TESSERACT-style honest reporting.** Pendlebury et al. 2019 argue that
   security-ML papers should report a deployment-realistic number alongside
   the best-case lab number. Our dual report follows their framework: the
   honest 0.9135 is the deployment-realistic claim; the headline 0.9877 is the
   ceiling.

**The argument for keeping it (steel-man, addressed in Discussion):**
Sommer & Paxson (S&P 2010) argue protocol/service identity is necessary for
operational interpretability — a "high-confidence anomaly" alert means little
without "anomaly of what." We resolve this by keeping `sourcetype` in the
alert metadata (visible to the analyst on the dashboard) but removing it from
the feature vector seen by the honest model. The dashboard still routes by
sourcetype; the detection does not.

**How readers should interpret the numbers:**

| Model | What it answers | Honest claim level |
|---|---|---|
| Headline (sourcetype in) | "What is the best AUC achievable with the full feature set on this dataset?" | Upper-bound claim |
| Honest (sourcetype out) | "How much of that AUC survives removing the strongest routing-label shortcut?" | Deployment-realistic claim |
| Stratified-split reference | "How much of the temporal-vs-headline gap is leakage vs distribution shift?" | Diagnostic only |

## 3.6 Model

**LightGBMXT** = `lightgbm.LGBMClassifier(extra_trees=True, boosting_type='gbdt')`. The extra-trees variant picks split thresholds randomly rather than greedy-best, providing implicit regularization on high-cardinality categoricals (process names, command lines, URIs, DNS queries).

Hyperparameters lifted from AutoGluon's `medium_quality` preset, which won the prior experiment leaderboard:

```python
LGBMClassifier(
    extra_trees=True,
    boosting_type="gbdt",
    objective="binary",
    metric="auc",
    n_estimators=10_000,         # bounded by early stopping
    learning_rate=0.05,
    num_leaves=31,
    feature_fraction=1.0,
    min_data_in_leaf=20,
    n_jobs=6,
    random_state=42,
)
```

Early stopping at 200 rounds patience on validation AUC. Training takes 76–80 seconds per variant on 1.8M rows × 39 features.

## 3.7 Two model variants

We train and report two variants:

| Variant | Features | Purpose |
|---|---|---|
| `lgbm_xt_temporal` (headline) | 39 (sourcetype included) | Best-achievable detection score |
| `lgbm_xt_temporal_no_st` (honest) | 38 (sourcetype excluded) | Quantifies signal beyond the routing-label feature |

A third reference model (`lgbm_xt_stratified`) trains on a stratified random split as the oracle upper bound — used to attribute the temporal-vs-honest gap to distribution shift versus leakage.

## 3.8 Operating threshold

For each variant we grid-search 91 thresholds in `[0.05, 0.95]` on validation, selecting the F1-maximizing threshold. F1 balances precision (alert fatigue cost) and recall (missed-attack cost) — the standard operating metric in intrusion detection literature [Sommer & Paxson 2010].

In production, alert thresholds are deliberately set higher (≥0.9 headline, ≥0.7 honest) to bias toward precision in the SOC workflow. The F1-optimal threshold is the methodological reporting choice; the production threshold is the operational choice.

## 3.9 Evaluation protocol

For each variant on the test set:

- **Aggregate metrics:** ROC-AUC, F1, precision, recall, MCC at the operating threshold
- **Per-scenario recall:** group test rows by scenario among malicious rows
- **Per-sourcetype recall:** top 12 by malicious-row count
- **Permutation importance:** ΔROC-AUC when each feature is shuffled (interpret with caution when correlated features inflate dominant-feature importance)

Both temporal and stratified splits are evaluated; the gap quantifies generalization vs in-distribution performance.
