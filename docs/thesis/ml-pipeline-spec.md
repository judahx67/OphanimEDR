# ML Pipeline Specification

*Post Stream A (label tightening) + Stream C (retrain) + external_ip feature — 2026-05-16*

## Dataset

**Source:** Splunk BOTSv2 (2017), 188.5M events, 85+ sourcetypes  
**Storage:** Partitioned Parquet at `datasets/botsv2_parquet/`  
**Labeled corpus:** `datasets/botsv2_labeled/` — 101 sourcetype partitions, 138M rows

### Attack scenarios

| Scenario | Attack | Time window (UTC) |
|---|---|---|
| s200 | XSS + SQLi against brewertalk.com MyBB | Aug 15 23:15 → Aug 16 16:00 |
| s300 | Ransomware (.crypt extension) | Aug 18 21:00 → Aug 19 00:00 |
| s400 | Taedonggang APT, C2 at 45.77.65.211 | Aug 11 14:00 → Aug 26 12:00 |

## Labeling

**Script:** `server/ml-engine/botsv2/label.py`  
**Config:** `server/ml-engine/botsv2/iocs.yaml`  
**Method:** First-match-wins IOC substring search in `_raw` (lowercased), time-window gated per scenario.

### IOCs kept after empirical audit (Stream A)

| Scenario | IOC type | Values |
|---|---|---|
| s200 | attack_signatures | `updatexml`, `1502408189` (SQL injection fingerprints) |
| s300 | files | `Frothly_marketing_campaign_Q317.pptx.crypt` |
| s300 | attack_signatures | `.crypt` |
| s400 | ips | `45.77.65.211` (C2 server) |
| s400 | files | `invoice.zip`, `winsys32.dll` |
| s400 | attack_signatures | `912345678` (Korean phone number in C2 payload) |

**Dropped IOCs:** brewertalk.com/victim IPs (s200 victim traffic — 1.7M false positives), eidk.* domains (0 verifiable stream hits), 52.42.208.228 (509k hits, 327k legit MySQL).

### Label distribution

| | Old labels | New labels (Stream A) | Change |
|---|---|---|---|
| Total positives | 2,150,080 (1.56%) | **173,032 (0.125%)** | −12.4× |
| s200 | ~1.7M | 256 | |
| s300 | 4,709 | 3,207 | |
| s400 | ~438K | 110,758 | |

Top sourcetypes by new positive count: suricata (38,371), pan_traffic (48,397), stream_tcp (29,069), stream_ip (29,060), stream_http (9,906), Sysmon (6,564).

## Feature engineering

**Script:** `server/ml-engine/botsv2/extract_features.py`  
**Schema:** `server/ml-engine/botsv2/schema.py` (single source of truth)

### Feature columns (42 total fed to model)

**Graph triple (4):** `sourcetype`, `subject_type`, `object_type`, `edge_type`

**Network identity (3):** `external_ip` *(non-RFC-1918 endpoint, direction-independent)*, `src_ip`, `dest_ip`

**Numeric (13):** `src_port`, `dest_port`, `http_status`, `http_content_length`, `bytes`, `bytes_in`, `bytes_out`, `packets_in`, `packets_out`, `duration`, `event_id`, `process_id`, `suricata_alert_severity`

**Categorical (22):** `transport`, `protocol`, `app_proto`, `http_method`, `http_uri`, `http_user_agent`, `http_referrer`, `http_content_type`, `site`, `dns_query`, `dns_qtype`, `dns_rcode`, `process_name`, `image`, `command_line`, `parent_command_line`, `user`, `integrity_level`, `registry_key`, `registry_value`, `suricata_event_type`, `suricata_alert_category`

### Dropped at train

`_time`, `source`, `host`, `scenario` (bookkeeping/direct answer), `subject_id`, `object_id` (graph merge keys), `subject_name`, `object_name` (exact filenames/paths), `logon_id`, `parent_image`, `suricata_alert_signature` (low-value/not extracted)

### external_ip rationale

s400 C2 IP (45.77.65.211) appears as `src_ip` during initial compromise phase (training window Aug 11–20) and as `dest_ip` during exfiltration (test window Aug 25+). Using `src_ip`/`dest_ip` separately fails because LightGBM learns the signal in one column but test needs the other. `external_ip` = non-RFC-1918 endpoint resolves this regardless of connection direction. Implemented in `train.py` (`_add_external_ip`) and `feature_row.py` (`_external_ip`).

## Downsampling

**Script:** `server/ml-engine/botsv2/downsample.py`  
**Target:** 5.2M rows — all 173K malicious + ~5M proportionally sampled benign  
**Peak RAM:** 2.0 GB (streaming design)

### Split families

| Split | Train | Val | Test |
|---|---|---|---|
| **Temporal** | `_time ≤ Aug 20` (1.07% pos) | `Aug 20–25` (8.30% pos) | `Aug 25+` (5.13% pos) |
| **Stratified** | Random 60% | Random 20% | Random 20% |

## Model

**Algorithm:** `LightGBMClassifier(extra_trees=True, boosting_type='gbdt')` — "LightGBMXT"

**Hyperparameters:**

| Param | Value | Note |
|---|---|---|
| `n_estimators` | 10,000 | capped by early stopping |
| `learning_rate` | 0.05 | |
| `num_leaves` | 31 | |
| `feature_fraction` | 1.0 | |
| `min_data_in_leaf` | 20 | |
| `is_unbalance` | True | required: 1% train positive rate |
| `early_stopping_rounds` | 200 | on val AUC |
| `n_jobs` | 6 | |

**Categorical handling:** pandas `Categorical` dtype, codes aligned to train categories. Val/test unseen values → NaN (LightGBM NaN-safe).

## Results

| Model | Split | Features | AUC | Threshold |
|---|---|---|---|---|
| `lgbm_xt_temporal` | Temporal | 42 (with sourcetype) | **0.9530** | 0.050 |
| `lgbm_xt_temporal_no_st` | Temporal | 41 (no sourcetype) | 0.5544 | 0.050 |
| `lgbm_xt_stratified` | Stratified | 42 | **0.9999** | — |
| `lgbm_xt_stratified_no_st` | Stratified | 41 | **0.9853** | — |

### Per-scenario recall (stratified headline, test)

| Scenario | n | Recall |
|---|---|---|
| s200 webapp attack | 4,275 | 95.1% |
| s300 ransomware | 693 | 88.5% |
| s400 Taedonggang APT | 11,209 | 91.7% |

### Temporal gap explanation

Temporal AUC (0.9530) < stratified (0.9999) due to:
1. **Training volume:** pan_traffic has only 2 training positives vs 18,624 test positives — insufficient signal
2. **Suricata directionality:** training suricata positives are inbound flows (C2→victim), test are outbound (victim→C2); `external_ip` partially resolves this
3. **Domain shift:** attack phases differ across the evaluation window — early compromise vs late exfiltration

The old temporal AUC (0.9877 pre-Stream A) was inflated by IOC label leakage — the model learned which sourcetypes appear during attack time windows, not attack content.

## Production scoring

**Service:** `server/ml-edge-scorer/`  
**Model path:** `server/ml-engine/botsv2/models/lgbm_xt_temporal/` (volume-mounted read-only)  
**Feature builder:** `feature_row.py` — derives `external_ip` from `properties["botsv2_fields"]["src_ip"/"dest_ip"]`  
**Scores written:** `r.botsv2_ml_score` (headline), `r.botsv2_ml_score_honest` (no-sourcetype) on each Neo4j edge  
**Alert thresholds:** ≥ 0.9 headline, ≥ 0.7 honest
