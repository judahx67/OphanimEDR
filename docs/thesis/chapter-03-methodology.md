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
| 2. IOC corpus | `iocs.yaml` — empirically verified attacker IPs, files, signatures per scenario with time windows |
| 3. Labeling | `botsv2_labeled/` — adds `label`, `scenario` columns via substring `_raw` matching |
| 4. Feature extraction | `botsv2_features/` — 42 extracted columns from 11 per-sourcetype parsers |
| 5. Downsample + split | 3.1M train / 1.04M val / 1.04M test (temporal) and stratified counterparts |
| 6. Train | LightGBMXT model + frozen booster artifacts |
| 7. Evaluate | ROC, PR, confusion matrix, per-scenario, per-sourcetype, permutation importance |

Each phase is checkpoint-resumable; the labeled Parquet is preserved across feature-engineering iterations because labels derive from `_raw` content, not extracted features.

## 3.3 IOC-based labeling

Each scenario in `iocs.yaml` lists attacker IPs, file names, attack signatures, and a temporal window. An event is labeled malicious if its `_raw` contains any IOC string AND its `_time` falls within that scenario's window. First-match-wins; matching is case-insensitive substring search.

**Empirical IOC validation.** Each IOC was verified by scanning the full 138M-row corpus using Polars lazy evaluation, counting per-IOC hits and top sourcetypes. IOCs producing false-positive mass were removed:

| Dropped IOC | Reason | Hit count |
|---|---|---|
| `brewertalk.com`, `172.31.4.249` | Victim's own domain/IP — majority of s200 traffic is benign victim usage | ~1.7M |
| `eidk.duckdns.org`, `eidk.hopto.org` | Zero verifiable hits in stream_* (s300 C2 domains) | 0 |
| `52.42.208.228` | 509k hits, 327k in stream_mysql — legitimate AWS MySQL endpoint, not C2 | 509k |

**Result:** 2,150,080 → **173,032 positives** (−12.4×). Positive rate: 0.125%.

## 3.4 Feature engineering

The schema (`schema.py`) defines **42 model features**: 4 graph-triple features, 3 network-identity features (including `external_ip`), 13 numeric, and 22 categorical. Eleven per-sourcetype parsers handle the high-volume types: `stream_*`, `suricata`, `Sysmon`, `pan_traffic`, `mysql_*`, `auditd`, `linux_audit`, `WinRegistry`, `access_combined`, `WinHostMon`. Missing fields are NaN; LightGBM handles natively.

### 3.4.1 external_ip — direction-independent network identity

The s400 C2 server (45.77.65.211) appears as `src_ip` during the initial compromise phase (attacker → victim, training window Aug 11–20) and as `dest_ip` during exfiltration (victim → attacker, test window Aug 25+). Treating `src_ip` and `dest_ip` as separate categorical features means the model learns the signal in one column but cannot apply it to the other.

`external_ip` = the non-RFC-1918 endpoint of the flow, regardless of direction. Computed at both train time and live scoring:

```python
# src wins if public; otherwise dst; both private → dst fallback
external_ip = src_ip if not is_private(src_ip) else dest_ip
```

This resolves the directionality flip and is a behaviorally meaningful feature — identifying the external endpoint of an enterprise network flow is standard in network security analytics.

## 3.5 Leakage prevention

Columns dropped at training time:

| Group | Columns | Rationale |
|---|---|---|
| Temporal/booking (4) | `_time`, `source`, `host`, `scenario` | Temporal overfit / direct answer |
| Graph merge keys (2) | `subject_id`, `object_id` | High-cardinality instance IDs |
| Exact identifiers (2) | `subject_name`, `object_name` | Exact filenames/process paths — near-unique |
| Low-value (3) | `logon_id`, `parent_image`, `suricata_alert_signature` | Near-zero permutation importance |

Note: `src_ip`, `dest_ip`, and `external_ip` are **retained** as categorical features. These are behavioral network identifiers, not ground-truth labels. The tradeoff (closed-world vs open-world deployment) is discussed in Section 3.7.

### 3.5.1 Sourcetype — headline vs honest pivot

`sourcetype` is the single strongest feature. It is also partly a routing label (Splunk assigns it at ingest by `inputs.conf` pattern matching — identifying which parser processes the event, not what the event means). We train two variants to quantify this:

| Model | Features | AUC (temporal) | Interpretation |
|---|---|---|---|
| `lgbm_xt_temporal` (headline) | 42 (sourcetype in) | **0.9530** | Best achievable with full feature set |
| `lgbm_xt_temporal_no_st` (honest) | 41 (sourcetype out) | 0.5544 | Signal surviving removal of the routing-label shortcut |

The ~40 pp gap with the IP features included (vs ~9 pp in earlier inflated-label experiments) reflects the genuine contribution of sourcetype when labels are clean: without it, the model cannot route the C2 IP signal to the correct event-type context. This is discussed further in Chapter 6.

## 3.6 Model

**LightGBMXT** = `lightgbm.LGBMClassifier(extra_trees=True, boosting_type='gbdt')`. The extra-trees variant picks split thresholds randomly rather than greedy-best, providing implicit regularization on high-cardinality categoricals (process names, command lines, URIs, DNS queries).

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
    is_unbalance=True,           # 1% train positive rate
    n_jobs=6,
    random_state=42,
)
```

Early stopping at 200 rounds patience on validation AUC. Best iteration reached at ~99 rounds (headline model). Training takes ~60–96 seconds per variant on 3.1M rows × 42 features.

## 3.7 Evaluation protocol

**Split strategy:** Temporal 60/20/20 by `_time` (train Aug 11–20, val Aug 20–25, test Aug 25+). This reflects realistic deployment: the model is trained on earlier data and evaluated on later data. A stratified random split is also trained as a capability upper bound.

**Temporal gap explanation:** Test positive rate (5.1%) differs from train (1.07%) and val (8.3%) because s400 attacks concentrate in the later window. Per-sourcetype recall on temporal test reveals the blind spots driven by IP-based labeling:

| Sourcetype | Test positives | Temporal recall |
|---|---|---|
| Sysmon | 1,344 | 100% (command_line/image features) |
| stream_http | ~1,900 | high (http_uri SQL injection) |
| pan_traffic | 18,624 | 19% (external_ip partial) |
| suricata | 14,906 | 33% (external_ip + event type) |
| stream_ip/tcp | 9,259 each | 25% (directionality partially resolved) |

**Aggregate metrics reported:** ROC-AUC, F1, precision, recall, MCC at the operating threshold; per-scenario recall; per-sourcetype recall (top 12 by malicious count).
