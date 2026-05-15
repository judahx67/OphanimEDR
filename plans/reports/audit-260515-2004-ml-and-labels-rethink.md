# ML & Label Pipeline Audit — Rethink Required

**Date:** 2026-05-15
**Trigger:** Phase-01 threshold recalibration scoping flagged "the model was done in a pretty sloppy way, might have stemmed from the data labelling."
**Verdict:** **Confirmed.** Both labels and model need rethinking before any threshold work. Headline numbers (0.9877 / 0.9135 ROC-AUC) are largely a sourcetype-lookup illusion driven by IOC-text leakage from the labelling pipeline.

---

## Label pipeline (`label.py` + `iocs.yaml`)

### How labels are assigned
1. For each scenario, flatten string IOCs of allowed categories (`ips`, `domains`, `files`, `url_paths`, `attack_signatures`, `registry_keys`) into one list.
2. For each row: lowercase `_raw`; substring-match against the scenario's pattern list AND check `_time` is within that scenario's time window.
3. First scenario to match wins; the row is labelled `1` with that scenario id.

### What's wrong with this

**L-1. Time windows for 2/3 active scenarios cover the FULL DATASET range.**
- `iocs.yaml:50-54` — s200 window is `1501632000 → 1503705600` (the entire 2017-08-02 → 2017-08-25 corpus).
- `iocs.yaml:99-103` — s400 same.
- Comment at top of `iocs.yaml:11-13` openly admits: "Time windows are INFERRED from scenario date ranges" and `TODO(human): tighten windows per scenario if possible.` — **still not done.**
- Effect: any row with an attacker IP / URL / sig anywhere in the corpus is malicious. There's no temporal containment.

**L-2. Labels are pure substring matching on `_raw`.** A model that has any string-derived feature (`http_uri`, `http_user_agent`, `command_line`, `dns_query`, `site`, ...) has access to literally the same text the labeller grepped. Permutation importance confirms this directly (see M-1 below).

**L-3. Brewertalk's *internal* IP `172.31.4.249` (`iocs.yaml:59`) is labelled as s200-malicious.** All benign traffic to the same web server during the dataset is labelled malicious-s200. Massive false-positive injection.

**L-4. Cross-scenario IP sharing is resolved by arbitrary assignment.**
- Two IPs (`45.77.65.211`, `52.42.208.228`) appear in BOTH s200 and s400.
- The labeller moved them to s400 only with rationale "APT events are rarer — they need this IP more" (`iocs.yaml:55-57`, `105-107`).
- Any s200 row containing those IPs is now labelled s400. Per-scenario recall numbers are evaluating against shuffled scenario labels.

**L-5. First-match-wins disambiguation** (`label.py:99` clause `& (pl.col("label") == 0)`). Order of scenarios in YAML silently determines which scenario "owns" overlapping evidence. Not principled.

**L-6. Short `attack_signatures` bypass the specificity filter** (`label.py:64`). E.g. `"912345678"` (10 chars, s400) and `"1502408189"` (10 chars, s200) match anywhere these digit sequences appear in any log line. `1502408189` is also a perfectly valid Unix epoch (it IS one: 2017-08-11). High-collision strings labelled as malicious.

**L-7. s100 is disabled and s300 ransomware has a tight window** (4 days). So in practice the corpus has **two active labelling scenarios**, both with all-dataset windows.

**L-8. Resume guard at `label.py:152-159`** just trusts whatever's on disk. A partially-corrupted earlier run silently lives forever.

---

## Model evidence (`evaluate.py` output)

### Permutation importance (committed result, `models/lgbm_xt_temporal/eval/summary.json`)

| Feature | Mean importance | Comment |
|---|---:|---|
| **sourcetype** | **0.3327** | Alone carries 30× the next feature |
| event_id | 0.0114 | Sysmon/Windows event code |
| protocol | 0.0089 | tcp/udp/icmp routing label |
| command_line | 0.0059 | String-derived from _raw |
| bytes_in | 0.0043 | First non-leaky behavioural feature |
| subject_type | 0.0018 | |
| bytes | 0.0013 | |
| ... | | |
| http_uri | 0.000053 | Essentially zero |
| http_user_agent | 0.000043 | Essentially zero |
| **image** | **-0.000026** | Hurts the model |
| **src_port** | **-0.00043** | Hurts the model |
| **dest_port** | **-0.00055** | Hurts the model |
| **duration** | **-0.00065** | Hurts the model |
| **packets_in** | **-0.00075** | Hurts the model |
| **app_proto** | **-0.00204** | Hurts the model |

**M-1. The model is essentially a sourcetype lookup.** `sourcetype` carries 30× the mean importance of the next feature. Dropping it (the "honest" model) costs 8.7 pp AUC. Everything else combined carries ≈1.5 pp.

**M-2. Negative permutation importances** on `src_port`, `dest_port`, `duration`, `packets_in`, `app_proto`, `image`, `http_content_length`, `http_content_type`, `edge_type`. These features actively **hurt** the model on test. The classifier learnt noise on them and benefits from permuting them.

**M-3. Per-sourcetype recall is bimodal:**
- 100% recall on sourcetypes whose `_raw` carries the IOC text: `stream_mysql`, `stream_http`, `access_combined`, `stream_arp`, `mysql_*`, `linux_audit`, `auditd`, `stream_udp`, `stream_ip` (99.9%).
- Near-zero recall where IOC strings aren't in `_raw`: **pan_traffic 1.7%, suricata 6.4%, Sysmon 0.0%.**
- These low-recall sourcetypes are precisely the ones carrying **behavioural** signal (Suricata alerts, PAN flow records, Sysmon process/file events). The classifier ignores them because there's nothing string-matchable in their _raw.

**M-4. Per-scenario recall:**
- s200 (web app, lots of HTTP `_raw` with URL-path IOCs): **99.98%**.
- s400 (APT, more behavioural, less string-shareable evidence): **64.2%**.
- Gap matches M-3 exactly. s400 fails because the carriers of its evidence (Sysmon, Suricata, PAN) are precisely the sourcetypes the labeller couldn't grep effectively.

**M-5. The "honest" model (no sourcetype) at 0.9135 AUC is still leaky.** It still sees `command_line`, `http_uri`, `dns_query` etc., which are strings the labeller substring-matched. The 8.7 pp drop measures the *sourcetype-routing* leak; it doesn't remove the IOC-text leak.

---

## Diagnosis

The current pipeline is a **circular evaluation**:
1. Labels assigned by string-matching IOC text in `_raw`.
2. Features extracted by parsing `_raw` into typed columns that preserve those same strings (`http_uri`, `command_line`, `dns_query`, `site`, ...).
3. Model learns "sourcetypes where these strings appear in `_raw` → label."
4. Evaluation reports 0.9877 ROC-AUC and we celebrate.

A model that achieves 0.9877 ROC-AUC on **this labelling** is mostly proving the labelling is internally consistent. It is *not* demonstrating threat detection.

Under examination an examiner will ask exactly two questions, both of which are presently fatal:
- *"How did you label the data?"* — substring match → so where in the feature pipeline do you ensure the model isn't memorizing the same strings the labeller used?
- *"Per-sourcetype recall: pan_traffic 1.7%, suricata 6.4%, Sysmon 0%. These are the canonical EDR signals. What is the model learning if not those?"*

---

## Recommendation: **rethink**, do not recalibrate

Threshold recalibration on a model that's a sourcetype lookup is meaningless. Defer P0-1 until after a labelling/feature rework. The rework breaks into three independent, sequenceable streams.

### Stream A — Tighten labels (1–2 days)

Goal: shrink the positive class to events that are plausibly part of the attack chain, not "all events anywhere in the corpus that mention an attacker URL."

1. **Tighten s200 and s400 time windows.** BOTSv2 walkthroughs and Splunk's blog list specific attack-event timestamps. Even a rough ±2-day window per scenario shrinks positives massively.
2. **Remove the brewertalk internal IP `172.31.4.249` from s200.** It labels every benign visit to the same site as malicious.
3. **Drop the all-digit `attack_signatures`** (`"912345678"`, `"1502408189"`) — these are collision-prone substrings that don't survive scrutiny.
4. **Choose a non-arbitrary scenario disambiguation** — multi-label, or assign by IOC specificity, or split shared-IP rows out of the positive class. First-match-wins is indefensible.
5. **Re-run `label.py`. Inspect `_label_summary.json` for new positive rates.** Expect significant drop, especially on s200.

### Stream B — Remove text-leak features (parallel)

Goal: keep features that carry **behavioural** signal, drop features that essentially echo back the IOC text.

| Feature | Currently | Recommendation |
|---|---|---|
| `http_uri` | Categorical | **Drop or hash-bucket.** URL path is what s200 labels match on. |
| `http_user_agent` | Categorical | **Drop or coarsen** to UA family. Specific UA strings are IOC list. |
| `command_line`, `parent_command_line` | Categorical | **Replace with structural features:** length, argument count, has-encoded-payload flag, has-base64, has-IP-literal, has-URL-literal. The raw string is leak. |
| `dns_query` | Categorical | **Coarsen to suffix** (eTLD+1) or drop. Full FQDN literally contains attacker domains. |
| `site` | Categorical | **Drop.** Same problem. |
| `image` | Categorical | **Coarsen to basename** (already mostly is) and drop registry-key-style strings. |
| `registry_key`, `registry_value` | Categorical | Audit per-IOC overlap; if none of s100/200/300/400's `registry_keys` IOC list is non-empty in YAML, keep; otherwise drop. |
| `sourcetype` | Categorical | **Keep BUT report results with-and-without** as the leakage ablation (you already do this — keep). |
| `event_id` (Sysmon) | Numeric | **Keep.** Behavioural. |
| `bytes`, `bytes_in`, `bytes_out`, `packets_*`, `duration` | Numeric | **Keep.** Currently mostly negative-importance — that's because labels are noisy, not because the features are bad. Should improve after Stream A. |
| `protocol`, `transport`, `app_proto` | Categorical | **Keep.** Coarse routing labels. |
| `suricata_event_type`, `suricata_alert_category`, `suricata_alert_severity` | Cat / num | **Keep.** Currently has zero importance because Suricata recall is 6% (labels don't reach these rows). Should light up after Stream A. |
| `dns_qtype`, `dns_rcode` | Categorical | **Keep.** Behavioural protocol fields. |

Add three new structural features computed in `extract_features.py`:
- `cmdline_has_ip_literal` (bool): regex match of dotted-quad in command_line.
- `cmdline_has_url_literal` (bool): http(s)://.
- `cmdline_has_base64_blob` (bool): ≥40-char base64 run.

### Stream C — Retrain and re-evaluate (1 day)

1. Rerun `train.py --split temporal` on the new featured Parquet.
2. Expect: lower ROC-AUC (maybe 0.85–0.92 honest range), distributed importance, more useful permutation profile.
3. Per-sourcetype recall should redistribute — Suricata, PAN, Sysmon should climb above zero if there's any behavioural signal at all.
4. **The new headline number is more defensible at 0.85 than the current 0.9877 is at 0.9877.** "We tightened labels, removed IOC-text leakage, dropped 5 points of AUC, and now the model actually uses behavioural features" is a much stronger thesis story than "we got 0.9877 on a pipeline that grades itself."

### Stream D — Then and only then, threshold (deferred)

After Stream C, F1-optimal threshold will re-derive itself; precision-target calibration then becomes meaningful. Phase-01 item P0-1 stays open until Streams A–C land.

---

## What this changes in the broader plan

- **Phase 01 items remaining:** P0-1 threshold work is officially **blocked** by this rework. Streams A–C must precede it.
- **Phase 02** (causal correctness, FSM bug) is **unblocked** and independent. Recommend doing Phase 02 in parallel with Stream A while Stream A waits for time-window research.
- **Phase 03 schema-dedup work** unaffected.
- **Thesis claim wording:** the binary-classification + LLM-explanation story works **better** post-rework because the classifier will actually be doing classification rather than sourcetype lookup. Pre-empt examiner questions by surfacing the permutation-importance plot and the per-sourcetype recall bimodality as part of the methodology section ("we discovered the original labelling produced trivial sourcetype-routing models; here is how we tightened both label and feature pipelines to force the model to learn behavioural signal").

---

## Severity of leaving this alone

If shipped as-is and probed even moderately:
- **Examiner**: "Show me permutation importance." → 0.333 vs 0.011 vs everything-tiny → "Your model is a sourcetype classifier." → fail.
- **Examiner**: "Per-sourcetype recall: Sysmon 0%, Suricata 6%, PAN 1.7%. What are you actually detecting?" → no answer that doesn't admit the leak.
- **Examiner**: "Your s200 window is the full corpus and labels brewertalk's own internal IP. How is that the s200 attack?" → no defense.

**Cost of rework: ~3–5 days for Streams A–C. Cost of NOT reworking: the defense narrative becomes impossible to hold under any rigorous question.**

---

## Unresolved

1. **Time-window source for s200/s400** — does the Splunk BOTSv2 walkthrough give exact attack timestamps, or do we need to derive them from the Suricata/Sysmon-with-IOC-hits cluster ourselves (which is itself a label-dependent task — chicken/egg)?
2. **Multi-label vs single-label per row.** With overlapping IOC sets across scenarios, the cleanest fix is a per-scenario binary label (4 columns instead of 1). But this requires retraining 4 models or a multi-task head. Worth the complexity?
3. **Registry-key labelling** — `iocs.yaml` has `registry_keys` listed but every scenario's list is empty. Is that an oversight or deliberate (and does it match the actual BOTSv2 evidence)?
4. **`s100` insider threat is disabled** because SMTP frames split content. Is there a parser-level fix that re-assembles SMTP DATA before labelling? Or do we accept s100 as out-of-scope and document it?
5. **Replace the labels with rule-engine output?** The 36 Sigma rules in `server/rule-engine/rules/` produce `:Incident` nodes — could those serve as a more rigorous label source than IOC-substring-match? Risk: rules and ML become circular too.
