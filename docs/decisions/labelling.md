# Decision: Ground-Truth Label Assignment

## What

Labels are assigned by `server/ml-engine/botsv2/label.py` using `iocs.yaml`.
A row is labelled **malicious (1)** if:

1. Its `_time` falls within the scenario's `time_window` (Unix epoch seconds), AND
2. The concatenated string `_raw + source + host` (lowercased) contains **any** of the scenario's IOC patterns (Aho-Corasick substring match, first-match-wins).

Otherwise the row is labelled **benign (0)**.

## IOC inventory per scenario

| Scenario | Time window | IOC types | IOC values |
|---|---|---|---|
| s100_insider_threat | 2017-08-02 to 2017-08-26 | — | **0 IOCs → zero labels** |
| s200_webapp_attack | 2017-08-16 ~16h window | attack_signatures (2) | `updatexml`, `1502408189` |
| s300_ransomware | 2017-08-19 ~3h window | files (1), attack_signatures (1) | `Frothly_marketing_campaign_Q317.pptx.crypt`, `.crypt` |
| s400_taedonggang_apt | 2017-08-11 to 2017-08-26 | ips (1), files (2), attack_signatures (1) | `45.77.65.211`, `invoice.zip`, `winsys32.dll`, `912345678` |

**s100 has zero labels** — no usable IOCs identified; this scenario contributes only benign rows.

## Why substring match, not field-level matching?

BOTSv2 is stored as raw Splunk events (`_raw`). Structured field extraction is
sourcetype-dependent and would require per-sourcetype parsers at label time. Substring
match on `_raw` is sourcetype-agnostic and sufficient for these IOCs (each is specific
enough to have near-zero false positive rate within the time window).

## Leakage disclosure

**Scenario column.** The `scenario` column in the raw dataset directly encodes which
scenario each event belongs to. `label.py` does NOT use `scenario` to assign labels —
labels are assigned purely from IOC substring match + time window. However, `scenario`
is dropped as a leaky column at training time (`LEAKY_COLS` in `schema.py`).

**Time window.** The time window is itself scenario-derived. It defines the labelled
"attack period". Any benign activity during that period that happens to match an IOC
would be mis-labelled; the IOC specificity minimises this (no false positives found in
the audit scan run against the full corpus).

**IP-based labelling (s400).** The C2 IP `45.77.65.211` is the primary s400 IOC.
It appears as a destination IP in pan_traffic/suricata rows during the compromise phase,
but as a source IP during some lateral movement phases. The `external_ip` feature
(direction-independent — always the non-RFC-1918 endpoint) was added to partially
address this directionality, but the temporal domain shift between train and test windows
means s400 recall remains lower than s200/s300. See `docs/decisions/s400-recall.md`.

**`dest_ip` excluded.** `dest_ip` was initially kept but caused leakage: the model
learned to flag any traffic to `45.77.65.211` by IP — memorising the attack rather than
the behaviour. `dest_ip` was moved to `LEAKY_COLS` and replaced by `external_ip`.

## Practical impact on metrics

- s200 (SQL injection): `updatexml` in `http_uri` is a learnable content pattern → recall ~100% on stratified split, ~99.98% on temporal.
- s300 (ransomware): `.crypt` in `object_name` is learnable via Sysmon → recall ~88.5% on stratified.
- s400 (APT): IP-only IOC with no learnable content pattern after dropping `dest_ip` → recall ~91.7% stratified, ~0% temporal (complete domain shift).

## Verified false-positive class: brewertalk.com flows

Live replay of 5000 BOTSv2 events produced 541 ML alerts. Bucketed by source/destination:

| Bucket | Alerts | % |
|---|---|---|
| brewertalk.com (52.42.208.228) — victim web server | 269 | 49.7% |
| Other socket-to-socket CONNECT (internal infra) | 272 | 50.3% |
| Known C2 IP (45.77.65.211) | 0 | 0% |
| Known IOC files (.crypt, invoice.zip, winsys32.dll) | 0 | 0% |

**Cross-referenced against Splunk's own BOTSv2 writeup ([christiant.io/splunkbotsv2](https://christiant.io/splunkbotsv2)):
52.42.208.228 is `www.brewertalk.com` — the victim's own web server, not Taedonggang infrastructure.**

This is not a label miss. brewertalk.com flows are correctly labelled `0` (benign) in training. The model learned the flow-shape signature (~5KB HTTPS, port 443, AWS source IP, internal :443 destination) which the s200 attack traffic shares with normal user traffic. Pan_traffic / suricata sourcetypes carry no `http_uri`, so the discriminating SQL-injection content (`updatexml`) is not visible — the model has only flow shape, which is shared.

**This matches the documented test precision of 0.608.** At our deployment threshold of 0.05, ~40% of alerts are expected to be false positives, and the visible cluster on brewertalk.com is that 40% manifesting on a specific victim domain. It is not a defect of the pipeline or the labelling — it is the documented operating point.

**Implication:** Pure ML cannot triage this FP class. The LLM analyser layer must cross-reference endpoint identity (e.g. "is this IP the victim's own infrastructure per public OSINT?") to suppress alerts on known-benign infrastructure. See `s400-recall.md` and the LLM enrichment roadmap.
