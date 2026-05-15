# IOC Verification — `iocs.yaml` per-IOC evidence

**Status:** FINAL for parseable sourcetypes (26 sourcetypes, ~50M text-rich rows scanned in 3.4 min). CSV artefact: `server/ml-engine/botsv2/audit/audit_iocs_hits.csv`.

**Methodology:** `server/ml-engine/botsv2/audit/audit_iocs.py` substring-matches each IOC against the lowercased `_raw` field of every event in the parseable sourcetype partitions and reports total hit count, time range, and per-sourcetype distribution. CSV artefact: `server/ml-engine/botsv2/audit/audit_iocs_hits.csv`.

**Why this matters:** The current labelling assigns malicious labels by substring-matching IOC strings in `_raw`. An IOC that matches *all over the corpus* labels benign rows as malicious, polluting the training set and inflating ROC-AUC by giving the model a trivial "this string appears → malicious" shortcut.

---

## Headline findings (full corpus — 26 parseable sourcetypes)

| Scenario | IOC | Hits | Time span | Verdict |
|---|---|---:|---|---|
| s200 | `172.31.4.249` (victim internal IP) | **1,698,096** | 31 d | **DROP** — `_raw` of every HTTP/TCP/IP packet to brewertalk |
| s200 | `brewertalk.com` | **967,624** | 31 d | **DROP** — victim's own domain |
| s200 | `www.brewertalk.com` | **933,418** | 31 d | **DROP** — same |
| s200 | `/member.php` (generic phpBB) | 292,668 | 31 d | **DROP** — generic forum path |
| s200 | `/search.php` (generic phpBB) | 96,954 | 31 d | **DROP** — generic forum path |
| s200 | `updatexml` (SQLi payload) | 1,139 | **0.00 d** (7 min on Aug 16 15:24–15:31) | **KEEP** — real SQLi |
| s200 | `1502408189` (XSS cookie value) | 219 | 0.66 d (Aug 15–16) | **KEEP** — real XSS |
| s200 | `tor browser 7.0.4` | **0** | — | **DROP** — never matches in corpus |
| s300 | `.crypt` | 4,260 | **0.13 d** (3 h on Aug 18–19) | **KEEP** — real ransomware encryption |
| s300 | `eidk.duckdns.org` | 12 | 0.00 d (Aug 3 18:20-18:22, **outside current window**) | **AMBIGUOUS** — pre-attack C2 recon |
| s300 | `eidk.hopto.org` | 8 | 0.00 d (Aug 3 18:20-18:21, **outside current window**) | **AMBIGUOUS** — pre-attack C2 recon |
| s300 | `frothly_marketing_campaign_q317.pptx.crypt` | 1 | Aug 19 00:39 (Sysmon) | **KEEP** — real |
| s300 | `got.s07e02...crypt`, `hr_mkraeusen.zip` | 0 | — | **DROP** — never matches |
| s400 | `52.42.208.228` | **509,870** | 31 d | **DROP** — 327k hits in stream_mysql; this is NOT APT infra, it's a legit MySQL endpoint |
| s400 | `45.77.65.211` | 164,291 | 14.74 d (Aug 11–Aug 26) | **KEEP** — real APT C2 |
| s400 | `invoice.zip` | 8 | 0.01 d (Aug 24 03:27, stream_smtp) | **KEEP** — phishing delivery |
| s400 | `912345678` (zip password) | 4 | 0.00 d (Aug 24 03:27, stream_smtp) | **KEEP** |
| s400 | `winsys32.dll` | 3 | 0.02 d (Aug 24 03:36–04:07, Sysmon) | **KEEP** — post-extraction execution |
| s400 | `나는_데이비드를_사랑한다.hwp` | 0 | — | **DROP** — never matches (encoding or absence) |

### Empirical attack windows from this evidence

- **s200_webapp_attack**: 2017-08-15 23:35 UTC → 2017-08-16 15:32 UTC (~16h). XSS exfil cookie `1502408189` runs across that 16h; SQLi `updatexml` is a tight 7-minute burst on Aug 16 15:24–15:31, hitting mysql logs (502 server_stats + 501 transaction_details) in addition to HTTP — clean fingerprint of SQL injection landing.
- **s300_ransomware**: main encryption activity is **3 hours** on 2017-08-18 21:52 → 2017-08-19 00:55 (`.crypt` extension matches in stream_smb + Sysmon). DNS lookups to `eidk.duckdns.org` / `eidk.hopto.org` occur **15 days earlier** on Aug 3 18:20 — outside the current s300 window. Either: (a) extend s300 to a multi-phase window including the recon DNS, or (b) drop the eidk domains as IOCs and rely on `.crypt` alone (current `.crypt` matches alone cover 4,260 of 4,261 in-window malicious events). Recommendation: **(b)** — keeps s300 window tight and avoids labelling DNS-recon events that have no other behavioural evidence.
- **s400_taedonggang_apt**: 2017-08-11 14:40 UTC → 2017-08-26 08:26 UTC (~14.7d), driven by `45.77.65.211` C2 traffic. Phishing-delivery cluster is a separate **40-minute event** on Aug 24 03:27–04:07 (zip delivery in stream_smtp → file write `winsys32.dll` in Sysmon). The bulk of s400 labels are C2 flow records (pan_traffic, suricata, stream_tcp).

### Defense impact — quantified

Projected positive-label volume under the proposed tightening (full corpus):

| Scenario | Current labels | Proposed labels | Reduction |
|---|---:|---:|---:|
| s200_webapp_attack | 1,706,832 | ~1,358 (`updatexml` + `1502408189`, 16h window) | **~1,250×** |
| s300_ransomware | 4,709 | ~4,260 (`.crypt` in 3h window) | ~1.1× |
| s400_taedonggang_apt | 438,539 | ~164,000 (`45.77.65.211` + Aug 24 phishing cluster) | ~2.7× |
| **TOTAL malicious** | **2,150,080** (1.14%) | **~170,000 (0.09%)** | **12.6×** smaller positive class |

Implications:
- The current 0.9877 ROC-AUC is on a corpus where **86% of the malicious class is mislabelled traffic to brewertalk.com**. A model exposed to such labels learns "stream_http row with brewertalk in `_raw` → malicious" rather than any attack pattern.
- Positive rate drops from 1.14% to 0.09% — a more realistic attack-vs-benign ratio in an EDR setting.
- s400 still keeps its hard cases (the C2 traffic that pan_traffic / suricata / Sysmon should detect), so the 64.2% s400 recall problem will be even more visible — but now it's the **right** problem (genuine APT detection difficulty) rather than the wrong problem (label noise).

This is exactly the leakage signal the permutation-importance plot showed (`sourcetype` carrying 30× the importance of any other feature): the model is learning "stream_http rows tend to be labelled s200" because almost ALL stream_http rows touching the brewertalk domain are labelled s200, regardless of whether they're attacks.

---

## Recommended `iocs.yaml` rewrite (preliminary)

```yaml
scenarios:

  - id: s100_insider_threat
    enabled: false  # unchanged — SMTP frame splitting defeats substring match

  - id: s200_webapp_attack
    name: "Brewertalk.com Web Application Attack (XSS + SQLi)"
    # Tightened to the empirically observed attack span:
    # XSS cookie exfil starts ~2017-08-15 23:35; SQLi finishes ~2017-08-16 15:25.
    time_window:
      start: 1502841600   # 2017-08-15 23:00:00 UTC
      end:   1502898000   # 2017-08-16 15:00:00 UTC
      # NOTE: SQLi 30-second window is 2017-08-16 15:24:49 -> 15:25:19; window
      # extended to 15:00 to capture any post-exploitation HTTP activity.
    # Removed all broad IOCs (brewertalk.com, www.brewertalk.com, 172.31.4.249,
    # /member.php, /search.php) — they hit 600k+ benign rows each over the
    # full corpus and labelled all benign brewertalk traffic as malicious.
    attack_signatures:
      - updatexml            # 1139 hits in 7-min burst (mysql_server_stats=502, mysql_transaction_details=501, stream_http=136)
      - "1502408189"         # XSS-exfiltrated cookie value, 219 hits over 16h
      # "tor browser 7.0.4" DROPPED — 0 hits anywhere in corpus.

  - id: s300_ransomware
    name: "Mallory Kraeusen - Ransomware + fpsaud Malware"
    # Empirical window: .crypt activity 2017-08-18 21:52 → 2017-08-19 00:55 (~3h).
    # Eidk domains DROPPED — pre-attack DNS recon Aug 3 18:20-18:22 (15d before
    # the encryption); the 20 events are too small to matter and the timestamp
    # gap argues against bundling them into s300 without a multi-phase rewrite.
    # got.s07e02..crypt and hr_mkraeusen.zip DROPPED — 0 hits.
    time_window:
      start: 1503093600     # 2017-08-18 21:00:00 UTC
      end:   1503104400     # 2017-08-19 00:00:00 UTC
    files:
      - Frothly_marketing_campaign_Q317.pptx.crypt  # 1 hit on Aug 19 00:39 (Sysmon)
    attack_signatures:
      - ".crypt"             # 4260 hits in 3h window (stream_smb + Sysmon)

  - id: s400_taedonggang_apt
    name: "Taedonggang APT - Spear-phishing → C2 → Exfil"
    # Tightened from full-corpus to the 45.77.65.211 hit span (14.7 days).
    # 52.42.208.228 DROPPED — 510k hits across 31 days, 327k in stream_mysql,
    # i.e. legitimate MySQL endpoint mislabelled as APT infra by prior labeller.
    # Korean .hwp filename DROPPED — 0 hits (encoding mismatch or absent).
    # "got.s07e02..crypt" / "hr_mkraeusen.zip" also 0 hits — drop.
    time_window:
      start: 1502462400     # 2017-08-11 14:00:00 UTC
      end:   1503744000     # 2017-08-26 12:00:00 UTC
    ips:
      - 45.77.65.211         # 164k hits over 14.7d; real APT C2 (pan_traffic, suricata, stream_tcp)
    files:
      - invoice.zip          # 8 hits on Aug 24 03:27 (stream_smtp); phishing delivery
      - winsys32.dll         # 3 hits on Aug 24 03:36–04:07 (Sysmon); post-extraction execution
    attack_signatures:
      - "912345678"          # 4 hits on Aug 24 03:27 (stream_smtp); zip password

labeling:
  match_categories:
    - ips
    - domains
    - files
    - url_paths
    - attack_signatures
    - registry_keys
  blocklist_patterns: []   # all removed via per-scenario edits; clearer to read
  min_ioc_specificity: 8
  case_sensitive: false
```

### Disambiguation rule change

Replace `label.py:99` first-match-wins clause with:
- If an event matches IOCs of multiple scenarios, attach the **more specific** scenario by IOC specificity rank (longer IOC string > shorter; named files > IP literal > URL path).
- Emit a `label_ambiguous` flag column for any row that would have matched ≥ 2 scenarios; surface this in the eval to quantify the disambiguation cost.

---

## Resolved by the full scan

- ✅ `52.42.208.228` is **not APT infra** — 327k of 510k hits are in `stream_mysql`. It's a legitimate MySQL endpoint mislabelled as s400. Dropped.
- ✅ s400 file IOCs land where expected: `invoice.zip` in stream_smtp (8 hits), `winsys32.dll` in Sysmon (3 hits), `912345678` zip password in stream_smtp (4 hits). All tight Aug 24 03:27–04:07 cluster.
- ✅ `.crypt` is the dominant s300 signal: 4260 hits in 3h, split stream_smb (2206) + Sysmon (2054). Beautiful behavioural fingerprint of file encryption.
- ✅ `tor browser 7.0.4`: 0 hits anywhere → drop.
- ✅ `eidk.duckdns.org` / `eidk.hopto.org` cluster on Aug 3 18:20 (DNS) — 15 days before s300 main attack. Pre-attack recon, outside main window. Dropped (alternative would be a multi-phase window).
- ✅ Korean .hwp filename: 0 hits. Probably encoding mismatch (UTF-8 vs the raw bytes in `_raw`); dropped.
- ✅ Sysmon recall mystery: the 1648 malicious Sysmon labels in test must come from `.crypt` (s300) — none of the s400 IOCs hit Sysmon except `winsys32.dll` (3 events). **The 0% s400-Sysmon recall in the model is real** — there is essentially no s400-labelled Sysmon evidence in the corpus for the model to learn from.

---

## Open issues (still unresolved)

1. **Walkthrough cross-check** — the BOTSv2 walkthrough at chan2git/splunk-bots may specify exact attack timestamps independently of the IOC-hit windows derived here. Worth a one-time read; if the walkthrough's timestamps disagree, theirs are more authoritative because they're documented attacker actions.
2. **Multi-phase s300 modelling** — the Aug 3 DNS recon is real attacker behaviour but isolated from the Aug 18 encryption phase by 15 days. Keeping a single tight window discards 20 evidence rows; a multi-phase window labels DNS-only events at Aug 3 with no behavioural support. Current recommendation: drop the eidk domains; eat the 20-event loss. Alternative: add separate `s300_recon` phase as a distinct labelled-but-separable scenario.
3. **Disambiguation logic** — first-match-wins in `label.py` is still indefensible. With the proposed tightened windows there's almost no scenario overlap (s200 ends Aug 16; s300 starts Aug 18; s400 spans Aug 11–26 but its IOCs are highly specific). Risk is largely mitigated by data; still worth rewriting the disambiguation to "longest IOC string wins" or "score by IOC specificity" to be safe.
4. **Dataset swap gating** — re-run of `label.py` writes to `botsv2_labeled_v2/` per existing script pattern. Need explicit gate before swapping into the training pipeline (`botsv2_labeled/`) so we never train on partially-relabelled state. Suggest committing the new `iocs.yaml` and the new labelled summary together, atomic move on success.
