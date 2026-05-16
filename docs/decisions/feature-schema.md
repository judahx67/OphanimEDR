# Decision: Feature Schema (42 columns)

## What

The LightGBMXT model is trained on 42 features extracted per provenance edge.
Single source of truth: `server/ml-engine/botsv2/schema.py`.
Live-scoring mirror (must be kept in sync): `server/botsv2_parsers/parsers.py`.

## Feature groups

### Graph triple (4 cols)
`sourcetype`, `subject_type`, `object_type`, `edge_type`

These encode what kind of causal relationship the edge represents.
`sourcetype` is included in the headline model; excluded in the honest model (no-sourcetype variant).

### Numeric features (13 cols)
`src_port`, `dest_port`, `http_status`, `http_content_length`, `bytes`, `bytes_in`,
`bytes_out`, `packets_in`, `packets_out`, `duration`, `event_id`, `process_id`,
`suricata_alert_severity`

### Categorical features (25 cols)
**Network identity:** `external_ip`, `src_ip`, `dest_ip`
**Transport:** `transport`, `protocol`, `app_proto`
**HTTP:** `http_method`, `http_uri`, `http_user_agent`, `http_referrer`, `http_content_type`, `site`
**DNS:** `dns_query`, `dns_qtype`, `dns_rcode`
**Process:** `process_name`, `image`, `command_line`, `parent_command_line`, `user`, `integrity_level`
**Registry:** `registry_key`, `registry_value`
**Suricata:** `suricata_event_type`, `suricata_alert_category`

## Why these features?

**Why network identity?** IP addresses identify C2 infrastructure. `external_ip` (always the non-RFC-1918 endpoint, direction-independent) was added after observing that `src_ip`/`dest_ip` swap roles between attack phases, causing temporal domain shift. See `s400-recall.md`.

**Why graph triple?** The provenance graph type system (14 edge types × 9 node types) is the primary structural signal. A CONNECT from Process→Socket is qualitatively different from a WRITE from Process→File; the model needs this context.

**Why process fields?** Command-line content (`command_line`, `parent_command_line`, `image`) carries attack signatures (encoded payloads, LOLBin invocations, suspicious parents).

**Why HTTP fields?** `http_uri` carries SQL injection patterns (s200), encoded shellcode, webshell paths. `http_user_agent` and `http_status` provide response-code and client-fingerprint signal.

## Columns excluded as leaky

Dropped at training time — would give the model information unavailable at inference:

| Column | Reason |
|---|---|
| `_time` | Encodes time position; model would learn time-of-day/week patterns, not behaviour |
| `source` | Splunk source path — encodes the log origin, not content |
| `host` | Machine hostname — encodes infrastructure topology, not behaviour |
| `scenario` | Direct attack label — pure leakage |
| `subject_id` | UUID — random per event, no signal |
| `object_id` | UUID — same |
| `subject_name` | Full entity name often contains IOC strings (e.g. `45.77.65.211`) |
| `object_name` | Same |
| `logon_id` | Session token — encodes identity, leaks via reuse |
| `parent_image` | Often identical to `image` with slightly different formatting |
| `suricata_alert_signature` | Contains full IOC strings (IPs, domains) |

`subject_name`/`object_name` are excluded because they can embed the C2 IP or attack domain directly, making the model a string-matcher rather than a behaviour learner.

## Startup guard

`server/ml-edge-scorer/model_loader.py` checks that the booster's internal feature list matches `feature_names.json` at startup. Any mismatch is logged as an error before scoring begins.
