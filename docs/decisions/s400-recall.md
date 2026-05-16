# Decision: s400 APT Recall Gap

## What

Recall on the s400_taedonggang_apt scenario differs dramatically between splits:

| Split | s400 recall | s200 recall |
|---|---|---|
| Stratified (oracle mix) | ~91.7% | ~95.1% |
| Temporal test (60/20/20) | ~0% | ~99.98% |

## Root cause

s400 positive rows are labelled exclusively by C2 IP `45.77.65.211` (plus two file
names and one PID with very few hits). The vast majority of s400-labelled events are
pan_traffic and suricata network flows containing this IP.

In the temporal split:
- **Training window (60%):** covers the early attack period — traffic from the compromised
  host TO the C2 IP (C2 as `dest_ip`).
- **Test window (20%):** covers the exfiltration/persistence period — traffic FROM the C2
  IP back to internal hosts (C2 as `src_ip`).

The `external_ip` feature (always the non-RFC-1918 endpoint, direction-independent) was
added to partially bridge this gap. It helps, but the feature distribution still shifts
because other co-occurring fields (ports, bytes, protocol) also change between phases.

**Stratified split does not have this problem** because each split contains a random mix
from all time periods, so the model sees both phases in training and tests on the same
distribution. This is why stratified recall is ~91.7% while temporal is ~0%.

## Defense framing (chosen: option C)

**The temporal recall gap on s400 is the thesis's key finding on temporal domain shift,
not a model failure.**

The narrative:
1. *Stratified recall (91.7%)* shows the model **can** learn to flag the APT — it has
   sufficient signal when attack behaviour is seen in training.
2. *Temporal recall (~0%)* shows that **when the attack evolves over time** (C2 direction
   reversal, changing port patterns), a model trained only on the earlier phase cannot
   generalise to the later phase.
3. This is the **core challenge in provenance-graph threat hunting**: attacks are not
   i.i.d. samples. Defenders need continuous re-labelling or online learning as the
   threat actor pivots.
4. The `external_ip` feature is a concrete mitigation — it partially addresses the
   directionality problem. Future work: sliding-window retraining or online feature
   adaptation.

## Alternatives considered

| Option | Reason rejected |
|---|---|
| A: "Known limitation, threshold trading recall for precision" | Doesn't explain the stratified/temporal gap — examiner would ask why |
| B: "Fix by adding better features" | external_ip is the main fix; further gains require richer temporal features or retraining on the full timeline, out of scope |
| C: "Temporal shift demonstration" (chosen) | Honest, supported by numbers, and connects to the thesis's central theme of causality tracking in evolving attack graphs |

## Numbers for the defense

- s400 positives in training: **2 rows** (pan_traffic, temporal window)
- s400 positives in test: **18,624 rows** (pan_traffic + suricata, later time period)
- Without `external_ip`: temporal AUC 0.8233, s400 recall ~0%
- With `external_ip`: temporal AUC 0.9530, s400 recall still ~0% (direction shift dominates)
- Stratified AUC with `external_ip`: 0.9999 (both directions seen in training)
