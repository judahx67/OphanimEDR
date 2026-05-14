# Sourcetype-Drop Precedent: Deep Dive

**Date:** 2026-05-11
**Scope:** Four-angle expansion on the existing prior-art report
(`research-260510-2133-binary-classifier-prior-art-and-leakage-precedent.md`)
to support thesis Methodology + Discussion chapters.

**Angles covered:** (1) 2025–2026 precedent, (2) Sommer–Paxson steel-man,
(3) field-by-field drop justification, (4) consolidated framing.

---

## 1. 2025–2026 Precedent — Status

**Finding:** No new high-impact paper found that *quantifies* a routing-label
drop with reported metric delta beyond what was already cited (Arce et al. 2025
arXiv 2506.09662). 2025–2026 NIDS literature is dominated by:

- Generic survey/review papers (5G NIDS reviews, transfer-learning surveys)
- Explainability-focused work (XAI for IDS, attention/saliency on flow features)
- Boosting-classifier feature-engineering ablations on CICIDS-family datasets

**Closest 2023–2025 additions worth citing:**

| Paper | Venue | Contribution to sourcetype-drop argument |
|---|---|---|
| **Wei et al. 2023 — XNIDS** | USENIX Security 2023 | Explainability framework that *forces* deep NIDS classifiers to expose which features drive predictions — natural lever to detect routing-label shortcuts post-hoc. |
| **Apruzzese et al. 2023 SoK** | IEEE EuroS&P 2023 (re-cite) | Already in foundation. Strongest "deployment-realistic vs lab" framing. |
| **Arce et al. 2025** | arXiv 2506.09662 (re-cite) | Already in foundation. PE-metadata integrated-gradients. Most recent leakage quantification. |
| **Various 2025 5G NIDS surveys** | MDPI / Springer | Cite *only* if reviewer asks for breadth — survey-level, no novel AUC-cost evidence. |

**Bottom line:** The 8-paper foundation already cited is still the canonical
defense. Adding XNIDS strengthens the "interpretability lets us *detect*
routing-label shortcuts" angle.

---

## 2. Sommer–Paxson Steel-Man

**Position to address:** Sommer & Paxson (S&P 2010) argue ML for NIDS suffers
a *semantic gap* — predictions without protocol/service context are
operationally useless. Therefore some "routing" features (sourcetype, protocol
family, service identity) may be **necessary for interpretability**, not just
predictive lift.

**When keeping routing-label features IS justified:**

1. **Operational triage.** When the goal is alert dispatching to the right
   analyst team (web-app vs network vs endpoint), the sourcetype IS the answer
   — the model is doing routing, not detection. Dropping it makes the output
   harder to action.

2. **Per-sourcetype model specialization.** If the architecture trains *one
   classifier per sourcetype*, sourcetype is implicit in the model selection
   and explicit retention is redundant, not leakage.

3. **Semantic-gap framing (S&P 2010 §3.3).** A "high-confidence anomaly" alert
   means little without "anomaly *of what*". Protocol/service identity grounds
   the prediction.

4. **Concept-drift defense.** If new sourcetypes appear in deployment that the
   model has never seen, a sourcetype-aware model can be retrained or routed
   safely; a content-only model silently scores them as in-distribution.

**Three counter-counter points (defend the sourcetype-drop):**

1. **Distinguish *prediction-time* from *display-time* sourcetype use.** Drop
   it from the *feature vector* but keep it in the *alert payload*. You lose
   nothing operationally — the analyst still sees sourcetype on the dashboard
   — but the model can't shortcut.

2. **Routing ≠ detection.** S&P's argument applies to the *system*, not the
   *classifier*. A two-stage design (sourcetype-aware router → sourcetype-blind
   detector) addresses both concerns.

3. **Apruzzese 2023 SoK explicitly resolves this.** Their "deployment-realistic"
   reporting framework keeps context features available for the *analyst* but
   strips them from the *model* to measure honest discrimination.

**Recommended thesis posture:** Acknowledge S&P in Discussion. State that the
honest model is the *detection layer*, not the *triage layer*; sourcetype is
preserved in graph node properties and alert metadata for analyst use.

---

## 3. Field-by-Field Drop Justification

Designed as a Methodology-chapter table. Each row: feature → leakage category
→ strongest single citation → one-line defense.

| Dropped feature | Leakage category | Strongest citation | One-line defense |
|---|---|---|---|
| `_time` | **Temporal** | Pendlebury et al. 2019 (TESSERACT) | Temporal split already isolates train/test eras; including absolute timestamps lets the model memorise attack windows rather than learn behaviour. |
| `host`, `hostname` | **Identity (spatial)** | Arp et al. 2022 (Pitfall P4 Spurious Correlations) | Host identity encodes the BOTSv2 scenario layout — `we8105desk` = workstation, `gacrux` = web server. The model would learn the lab topology, not the threat. |
| `src_ip` | **Identity / IOC memorisation** | Engelen, Rimmer, Joosen 2021 | Direct analog to their Destination Port drop: a flow-defining identifier, not behavioural content. Attacker IPs in BOTSv2 are unique constants. |
| `dest_ip` | **Identity / IOC memorisation** | Engelen et al. 2021 (same paper) | Same logic; destination IPs include hard-coded victim hosts that would not generalise to a new deployment. |
| `sourcetype` | **Routing / spurious correlation** | Arp et al. 2022 (P4) + Engelen 2021 | Splunk routing label assigned at ingest, not derived from behaviour. The 8.7-pp AUC cost (0.9877 → 0.9135) is the quantified shortcut. |
| `scenario` | **Direct target leakage** | Kaufman et al. 2012 | The labelling field itself; trivial leakage. Standard ML hygiene. |
| `subject_id`, `object_id` | **Compound identity** | Arp P4 (inherits host+IP) | Built from host + pid + path — every component already dropped for identity reasons. Keeping the composite would re-import them. |
| `subject_name`, `object_name` | **High-cardinality near-unique** | Arp et al. 2022 (Pitfall P5 Inappropriate Performance Measures) | Process command lines / file paths are effectively unique per event; LightGBM would memorise them. |
| `parent_image` | **Identity / spurious correlation** | Arp P4 (parent-process names act as deployment artefact) | The parent's *behaviour* survives in FORK edges; the parent's *string name* is environment-specific (`/usr/bin/sshd` paths differ across hosts). |
| `logon_id` | **Identity** | Kaufman 2012 (high-cardinality identifier) | Session-scoped opaque integer; near-unique per event. |
| `suricata_alert_signature` | **Target proxy** | Arp P4 (label-correlated metadata) | Suricata's own signature label is what *another* detector already decided — using it as a feature makes the ML classifier a Suricata reproducer, not an independent signal. |

**Citation density:** 3 papers (Arp 2022, Engelen 2021, Kaufman 2012) cover
every row. TESSERACT covers the temporal axis. That's the minimum citation set
for the Methodology chapter.

---

## 4. Consolidated Recommended Framing for the Thesis

**Methodology chapter** — three citation pillars:

1. **Arp et al. 2022 (USENIX Sec) — Pitfall P4 Spurious Correlations.**
   The taxonomic anchor: routing labels are P4 by definition. Cite once,
   reuse for every identity/routing drop.

2. **Engelen, Rimmer & Joosen 2021 (IEEE S&P WTMC) — CICIDS port-drop.**
   The closest direct analog: drops a flow-identifying field, reports the
   cost, defends the methodology. Your sourcetype-drop is the same move on a
   different field.

3. **Pendlebury et al. 2019 (USENIX Sec) — TESSERACT.**
   The honest-reporting framework. Your dual-model presentation (headline
   vs honest) is TESSERACT-style.

**Discussion chapter** — two additions:

1. **Sommer & Paxson 2010.** Steel-man the keep-it argument. Resolve via the
   two-stage framing (drop from features, keep in alert metadata).

2. **Apruzzese et al. 2023 SoK.** "Pragmatic / deployment-realistic" framing
   is the modern resolution of the S&P critique.

**Optional citations** (cite only if depth needed):

- Catillo et al. 2023 — quantifies cost on CICIDS. Useful if reviewers want
  multi-classifier ablation.
- Arce et al. 2025 — most recent (2025) leakage quantification, integrated
  gradients on PE metadata.
- Sommer & Paxson 2010 — only in Discussion, as the position you're refuting.

---

## 5. Unresolved Questions

1. Has Splunk published any internal document on how `sourcetype` is assigned
   for BOTSv2 events? Specifically: is `stream:http` set by L7 inspection
   (content-derived) or by collector configuration (pure routing)? If
   content-derived, the leakage argument weakens to "this is a content summary
   feature" and may need re-framing as Arp Pitfall P3 (Sampling Bias) rather
   than P4.

2. Worth direct-reading XNIDS (USENIX Sec 2023) to confirm whether their
   explainability framework was ever applied to a routing-label feature
   specifically. If yes, that's a strong post-hoc validation citation.

3. Is there a 2025–2026 paper specifically on *Splunk* ML pipelines that
   discusses sourcetype handling? Search did not surface one but Splunk's
   internal blogs may have unindexed content.

---

## 6. Sources

### Already in foundation report (re-cited)
- [Arp et al. — Dos and Don'ts of ML in Security (USENIX 2022)](https://www.usenix.org/system/files/sec22summer_arp.pdf)
- [Pendlebury et al. — TESSERACT (USENIX 2019)](https://www.usenix.org/system/files/sec19-pendlebury.pdf)
- [Engelen et al. — Troubleshooting CICIDS2017 (WTMC 2021)](https://intrusion-detection.distrinet-research.be/WTMC2021/Resources/wtmc2021_Engelen_Troubleshooting.pdf)
- [Catillo et al. — Faulty use of CIC-IDS 2017 (J. Comput. Virol. 2023)](https://link.springer.com/article/10.1007/s11416-023-00509-7)
- [Apruzzese et al. — SoK Pragmatic Assessment NIDS (EuroS&P 2023)](https://arxiv.org/abs/2305.00550)
- [Arce et al. — Spurious Correlations in Malware Detection (arXiv 2025)](https://arxiv.org/abs/2506.09662)
- [Kaufman et al. — Leakage in Data Mining (ACM TKDD 2012)](https://dl.acm.org/doi/10.1145/2382577.2382579)
- [Sommer & Paxson — Outside the Closed World (IEEE S&P 2010)](https://www.icir.org/robin/papers/oakland10-ml.pdf)

### Added in this report
- [Wei et al. — XNIDS Explaining Deep Learning NIDS (USENIX Sec 2023)](https://www.usenix.org/system/files/sec23summer_77-wei-prepub.pdf)

### Background (for breadth only, not load-bearing)
- [Frontiers — Evaluating ML IDS with Explainable AI (2025)](https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1520741/full)
- [MDPI — Review of ML / Transfer Learning for IDS in 5G (2025)](https://www.mdpi.com/2227-7390/13/7/1088)
