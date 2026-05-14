# Chapter 5 — Conclusion & Future Work

## 5.1 Summary of contributions

This thesis presents an end-to-end EDR system that combines rule-based and ML-based detection on a unified provenance graph derived from heterogeneous Splunk BOTSv2 telemetry. The principal contributions are:

1. **First reported ML classifier on BOTSv2.** A reusable IOC labeling pipeline produces per-event labels from a previously CTF-only dataset. The 39-feature schema and 11 per-sourcetype parsers are released as a foundation for further BOTSv2 ML work.

2. **Quantified leakage methodology.** Two model variants (headline ROC-AUC 0.9877, honest 0.9135) make the contribution of the routing-label feature explicit. A third stratified reference (0.9981) attributes the residual gap to distribution shift rather than additional leakage. The methodology extends Arp / TESSERACT / Engelen leakage-prevention precedent to multi-source SIEM telemetry.

3. **Production hybrid pipeline.** Rules and ML co-annotate the same Neo4j provenance graph at ingest rate. ML scores trigger LLM-generated narratives, closing the explainability gap that opaque ML scores otherwise leave for SOC analysts.

## 5.2 Answers to research questions

**RQ1** (BOTSv2 vs DARPA-TC baseline performance): Honest model achieves 0.9135 ROC-AUC on temporal split — comparable in magnitude to ActMiner / KAIROS reported numbers on DARPA TC, while operating on substantially more heterogeneous telemetry (85+ sourcetypes vs uniform CDM). Direct head-to-head is not possible due to dataset and evaluation-protocol differences.

**RQ2** (genuine signal vs metadata): The 8.7 pp gap between headline (0.9877) and honest (0.9135) variants quantifies the routing-label contribution. The honest variant's 0.9135 confirms substantial behavioral signal exists beyond sourcetype, but also indicates the headline number overstates deployment-realistic detection by roughly 9 percentage points.

**RQ3** (dual-layer benefit): The rule engine and ML scorer flag overlapping but non-identical edges. Rules provide explainable matches for known ATT&CK techniques (36 rules across 11 tactics); ML provides coverage of unknown variants. The shared graph storage enables analyst views that surface both signals without forcing a choice between them.

## 5.3 Limitations

1. **BOTSv2 is synthetic-but-realistic.** While the dataset is widely accepted as enterprise-realistic for SOC training, it is not real-world production telemetry. Generalization to live enterprise environments is not validated.

2. **IOC-based labels carry noise.** Manual spot-check of 100 labeled-malicious rows per scenario provides estimated precision; recall against true ground truth is unknown.

3. **s100 insider-threat scenario excluded.** Email/SMTP MIME encoding defeats substring IOC matching. Future work could enable this scenario via NLP-based label propagation or MIME-decoded matching.

4. **Single-dataset evaluation.** Cross-dataset transfer (e.g., to DARPA TC E3 or production logs) is untested. Cross-dataset experiments on UNSW↔TON_IoT [Section 2] suggest substantial drops are likely.

5. **Sourcetype semantics ambiguity.** Whether sourcetype is purely a routing label or partly content-derived (`stream:http` inferred from L7 inspection) affects the strict-leakage interpretation. Both interpretations are noted in the Discussion.

6. **Three blind-spot sourcetypes.** `pan_traffic` (recall 1.7%) and `suricata` (recall 6.4%) — these carry near-zero distinguishing content features after dropping IPs. Future feature engineering targeted at these sourcetypes is needed.

## 5.4 Future work

### 5.4.1 Methodological extensions
- **Cross-dataset evaluation.** Train on BOTSv2, test on production traces or DARPA TC. The graph-type abstraction (Process/File/Socket × FORK/EXEC/READ/WRITE) is dataset-agnostic; categorical content features must be re-engineered.
- **Adversarial robustness.** Mimicry attacks per Goyal et al. — modify malicious events to mimic benign distributions and measure detection degradation.
- **Recall-targeted feature engineering for blind spots.** `pan_traffic` and `suricata` recall below 10% suggests these sourcetypes need either content-derived features (deep packet inspection summaries) or scenario-aware features.

### 5.4.2 Model extensions
- **GNN-based per-node scoring.** Replace tabular ML with a graph neural network that scores nodes (Process / Host / User) directly, using local subgraph context. KAIROS's encoder-decoder is a candidate baseline.
- **Multi-class extension to MITRE tactic.** Current model is binary (malicious vs benign). A multi-label tactic classifier (per the older THEIA-track design) could provide analyst-actionable categorization. Rule-engine incidents serve as weak multi-label supervision.
- **Online learning / drift detection.** Production deployment requires retraining cadence and drift detection, neither addressed here.

### 5.4.3 System extensions
- **Streaming inference at higher throughput.** Current scorer batches at 50 events with 2 s flush; production SIEMs see millions of events/minute. Kafka + Flink or Ray Serve are candidate architectures.
- **LLM-assisted forensic narrative refinement.** Current LLM analyzer generates per-incident narratives; a multi-step agent could pull additional Neo4j context and propose response actions.
- **Active learning loop.** Analyst feedback on dashboard incidents could feed back as training labels, closing the rule + ML + analyst loop.

## 5.5 Closing remarks

The dual-layer rule + ML approach, anchored in honest leakage-prevention methodology and applied to the underexplored BOTSv2 dataset, demonstrates that detection systems can be both performant and methodologically honest about their performance. The 8.7 pp gap between headline and honest variants is small enough to argue real behavioral signal exists, large enough to demand transparency about which number is being reported. Future EDR systems benefit from designing for both numbers from the start.
