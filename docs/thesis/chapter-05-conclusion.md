# Chapter 5 — Conclusion & Future Work

## 5.1 Summary of contributions

This thesis presents an end-to-end EDR system that combines rule-based and ML-based detection on a unified provenance graph derived from heterogeneous Splunk BOTSv2 telemetry. The principal contributions are:

1. **First reported ML classifier on BOTSv2.** A reusable IOC labeling pipeline produces per-event labels from a previously CTF-only dataset. Per-IOC hit counts were empirically verified across the full 138M-row corpus, eliminating 12.4× label inflation from over-broad indicators. The 42-feature schema and 11 per-sourcetype parsers are released as a foundation for further BOTSv2 ML work.

2. **Direction-independent network feature engineering.** The `external_ip` feature resolves a structural challenge in temporal evaluation: C2 infrastructure appears as `src_ip` during compromise and `dest_ip` during exfiltration. Without it, temporal AUC collapses to 0.82; with it, 0.9530. This technique generalises to any dataset where bidirectional flows are labeled by one endpoint.

3. **Quantified leakage methodology.** Two model variants (headline AUC 0.9530, honest 0.5544) make the routing-label contribution explicit. A stratified reference (0.9999) confirms the model can learn the full signal with proper train/test mix; the temporal gap to 0.9530 reflects genuine domain shift, not additional leakage. The methodology extends Arp / TESSERACT / Engelen leakage-prevention precedent to multi-source SIEM telemetry.

4. **Production hybrid pipeline.** Rules and ML co-annotate the same Neo4j provenance graph at ingest rate. ML scores trigger LLM-generated narratives, closing the explainability gap that opaque ML scores otherwise leave for SOC analysts.

## 5.2 Answers to research questions

**RQ1** (BOTSv2 detection performance): Headline model achieves 0.9530 ROC-AUC on temporal split. Stratified upper bound is 0.9999, confirming the model can learn all attack patterns when trained on a representative mix. The temporal gap (0.9530 vs 0.9999) is attributable to genuine domain shift: attack phases differ between training and test windows, and three sourcetypes (pan_traffic, suricata, stream_tcp/ip) are labeled purely by C2 IP with insufficient training examples to fully generalize.

**RQ2** (genuine signal vs metadata): The ~40 pp gap between headline (0.9530) and honest/no-sourcetype (0.5544) quantifies the routing-label contribution under clean labels. Unlike the pre-Stream-A experiment (8.7 pp gap with inflated labels), this larger gap is honest: with clean labels the model cannot substitute sourcetype correlation for real content patterns. The honest model's 0.5544 still exceeds random, driven by Sysmon (100% recall via command_line/image) and partial IP signal in pan_traffic/stream sourcetypes.

**RQ3** (dual-layer benefit): The rule engine and ML scorer flag overlapping but non-identical edges. Rules provide explainable matches for known ATT&CK techniques (36 rules, 11 tactics); ML provides coverage of unknown variants and assigns continuous risk scores. The shared Neo4j graph enables analyst views that surface both signals without forcing a choice between them.

## 5.3 Limitations

1. **BOTSv2 is synthetic-but-realistic.** While widely accepted for SOC training, it is not real-world production telemetry. Generalization to live environments is not validated.

2. **IOC-based labels carry noise.** Labels derive from substring matches in `_raw`. Empirical audit reduced false positives by 12.4× but recall against true ground truth remains unknown.

3. **IP-based s400 labeling limits temporal recall.** s400 contributes 64% of positives, all labeled by C2 IP. The model cannot detect these flows without IP features; with them, it achieves 19–33% recall on network sourcetypes due to low training-positive counts and phase shift.

4. **s100 insider-threat scenario excluded.** MIME encoding defeats substring IOC matching.

5. **Single-dataset evaluation.** Cross-dataset transfer is untested.

6. **No-sourcetype model underperforms.** Honest temporal AUC (0.5544) is marginally above random for network events. Future work would need richer behavioral features to close this gap without the routing-label shortcut.

## 5.4 Future work

- **Cross-dataset evaluation.** Train on BOTSv2, test on DARPA TC E3 or production traces. The provenance schema is dataset-agnostic; categorical content features need re-engineering.
- **Recall-targeted feature engineering.** `pan_traffic` and `suricata` network flows need either DPI-derived content features or alternative labeling strategies to improve temporal recall.
- **GNN-based per-node scoring.** Replace tabular ML with a graph neural network scoring nodes directly using local subgraph context (KAIROS encoder-decoder as baseline).
- **Online learning / drift detection.** Production deployment requires retraining cadence and distribution-shift monitoring, neither addressed here.
- **Active learning loop.** Analyst feedback on dashboard incidents could feed back as training labels, closing the rule + ML + analyst loop.

## 5.5 Closing remarks

The dual-layer rule + ML approach, grounded in empirically-verified labels and honest temporal evaluation, demonstrates that detection systems can be both performant and methodologically transparent. The journey from inflated (0.9877) to honest (0.9530) AUC — achieved by fixing label methodology rather than tuning the model — illustrates that label quality is the dominant factor in security ML credibility. Future EDR systems benefit from auditing their labels before tuning their models.
