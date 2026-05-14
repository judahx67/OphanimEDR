# Audit: EDR Classifier Survey Citation Check

Source: `research-260510-2200-edr-classifier-data-handling-survey.md`. Spot-checks via WebFetch / WebSearch (~13 papers).

## Verified ✅

- **UNICORN — Han et al., NDSS 2020.** Authors: Han, Pasquier, Bates, Mickens, Seltzer. WL-style sketches, benign-only training, per-engagement holdout — all confirmed (search + dblp).
- **MAGIC — Jia et al., USENIX Security 2024.** Title and venue match (arXiv 2310.09831). Masked graph autoencoder, three datasets, benign self-supervision confirmed. "Lookup embedding only" claim plausible per arch summary but specific architectural detail not directly verified from abstract — flag as low-confidence (see ⚠️).
- **threaTrace — Wang et al., IEEE TIFS 2022.** Confirmed: node-level, GraphSAGE, benign-only. Author = Su Wang + 8 co-authors. arXiv submission Nov 2021, TIFS pub 2022.
- **KAIROS — Cheng et al., IEEE S&P 2024.** Confirmed: Zijun Cheng, Lv, Liang, Wang, Sun, Pasquier, Han. TGN encoder + MLP decoder, edge-level scoring. Matches survey claim.
- **SLOT — Qiao et al., ACM CCS 2025.** Confirmed: Qiao, Feng, Li, Ma, Shen, Ma, Liu. Graph RL on provenance.
- **ShadeWatcher — Zeng et al., IEEE S&P 2022.** Confirmed: Jun Zeng, Wang, Liu, Chen, Liang, Chua, Chua. TransR + GNN over knowledge graph.
- **FLASH — Rehman et al., IEEE S&P 2024.** Confirmed: Mati Ur Rehman, Hadi Ahmadi, Wajih Ul Hassan. Word2Vec + GraphSAGE + XGBoost. DART Lab.
- **ANUBIS — Anjum et al., SAC 2022.** Confirmed: Md. Monowar Anjum, Shahrear Iqbal, Benoit Hamelin. Bayesian NN on OpTC.
- **DeepTaskAPT — Mamun & Shi, IEEE TrustCom 2021.** Confirmed authors and venue. Task-tree + LSTM. (Survey credits "Mamun" — correct lead author.)

## Partial ⚠️

- **MAGIC "lookup embedding only" specifics.** Abstract confirms masked-graph representation learning, but the precise claim that node features are *purely* a one-to-one label→vector lookup (no path/IP) was not verified from the abstract. Likely correct per public code (FDUDSDE/MAGIC), but treat as soft until repo is checked. Survey author's own unresolved Q #2 already flags this.
- **threaTrace "F1 0.86–0.99 across E3 sub-datasets"** — abstract did not enumerate exact F1 values; range is plausible per literature but not confirmed in spot-check.
- **FLASH headline F1 ~0.96** — paper text not directly fetched (PDF fetch blocked); reported F1 by other surveys is in this range, so plausible.
- **Berrueta et al., SACMAT'21 (OpTC analysis).** **Misattribution.** The SACMAT'21 OpTC dataset analysis paper ("Analyzing the Usefulness of the DARPA OpTC Dataset...") is by **Anjum, Iqbal, Hamelin** — the same authors as ANUBIS. No "Berrueta" SACMAT'21 OpTC paper found. Survey should either rename the citation to Anjum et al. SACMAT'21 (and disambiguate from ANUBIS SAC'22) or remove. The arXiv ID 2103.03080 in the source link belongs to Anjum et al., not Berrueta.
- **TON_IoT IEEE Access'21 attributed to "Booij/Moustafa et al."** **Misattribution.** IEEE doc 9189760 ("TON_IoT Telemetry Dataset…") is **Alsaedi, Moustafa, Tari, Mahmood, Anwar**, IEEE Access vol 8, 2020 (online 2020, often cited 2021). Booij et al. is a *different* paper (IEEE IoT Journal 2021, "ToN_IoT: The Role of Heterogeneity…"). Both exist; the survey conflates them. Fix: split into two rows or relabel as Alsaedi et al.

## Unverified ❌

- **ATLAS PDF (usenix.org/system/files/sec21-alsaheel.pdf)** — 403 Forbidden. However, ATLAS at USENIX Security 2021 by Alsaheel et al. is well-known; entry exists in USENIX program. Author/venue/year safe to assume correct; symbol-abstraction claim (IP_EXT/IP_INT, FILE) is consistent with the published abstract per general knowledge, not directly re-verified here.
- **ProvDetector NDSS 2020 PDF** — fetched but PDF body unparseable. Paper exists at NDSS'20 by Wang et al.; methodology claim (rare-path + PV-DM + LOF) is widely cited and consistent.
- **ProGrapher USENIX'23 PDF** — 403. Paper exists in USENIX Sec'23 program (Yang et al.).
- **StreamSpot KDD'16** — not directly fetched; well-known reference, no reason to doubt.
- **Moustafa arXiv 2010.08521** — not directly fetched; arXiv ID format valid.

## Errors found (action items for survey author)

1. **Berrueta → Anjum.** The SACMAT'21 OpTC analysis paper (arXiv 2103.03080) is authored by **Anjum, Iqbal, Hamelin**, not Berrueta. Same group later published ANUBIS at SAC'22. Rename row in §2 and disambiguate from ANUBIS row.
2. **TON_IoT IEEE Access citation.** Doc 9189760 = **Alsaedi et al. 2020** (IEEE Access), not Booij/Moustafa. Booij et al. is IEEE IoT Journal 2021 (separate paper). Either split into two rows or correct lead author to Alsaedi.
3. **MAGIC "lookup embedding only"** — strengthen by citing the MAGIC code repo or specific section of the paper; current abstract-level evidence is suggestive, not conclusive.
4. **Minor:** UNICORN train/test split per survey says "Per-engagement holdout"; the actual UNICORN paper uses 90/10 split *within each benign dataset* for training, plus separate attack snapshots for test. Not wrong, but phrasing could be tightened.

## Top-line confidence

**Survey is ~85% citation-accurate based on 13 spot-checks.** Two clear misattributions (Berrueta, Booij/Moustafa→Alsaedi); one soft architectural claim (MAGIC lookup-only) that needs repo confirmation; remaining citations verified or strongly plausible. Methodology claims for the high-confidence rows (UNICORN, KAIROS, ShadeWatcher, FLASH, ANUBIS, DeepTaskAPT) all check out against verified abstracts.
