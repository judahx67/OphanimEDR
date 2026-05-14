# EDR Classifier Data-Handling Survey

Scope: peer-reviewed ML papers training classifiers (binary / multi-class / node-level / graph-level) on EDR-style telemetry. Focus: **data handling**, not model deep dive.

Comparison context: thesis uses LightGBMXT on Splunk BOTSv2 — 39 typed features, IOC-based per-edge labels, temporal split, F1-tuned threshold, leakage-drop ablation (sourcetype model vs no_st honest model).

Prior reports (do not repeat): BOTSv2 prior art, leakage-drop precedent (Arp 2022 / TESSERACT / Engelen 2021 / Catillo 2023 / Apruzzese 2023 / Kaufman 2012 / Sommer-Paxson 2010 / Arce 2025).

---

## 1. DARPA TC E3/E5 (THEIA, CADETS, TRACE, FiveDirections)

| Paper | Label | Features | Leakage | Balance | Split | Threshold | Model | Headline |
|---|---|---|---|---|---|---|---|---|
| **UNICORN** (Han, NDSS'20) | Graph-level (per-snapshot benign/attack) from ground-truth time ranges | WL-style histogram of rooted subtrees over node/edge label vocabulary; **fixed-size graph sketch** | Uses only label types (Process/File/Socket); IPs/paths abstracted into types; no per-instance identifiers | Trains on **benign only** (one-class); attack snapshots only at test | Per-engagement holdout | Distance-from-cluster-centroid | k-means + outlier | F1 ~0.93 on E3 sub-datasets |
| **ShadeWatcher** (Zeng, S&P'22) | Edge-level via knowledge-graph link prediction; benign edges = positive samples, negative sampled | TransR knowledge-graph embeddings + GNN over system entity-relation triples | Entity strings hashed to ID space; raw paths abstracted; no IP literals | Negative sampling for KG | Per-engagement | Score percentile | TransR + GNN classifier | F1 ~0.95 on E3-Trace |
| **threaTrace** (Wang, TIFS'22) | **Node-level** anomaly via type-prediction error (multi-model GraphSAGE) | One-hot of node label type + neighborhood aggregate; trains only on benign nodes | Identifiers not used as features (only node-type vocabulary) | Benign-only training; per-class GraphSAGE heads | Per-engagement | Misclassification probability threshold | GraphSAGE | Node-level F1 0.86–0.99 across E3 sub-datasets |
| **MAGIC** (Jia, USENIX'24) | **Entity-level** (per-node) using DARPA ground truth attack UUIDs; also batched-log graph-level | **Lookup embedding only**: one-to-one map of node-label→vector and edge-label→vector. No path/IP/PID features. | Pure label-vocabulary embedding — no string/IP leakage by construction | Self-supervised masked reconstruction on benign only; KMeans outlier on embeddings | Per-engagement (DARPA E3) and 75/25 (StreamSpot, Wget) | Outlier-distance threshold (validation tuned) | Masked-graph autoencoder | Entity-AUC ~0.99 on E3-CADETS / THEIA / TRACE |
| **FLASH** (Rehman, S&P'24) | Node-level via type prediction (misclassification = malicious) | Word2Vec on system-call/path tokens + GraphSAGE struct embedding → XGBoost classifier | Path tokens kept (Word2Vec) — leakage risk acknowledged but not ablated | Benign-only training; pre-stored embedding cache | Per-engagement | XGBoost 0.5 default | XGBoost over fused embedding | F1 ~0.96 across E3 |
| **KAIROS** (Cheng, S&P'24) | **Per-edge** scoring then **per-time-window** alerting (window labeled if any edge anomalous; ground truth windows from DARPA timeline) | Temporal Graph Network edge embedding; node features = label-type vocab | Identifiers not used as raw features; node-type only | Self-supervised on benign provenance only | Streaming temporal split: earlier benign → train; later (with attacks) → test | Per-window reconstruction-loss threshold (validation) | TGN encoder-decoder | Per-window F1 ~0.95 on E3 |
| **SLOT** (Qiao, CCS'25) | Per-node multi-armed-bandit reward shaping over benign vs attack | Semantic node embedding + latent relation mining | Same label-vocab style; minimal raw-string usage | RL exploration handles imbalance | Per-engagement | Policy-driven | Graph RL | Acc ~0.99 on E3 |

**Pattern (TC E3):** virtually all 2020-2024 papers convert raw provenance into a **type-vocabulary embedding** and train **one-class on benign**. Per-edge or per-node labels are derived from DARPA's ground-truth attack-UUID list. Train/test is always **per-engagement holdout** (which is implicit temporal split — attacks happen on specific days). IPs and PIDs are routinely dropped because the type vocabulary already discards them; leakage rarely ablated explicitly.

Sources: [UNICORN](https://www.ndss-symposium.org/wp-content/uploads/24046-paper.pdf), [ShadeWatcher](https://jun-zeng.github.io/file/shadewatcher_paper.pdf), [threaTrace](https://arxiv.org/abs/2111.04333), [MAGIC](https://arxiv.org/abs/2310.09831), [FLASH](https://dartlab.org/assets/pdf/flash.pdf), [KAIROS](https://tfjmp.org/publications/2024-sp.pdf), [SLOT](https://arxiv.org/abs/2410.17910).

---

## 2. DARPA OpTC

| Paper | Label | Features | Leakage | Balance | Split | Threshold | Model | Headline |
|---|---|---|---|---|---|---|---|---|
| **ANUBIS** (Anjum, SAC'22) | Per-process via red-team ground-truth event list; binary | Per-event-type expected/actual count vectors D=[D_proc,D_file,D_flow,D_shell] over walks on process tree | Counts only — IPs/UUIDs not directly used | **APT oversampling** during training (severe imbalance) | 80/20 random | BNN softmax | Bayesian NN | Acc 99%, FPR 2.8% |
| **DeepTaskAPT** (Mamun, TrustCom'21) | **Task-level** (a task = subtree); task = malicious if ≥1 entry malicious | Task-tree encoded into LSTM token sequence | PIDs / paths kept as tokens; no explicit drop | Trained on benign tasks only (one-class) | Per-user temporal | Reconstruction-error threshold | LSTM | F1 ~0.97 user0201 |
| **Anjum et al. OpTC analysis** (SACMAT'21, arXiv 2103.03080) | Defines red-team-tagged event sets as positives | Cooccurrence vectorizer on (object,action) pairs | Object strings kept | n/a (analysis study) | n/a | n/a | various baselines | demonstrates feasibility — same authors as ANUBIS, predecessor work |

**Pattern (OpTC):** severe imbalance (~17B events, <0.001% malicious). Strategies: oversample positives (ANUBIS) or train one-class on benign tasks (DeepTaskAPT). Random 80/20 splits are common despite OpTC having a clear day-by-day temporal structure — a methodological weakness.

Sources: [ANUBIS](https://arxiv.org/abs/2112.11032), [DeepTaskAPT](https://arxiv.org/abs/2108.13989), [Anjum OpTC analysis SACMAT'21](https://arxiv.org/abs/2103.03080).

---

## 3. ATLAS (multi-host attack scenarios)

| Paper | Label | Features | Leakage | Balance | Split | Threshold | Model |
|---|---|---|---|---|---|---|---|
| **ATLAS** (Alsaheel, USENIX'21) | Per-sequence (attack vs non-attack symbol sequences); ground-truth from authors' attack scripts | Lemmatized event sequences; entity types abstracted (file→FILE, IP→IP_EXT/IP_INT). Path/IP literal stripping is core to the method | **Explicit abstraction** of IPs and paths to symbol classes — closest to a leakage-drop in this domain | Negative sequences mined from non-attack lineages | Per-scenario leave-one-out across 10 scenarios | LSTM softmax | BiLSTM | F1 ~0.95 |

ATLAS is unusually explicit about replacing identifiers with type symbols before learning — strong precedent for the thesis's "no_st honest" model.

Source: [ATLAS](https://www.usenix.org/system/files/sec21-alsaheel.pdf).

---

## 4. StreamSpot / Wget (Unicorn benchmarks)

| Paper | Label | Features | Leakage | Balance | Split | Model | Headline |
|---|---|---|---|---|---|---|---|
| **StreamSpot** (Manzoor, KDD'16) | Per-graph (100 attack + 500 benign across 6 scenarios) | Shingle hashing over k-hop subgraphs | Type-vocab only | 5:1 ratio kept | 5-fold CV per scenario | Clustering | Acc ~0.98 |
| **Unicorn / Wget** | Per-graph snapshot benign vs attack | WL graph sketch | Type-vocab only | One-class | Holdout | k-means | F1 ~0.95 |
| **MAGIC on StreamSpot/Wget** | Per-graph | Masked reconstruction loss | Type-vocab only | Self-sup | 75/25 random | MaskedAE+KMeans | AUC 0.999 |

Pattern: small balanced corpora; type-vocab embeddings; random splits acceptable because each graph is independent.

Source: [Manzoor KDD'16](https://dl.acm.org/doi/10.1145/2939672.2939783).

---

## 5. TON_IoT (host telemetry — Linux/Windows audit)

| Paper | Label | Features | Leakage | Balance | Split | Model | Headline |
|---|---|---|---|---|---|---|---|
| **Alsaedi et al.** (TON_IoT telemetry, IEEE Access vol 8, 2020) | **Timestamp + IP-tag joining** of attack timeline to events (attacker IPs 192.168.159.30-39) | Disk/CPU/memory/process counters from atop logs; ~30 numeric features | **IP and timestamp explicitly used to label, then often retained as features** — high leakage risk; not ablated | Random downsample to balance | Random 70/30 | RF, XGBoost, DNN | Acc 0.99 binary, 0.87 multi-class |
| **Booij et al.** (TON_IoT heterogeneity, IEEE IoT Journal 2021) | Same labeling approach | Heterogeneity-focused subset selection | Same — IPs retained | n/a | 70/30 random | RF, DT | Confirms cross-source evaluation issues |
| **Linux subset eval** (Moustafa, arXiv 2010.08521) | Same | atop counters; categorical encoded | Same — IPs retained; some papers report IP as top feature, indicating likely leakage | SMOTE | 70/30 random | SVM/RF/DT | Acc 0.99 |

**Pattern (TON_IoT):** the canonical evaluation papers **do not drop the labelling-IP**, and tree models often select that IP as top feature. Recent critique papers (Engelen 2021 et al., already cited prior) flag this as label leakage — directly analogous to the BOTSv2 sourcetype concern.

Sources: [Alsaedi et al. TON_IoT IEEE Access 2020](https://ieeexplore.ieee.org/document/9189760), [Booij et al. TON_IoT IEEE IoT Journal 2021](https://ieeexplore.ieee.org/document/9552869), [Moustafa Linux eval arXiv 2020](https://arxiv.org/pdf/2010.08521).

---

## 6. Other reference points

**ProvDetector** (Wang, NDSS'20): rare-path mining → PV-DM doc2vec embedding (100-d) over k=20 paths → Local Outlier Factor. Trains on benign only. Path tokens kept verbatim (potential leakage from username/host strings — not addressed). F1 0.97 on internal corpora. [link](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24167-paper.pdf)

**ProGrapher** (Yang, USENIX'23): graph2vec snapshot embedding → LSTM for sequence anomaly. Type-vocab features only. Per-engagement split. F1 0.93+ on E3. [link](https://www.usenix.org/system/files/usenixsecurity23-yang-fan.pdf)

---

## Synthesis (under 1500 words)

### Common data-handling patterns

1. **Type-vocabulary embedding dominates provenance work.** UNICORN, threaTrace, MAGIC, KAIROS, SLOT, ProGrapher all reduce nodes/edges to a small enumerated vocabulary (Process / File / Socket / FORK / EXEC / READ / …). This **inherently drops IPs, paths, PIDs, timestamps** — a leakage-defense by construction, but rarely framed as such. Papers do not ablate "what if we kept the path string"; they assume the vocab abstraction is correct.

2. **Per-engagement / per-scenario holdout = de facto temporal split.** DARPA TC and OpTC papers split by engagement number. This is temporal because each engagement is a distinct day(s). Few papers state this explicitly; even fewer compare against a stratified split to quantify domain shift (the thesis's stratified-vs-temporal contrast is unusual and valuable).

3. **One-class / benign-only training is the default for graph-level provenance.** UNICORN, threaTrace, MAGIC, KAIROS, ProvDetector, DeepTaskAPT all train on benign only and treat reconstruction error / type-prediction error / outlier distance as the score. This sidesteps the imbalance problem entirely. The thesis's **supervised binary classifier with IOC-labeled positives** is the minority approach in provenance work, but mainstream in SIEM/host-telemetry work (TON_IoT, BOTSv2 lineage).

4. **Imbalance handled by oversampling, SMOTE, or one-class.** No provenance paper uses focal loss or class weights as the primary mechanism. Supervised papers (ANUBIS, TON_IoT) use oversampling/SMOTE, which can leak structure.

5. **Threshold selection rarely justified.** Most papers use validation-tuned reconstruction threshold or 0.5 default; very few report F1-max curve or precision-targeted thresholds. The thesis's per-model F1-tuned threshold (0.310 / 0.430) with per-scenario recall breakdown is more rigorous than typical.

6. **Labels come from ground-truth attack UUID lists or IOC + time-window joins.** DARPA TC papers use the published attack-UUID files. OpTC uses the red-team timeline. TON_IoT uses (attacker IP, time window). BOTSv2 IOC-yaml labeling is most directly analogous to TON_IoT but explicitly drops the labelling identifiers (src_ip, dest_ip) — a methodological improvement.

### Methodological gaps / where BOTSv2 LightGBMXT is novel or aligned

- **Aligned:** temporal split, IOC-driven labels, drop of `src_ip` / `dest_ip` / UUID-equivalents — same hygiene as DARPA-TC type-vocab papers, but explicit rather than implicit.
- **Novel:** running a **headline + honest-ablation pair** of models (sourcetype-in vs sourcetype-out) and **publishing the AUC delta (0.9877 → 0.9135)** as evidence the routing-label is partial leakage. No surveyed paper does this for an analogous "near-label" feature. ATLAS abstracts IPs but doesn't ablate. TON_IoT keeps IPs and accepts the inflation.
- **Novel:** **per-sourcetype recall break-down** exposing pan_traffic at 1.7% and suricata at 6.4%. Provenance papers report aggregate per-engagement F1; few stratify by data source within an engagement. This stratification is a strong contribution.
- **Gap (worth borrowing):** UNICORN/MAGIC train on benign only — the thesis could add a one-class baseline (e.g., LightGBM on negatives + outlier-detector head) for direct comparison.
- **Gap:** ATLAS's symbol abstraction is even more aggressive than the no_st model. Could test a "no_st + path-tokenized" variant.

### Concrete techniques worth borrowing

1. **Per-scenario leave-one-out evaluation** (ATLAS-style): retrain dropping s400_taedonggang_apt and report — quantifies generalization to unseen campaigns. The current 64.2% recall on s400 already hints at this.
2. **Stratified-vs-temporal AUC reporting** (already done — `lgbm_xt_stratified` 0.9981 vs temporal 0.9877). Frame this explicitly as the TESSERACT-style domain-shift gauge in the thesis.
3. **Permutation importance after ablation** (FLASH-style): run permutation importance on the no_st model to confirm no other "near-label" features dominate.
4. **One-class baseline** (UNICORN/MAGIC-style): isolation-forest or LightGBM-trained-on-negatives to give a label-free reference point.
5. **Per-source recall table as a standard metric**: provenance papers should adopt this; the thesis's pan_traffic / suricata weakness disclosure is a positive example.
6. **Negative-sampling for KG-style edge classification** (ShadeWatcher): potential to enrich training with hard negatives.

### Where the BOTSv2 thesis stands relative to the literature

- More rigorous than TON_IoT-style host-telemetry papers on leakage hygiene.
- More transparent than DARPA-TC papers on threshold and per-scenario performance.
- Less powerful than self-supervised graph models (MAGIC, KAIROS) on cross-engagement generalization — but those models do not produce per-event scores in real time without GPU; the LightGBMXT live scorer (50-msg batch, 2.0s flush) is operationally simpler.
- The headline + honest-ablation pair is a methodologically distinctive contribution.

---

## Citation accuracy

Audited 2026-05-10 (`audit-260510-2230-edr-survey-citation-check.md`): ~85% citation-accurate across 13 spot-checks. Fixed two misattributions in this revision: Anjum et al. SACMAT'21 (was incorrectly attributed to "Berrueta"); Alsaedi et al. IEEE Access 2020 (was incorrectly attributed to "Booij/Moustafa"). The MAGIC "lookup embedding only" claim remains soft pending repo verification (see Unresolved Q #2).

## Unresolved questions

1. Has any provenance paper published a stratified-vs-temporal AUC delta to quantify engagement-shift? KAIROS supplementary material may; need direct PDF access (current fetch blocked).
2. Does MAGIC's lookup embedding implicitly leak via collision patterns when the attack uses unique label combinations? Worth checking original code in FDUDSDE/MAGIC repo. **(Audit flagged this claim as soft — abstract-level evidence only.)**
3. How does ANUBIS's 80/20 random split inflate metrics relative to temporal? No paper reproduces ANUBIS with temporal split.
4. Is there a peer-reviewed paper using BOTSv2 with proper leakage hygiene? Prior survey said no — confirmed in this round; no new evidence.
5. Could the thesis also drop `subject_type` / `object_type` (the type vocabulary itself) as a stress test? DARPA-TC papers treat that vocab as load-bearing; an ablation would be novel.
6. ATLAS's symbol abstraction — is there a published study quantifying what abstraction level optimizes generalization vs detection? Not surfaced.

---

Saved to: `J:\THESIS-EDR\plans\reports\research-260510-2200-edr-classifier-data-handling-survey.md`
