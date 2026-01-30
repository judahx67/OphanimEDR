# Binary Anomaly Detection in Streaming IoT Traffic under Concept Drift

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Rodrigo Matos Carnier, Laura Lahesoo, Kensuke Fukuda |
| **Year** | 2025 |
| **Published** | 2025-10-31 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2510.27304v1 |
| **Paper URL** | http://arxiv.org/abs/2510.27304v1 |

---

## Citation

```
Rodrigo Matos Carnier, Laura Lahesoo, Kensuke Fukuda (2025). "Binary Anomaly Detection in Streaming IoT Traffic under Concept Drift". URL: http://arxiv.org/abs/2510.27304v1
```

---

## Abstract

With the growing volume of Internet of Things (IoT) network traffic, machine learning (ML)-based anomaly detection is more relevant than ever. Traditional batch learning models face challenges such as high maintenance and poor adaptability to rapid anomaly changes, known as concept drift. In contrast, streaming learning integrates online and incremental learning, enabling seamless updates and concept drift detection to improve robustness. This study investigates anomaly detection in streaming IoT traffic as binary classification, comparing batch and streaming learning approaches while assessing the limitations of current IoT traffic datasets. We simulated heterogeneous network data streams by carefully mixing existing datasets and streaming the samples one by one. Our results highlight the failure of batch models to handle concept drift, but also reveal persisting limitations of current datasets to expose model limitations due to low traffic heterogeneity. We also investigated the competitiveness of tree-based ML algorithms, well-known in batch anomaly detection, and compared it to non-tree-based ones, confirming the advantages of the former. Adaptive Random Forest achieved F1-score of 0.990 $\pm$ 0.006 at one-third the computational cost of its batch counterpart. Hoeffding Adaptive Tree reached F1-score of 0.910 $\pm$ 0.007, reducing computational cost by four times, making it a viable choice for online applications despite a slight trade-off in stability.

---

## Keywords/Categories

cs.LG, cs.CR

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
itional batch learning
models face challenges such as high maintenance and poor
adaptability to rapid anomaly changes, known as concept drift.
In contrast, streaming learning integrates online and incremental
learning, enabling seamless updates and concept drift detection
to improve robustness. This study investigates anomaly detection
in streaming IoT traffic as binary classification, comparing batch
and streaming learning approaches while assessing the limitations
of current IoT traffic datasets. We simulated heterogeneous
network data streams by carefully mixing existing datasets
and streaming the samples one by one. Our results highlight
the failure of batch models to handle concept drift, but also
reveal persisting limitations of current datasets to expose model
limitations due to low traffic heterogeneity. We also investigated
the competitiveness of tree-based ML algorithms, well-known
in batch anomaly detection, and compared it to non-tree-based
ones, confirming the advantages of the former. Adaptive Random
Forest achieved F1-score of 0.990 ± 0.006 at one-third the computational cost of its batch counterpart. Hoeffding Adaptive Tree
reached F1-score of 0.910 ± 0.007, reducing computational cost
by four times, making it a viable choice for online applications
despite a slight trade-off in stability.
Index Terms—anomaly detection, internet of things, data
streams.
I. INTRODUCTION
For decades, network traffic anomaly detection has relied
on ML techniques [1], [2]. Early intrusion detection systems (IDS) used heuristic or statistical methods, but after
enough computational power became available, security systems adopted ML and evolved into more generalized anomaly
detectors, identifying both malicious attacks and system failures by their traffic features.
The age of IoT has made traffic anomaly detection more
challenging by increasing the variety of devices, services,
anomaly types, and their rate of change. As more IoT devices
and services are deployed, new attack surfaces and failure
points appear, making it harder to train general ML-based
anomaly detection systems [3], [4]. Datasets quickly become
outdated due to growing traffic diversity and the fast emergence of new threats, complicating model maintenance and
the creation of updated benchmarks. Studies also highlight the
deficiencies of public IoT network traffic datasets [5].
In batch learning, the traditional ML approach, detection is
improved by preprocessing data and extracting key features
during offline training. While effective in some contexts, this
method struggles with IoT traffic because it requires retraining
models with accumulated data to address both old and new
threats. As datasets grow, model maintenance slows down.
Infrequent updates also reduce model effectiveness against
evolving attacks.
Streaming learning is a promising alternative that allows
incremental model updates without processing entire datasets,
simplifying model and dataset maintenance. It also possesses

```

---

## Relevance to EDR/Malware Detection

*[To be filled in during literature review]*

- **Key Contribution:** 
- **Methods Used:** 
- **Datasets:** 
- **Results:** 
- **Limitations:** 

---

## Notes

*[Add your notes here]*

---

*Note generated: 2026-01-30 01:18*
*Source: arxiv | Paper ID: acbc8a08*
