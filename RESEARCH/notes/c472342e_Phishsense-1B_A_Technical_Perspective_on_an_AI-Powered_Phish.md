# Phishsense-1B: A Technical Perspective on an AI-Powered Phishing Detection Model

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | SE Blake |
| **Year** | 2025 |
| **Published** | 2025-03-13 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2503.10944v1 |
| **Paper URL** | http://arxiv.org/abs/2503.10944v1 |

---

## Citation

```
SE Blake (2025). "Phishsense-1B: A Technical Perspective on an AI-Powered Phishing Detection Model". URL: http://arxiv.org/abs/2503.10944v1
```

---

## Abstract

Phishing remains one of the most persistent cybersecurity threats in the digital era. In this paper, we present Phishsense-1B—a fine-tuned variant of the meta-llama/Llama-Guard-3-1B model adapted for phishing detection and reasoning via Low-Rank Adaptation (LoRA) and the GuardReasoner finetuning methodology Liu et al. [2025]. We detail our LoRA-based fine-tuning methodology, describe the balanced dataset of phishing and benign emails, and demonstrate dramatic performance gains over the base model. Our experiments show that Phishsense-1B achieves near-perfect recall with an accuracy of 97.5% on a custom dataset and maintains robust performance (70% accuracy) on a challenging real-world dataset jov, significantly outperforming both unadapted and BERT-based detectors. Additionally, we review current state-of-the-art detection methods, compare prompt-engineering with fine-tuning approaches, and discuss potential deployment scenarios. 1

---

## Keywords/Categories

cs.CR, cs.LG

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
RA-based fine-tuning
methodology, describe the balanced dataset of phishing and benign emails, and demonstrate
dramatic performance gains over the base model. Our experiments show that Phishsense-1B
achieves near-perfect recall with an accuracy of 97.5% on a custom dataset and maintains robust
performance (70% accuracy) on a challenging real-world dataset jov, significantly outperforming both unadapted and BERT-based detectors. Additionally, we review current state-of-the-art
detection methods, compare prompt-engineering with fine-tuning approaches, and discuss potential deployment scenarios.
1
Introduction
Phishing attacks continue to impose a significant threat on digital communication and online transactions, costing organizations and individuals billions of dollars each year. According to the AntiPhishing Working Group (APWG), phishing incidents increased by over 25% in 2022 compared to
previous years, with attackers refining their methods to mimic trusted brands and deceive users
into revealing sensitive information Anti-Phishing Working Group [2022]. This alarming increase
not only highlights the ingenuity of cybercriminals but also emphasizes the critical need for more
advanced detection systems. In response, researchers and cybersecurity professionals have increasingly turned to artificial intelligence (AI) and deep learning (DL) techniques to build more accurate
and adaptable detection systems capable of identifying subtle cues in phishing attempts.
Historically, phishing detection relied on signature-based methods and blacklists, which, although useful, could not keep pace with the rapid evolution of phishing tactics. Traditional approaches often suffered from high false-positive rates and were unable to adapt to new, previously
unseen attack vectors. In contrast, the advent of deep learning has allowed for the development of
models that can automatically learn relevant features from raw data, reducing the need for manual feature engineering. Recent studies employing deep learning methods have reported striking
performance improvements.
For instance, long short-term memory (LSTM)-based models have
achieved accuracies as high as 99.1% on phishing email datasets Yang et al. [2024], demonstrating
their capability to capture temporal dependencies and subtle patterns in textual data.
In parallel, researchers have explored convolutional neural networks (CNNs) for detecting phishing URLs by focusing on character-level information.
Character-level CNN architectures have
reached detection rates of up to 98.74% for URL-based phishing detection Shweta et al. [2021].
1
arXiv:2503.10944v1 [cs.CR] 13 Mar 2025

--- Page 2 ---

These models are particularly effective because they do not rely on pre-defined features but instead
learn to extract discriminative patterns directly from the input strings. Hybrid approaches that
combine CNNs with LSTMs have also been developed, leveraging the spatial feature extraction
capabilities of CNNs along with the temp
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
*Source: arxiv | Paper ID: c472342e*
