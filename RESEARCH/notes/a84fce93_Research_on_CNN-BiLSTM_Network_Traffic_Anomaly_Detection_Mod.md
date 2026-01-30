# Research on CNN-BiLSTM Network Traffic Anomaly Detection Model Based on MindSpore

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Qiuyan Xiang, Shuang Wu, Dongze Wu, Yuxin Liu, Zhenkai Qin |
| **Year** | 2025 |
| **Published** | 2025-04-14 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2504.21008v1 |
| **Paper URL** | http://arxiv.org/abs/2504.21008v1 |

---

## Citation

```
Qiuyan Xiang, Shuang Wu, Dongze Wu et al. (2025). "Research on CNN-BiLSTM Network Traffic Anomaly Detection Model Based on MindSpore". URL: http://arxiv.org/abs/2504.21008v1
```

---

## Abstract

With the widespread adoption of the Internet of Things (IoT) and Industrial IoT (IIoT) technologies, network architectures have become increasingly complex, and the volume of traffic has grown substantially. This evolution poses significant challenges to traditional security mechanisms, particularly in detecting high-frequency, diverse, and highly covert network attacks. To address these challenges, this study proposes a novel network traffic anomaly detection model that integrates a Convolutional Neural Network (CNN) with a Bidirectional Long Short-Term Memory (BiLSTM) network, implemented on the MindSpore framework. Comprehensive experiments were conducted using the NF-BoT-IoT dataset. The results demonstrate that the proposed model achieves 99% across accuracy, precision, recall, and F1-score, indicating its strong performance and robustness in network intrusion detection tasks.

---

## Keywords/Categories

cs.CR, cs.AI

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
om
Zhenkai Qin
School of Information Technology
Guangxi Police College
530028,China
qinzhenkai@gxjcxy.edu.cn
ABSTRACT
With the widespread adoption of the Internet of Things (IoT) and Industrial IoT (IIoT) technologies, network architectures have become increasingly complex, and the volume of traffic has grown
substantially. This evolution poses significant challenges to traditional security mechanisms, particularly in detecting high-frequency, diverse, and highly covert network attacks. To address these
challenges, this study proposes a novel network traffic anomaly detection model that integrates a
Convolutional Neural Network (CNN) with a Bidirectional Long Short-Term Memory (BiLSTM)
network, implemented on the MindSpore framework. Comprehensive experiments were conducted
using the NF-BoT-IoT dataset. The results demonstrate that the proposed model achieves 99% across
accuracy, precision, recall, and F1-score, indicating its strong performance and robustness in network
intrusion detection tasks.
Keywords MindSpore · Convolutional Neural Network · Bidirectional Long Short-Term Memory · Network traffic
anomaly detection
1
Introduction
With the accelerated development of the Internet of Things (IoT) and Industrial Internet of Things (IIoT) technologies,
the network structure is becoming increasingly complex. Survey data shows that the number of global Internet users
has reached 5.5 billion in 2024 [1] , the number of cyber-attacks has increased by 28% year-on-year [2] , and the
scale of network traffic continues to climb, a change that poses a serious challenge to traditional security protection
mechanisms. Timely detection of these anomalies is essential to ensure quality of service, avoid financial losses and
maintain strong security standards [3] . Network traffic data usually consists of logs that summarise the communication
between network-connected devices [4] , which contain a large amount of sensitive communication content and access
patterns that, once maliciously accessed, can lead to information leakage or privilege abuse issues. In recent years,
thanks to the continuous evolution of machine learning and deep learning technologies, data-driven network traffic
anomaly detection methods have gradually become the focus of research. Among these approaches, deep learning
models—such as Convolutional Neural Networks (CNN) [5], Recurrent Neural Networks (RNNs) [6], and their hybrid
architectures—have markedly enhanced the accuracy and response efficiency of detection systems, owing to their
superior capabilities in feature extraction and temporal sequence modeling.
In this experiment, we construct a network traffic anomaly detection model using a convolutional neural network
(CNN) and a bidirectional long short-term memory network (BiLSTM) based on the MindSpore framework. First, the
NF-BoT-IoT dataset is loaded, feature pre-processed, time series reconstructed and divided into training, validation and
test sets. Then, the model structure is d
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
*Source: arxiv | Paper ID: a84fce93*
