# Adaptive Dual-Layer Web Application Firewall (ADL-WAF) Leveraging Machine Learning for Enhanced Anomaly and Threat Detection

## Metadata

| Field | Value |
|-------|-------|
| **Authors** | Ahmed Sameh, Sahar Selim |
| **Year** | 2025 |
| **Published** | 2025-11-16 |
| **Source** | arxiv |
| **Citations** | 0 |
| **PDF URL** | https://arxiv.org/pdf/2511.12643v1 |
| **Paper URL** | http://arxiv.org/abs/2511.12643v1 |

---

## Citation

```
Ahmed Sameh, Sahar Selim (2025). "Adaptive Dual-Layer Web Application Firewall (ADL-WAF) Leveraging Machine Learning for Enhanced Anomaly and Threat Detection". URL: http://arxiv.org/abs/2511.12643v1
```

---

## Abstract

—Web Application Firewalls are crucial for protecting web applications against a wide range of cyber threats. Traditional Web Application Firewalls (WAFs) often struggle to effectively distinguish between malicious and legitimate traffic, leading to limited efficacy in threat detection. To overcome these limitations, this paper proposes an Adaptive Dual-Layer WAF (ADL-WAF) employing a two-layered Machine Learning (ML) model designed to enhance the accuracy of anomaly and threat detection. The first layer employs a Decision Tree (DT) algorithm to detect anomalies by identifying traffic deviations from established normal patterns. The second layer employs Support Vector Machine (SVM) to classify these anomalies as either threat anomalies or benign anomalies. Our “Adaptive Dual-Layer WAF (ADL-WAF)” incorporates comprehensive data pre-processing and feature engineering techniques and has been thoroughly evaluated using five large benchmark datasets. Evaluation using these datasets shows that ADL-WAF achieves a detection accuracy of 99.88% and a precision of 100%, significantly enhancing anomaly detection and reducing false positives. These findings suggest that integrating machine learning techniques into WAFs can substantially improve web application security by providing more accurate and efficient threat detection. Keywords-Web Application Firewall (WAF), Machine Learning (ML), Decision Tree (DT), Support Vector Machines (SVM), Anomaly Detection, Threat Detection, Datasets.

---

## Keywords/Categories

cs.CR, cs.LG, cs.NI

---

## Content Preview

> The following is extracted from the paper PDF. This is raw extracted text, not a summary.

```
often struggle to effectively
distinguish between malicious and legitimate traffic, leading to
limited efficacy in threat detection. To overcome these limitations,
this paper proposes an Adaptive Dual-Layer WAF (ADL-WAF)
employing a two-layered Machine Learning (ML) model designed to
enhance the accuracy of anomaly and threat detection. The first
layer employs a Decision Tree (DT) algorithm to detect anomalies by
identifying traffic deviations from established normal patterns. The
second layer employs Support Vector Machine (SVM) to classify
these anomalies as either threat anomalies or benign anomalies. Our
“Adaptive
Dual-Layer
WAF
(ADL-WAF)”
incorporates
comprehensive data pre-processing and feature engineering
techniques and has been thoroughly evaluated using five large
benchmark datasets. Evaluation using these datasets shows that
ADL-WAF achieves a detection accuracy of 99.88% and a precision
of 100%, significantly enhancing anomaly detection and reducing
false positives. These findings suggest that integrating machine
learning techniques into WAFs can substantially improve web
application security by providing more accurate and efficient threat
detection.
Keywords-Web Application Firewall (WAF), Machine Learning
(ML), Decision Tree (DT), Support Vector Machines (SVM),
Anomaly Detection, Threat Detection, Datasets.

1. INTRODUCTION
The widespread adoption and critical importance of web
applications have made them prime targets for an increasing
number of cyberattacks. Traditional Web Application Firewalls
[1], however, are developed to protect these applications via
inspecting and controlling HTTP traffic. They mainly use
Application Learning (AL) to learn normal user behavior and
identify suspicious ones. Despite their popularity among
organizations, traditional WAFs exhibit several shortcomings
that hinder their effectiveness. Some of these include high false
positive rates, time-consuming fine-tuning processes, and a
static nature in responding to changes in threats and the
behavior of the applications.
The essence of the traditional WAF functionality is in the
possibility of generating profiles based on traffic analysis.
Nevertheless, this approach has some inherent drawbacks.
Manually validating these profiles prior to deployment is both
time-consuming and labor-intensive. Also, there are risks
connected to the learning phases’ imperfection or incorrectness:
fluctuations in legitimate traffic may be recognized as threats,
while real threats may be deemed benign. These are some of the
problems that require web application security to be more
dynamic and self-aware.
This study introduces an Adaptive Dual-Layer Web
Application Firewall (ADL-WAF) that leverages machine
learning to enhance the detection and categorization
capabilities of traditional WAFs. The proposed system
comprises two distinct layers: an Anomaly Detection Layer,
which utilizes Decision Tree (DT) algorithms to identify
deviations from normal traffic patterns, effectively
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
*Source: arxiv | Paper ID: dd20b366*
