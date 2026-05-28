# Adaptive Threat Hunt

### Machine Learning–Driven Network Anomaly Detection

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.5-orange?logo=scikitlearn)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)
![Dataset](https://img.shields.io/badge/Dataset-NSL--KDD-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

Captures network traffic from PCAPs or a live interface, extracts flow-level features, and scores flows with Isolation Forest, LOF, or One-Class SVM. Benchmarked on NSL-KDD against a supervised Random Forest baseline, with threshold tuning, feature importance analysis, and per-attack-category breakdown. Flask dashboard for interactive use; Docker for reproducible deployment.

---

## Benchmark Results (NSL-KDD)

| Model | Type | F1 | Precision | Recall | ROC-AUC |
|---|---|---|---|---|---|
| Isolation Forest (default) | Unsupervised | 0.4476 | **0.9535** | 0.2924 | **0.8701** |
| Isolation Forest (tuned) | Unsupervised* | **0.8375** | 0.7844 | **0.8982** | 0.8701 |
| Local Outlier Factor | Unsupervised | 0.6245 | 0.7464 | 0.5369 | 0.6834 |
| One-Class SVM | Unsupervised | 0.4191 | 0.8276 | 0.2806 | 0.7764 |
| Random Forest | Supervised | 0.7564 | 0.9688 | 0.6204 | 0.9612 |

\* Same model, threshold optimised post-hoc via precision-recall curve sweep — no labels used during training.

**Key finding:** Threshold-tuned Isolation Forest (F1=0.84) exceeds the supervised Random Forest baseline (F1=0.76) without access to any labels.

> Full methodology and interpretation → [`RESULTS.md`](RESULTS.md)

To reproduce:
```bash
python models/evaluate.py          # benchmark + threshold tuning + attack breakdown
python models/supervised_baseline.py   # supervised comparison
python models/feature_analysis.py      # importance plots + correlation heatmap
```

---

## Research Methodology

All models are evaluated on the NSL-KDD dataset (KDDTrain+ / KDDTest+) using a fixed train/test split. A `StandardScaler` is fit on the training set only and applied to both splits — no data leakage.

**Unsupervised training:** Isolation Forest, LOF, and One-Class SVM receive no labels during training. They learn the shape of the training distribution and flag test flows that deviate from it.

**Threshold tuning:** Unsupervised models produce a continuous anomaly score. The default `contamination=0.10` parameter flags the top 10% of scores as anomalies — a conservative threshold for a dataset where ~57% of test flows are attacks. We sweep 500 percentile thresholds and identify the point that maximises F1 and the best-precision point subject to recall ≥ 0.80. Results and a precision-recall curve are saved to `results/`.

**Supervised baseline:** A Random Forest classifier is trained on the binary labels using the same scaler and split. It serves as an upper bound to quantify how much discriminative power is lost by not having labels.

**Feature space:** 38 numeric columns from the 41-column NSL-KDD schema. Three categorical columns (`protocol_type`, `service`, `flag`) are dropped.

---

## Supervised Baseline Comparison

The core research question is: *how close can unsupervised detection get without labels?*

| | F1 | Notes |
|---|---|---|
| Random Forest (supervised) | 0.7564 | Trained with binary labels; default 0.5 threshold |
| Isolation Forest (tuned) | 0.8375 | No labels; threshold found via PR curve sweep |
| Gap | −0.08 | Tuned unsupervised exceeds supervised at default threshold |

The IF advantage over RF at default thresholds is largely a threshold-selection effect: both models have strong discriminative power (ROC-AUC 0.87 vs 0.96), but IF's threshold was explicitly optimised while RF's was not. A threshold-tuned RF would likely close this gap.

This suggests threshold-calibrated unsupervised models are worth considering when you don't have labelled training data or when attack patterns shift faster than you can relabel.

---

## Features

- Real-time or `.pcap`-based network traffic capture and feature extraction
- Automatic flow-level feature extraction (packet size, entropy, inter-arrival time, byte counts)
- Multi-model anomaly detection: Isolation Forest, Local Outlier Factor, One-Class SVM
- Threshold tuning via precision-recall curve sweep with configurable recall target
- Supervised baseline (Random Forest) for comparison
- Feature importance analysis and correlation heatmap
- Per-attack-category detection rates (DoS, Probe, R2L, U2R)
- Flask dashboard for live visualization
- Jupyter notebook with full research narrative (`notebooks/analysis.ipynb`)
- Fully containerized for reproducible deployment

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Framework | Flask 3.0 |
| Network Capture | Scapy / tcpdump |
| ML & Analytics | Scikit-learn, Pandas, NumPy |
| Visualization | Matplotlib |
| Notebook | Jupyter |
| Containerization | Docker & Docker Compose |
| Dataset | NSL-KDD (UNB) |

---

## Project Structure

```
adaptive-threat-hunt/
├── dashboard/              # Flask web interface
├── feature_extractor/      # Scapy-based PCAP feature extraction
├── models/
│   ├── evaluate.py         # Multi-model benchmark + threshold tuning + attack breakdown
│   ├── train.py            # Train a single model (IF / LOF / OCSVM)
│   ├── score.py            # Score new flows against a trained model
│   ├── supervised_baseline.py  # Random Forest supervised comparison
│   └── feature_analysis.py    # Feature importance + correlation heatmap
├── notebooks/
│   └── analysis.ipynb      # Full research narrative notebook
├── results/                # Generated plots and benchmark.json
├── data/nslkdd/            # NSL-KDD dataset (auto-downloaded)
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Installation and Usage

### 1. Clone the repository

```bash
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
```

### 2. Create a virtual environment and install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

### 3. Run the full benchmark

```bash
python models/evaluate.py
```

NSL-KDD is auto-downloaded on first run (~1MB). Outputs: `results/benchmark.json`, `results/pr_curve_isolation_forest.png`, `results/attack_breakdown.json`.

### 4. Run the supervised baseline and feature analysis

```bash
python models/supervised_baseline.py   # adds "supervised_baseline" to benchmark.json
python models/feature_analysis.py      # saves feature_importance.png, correlation_heatmap.png
```

### 5. Open the research notebook

```bash
.venv\Scripts\jupyter.exe notebook notebooks/analysis.ipynb
```

### 6. Train a model on custom traffic

```bash
python feature_extractor/extract.py --pcap data/capture.pcap --out data/features.csv
python models/train.py --model-type isolation_forest --csv data/features.csv
python models/score.py --csv data/features.csv --model models/model.pkl --out data/scored.csv
```

### 7. Launch the Flask dashboard

```bash
python dashboard/app.py   # http://localhost:5000
```

### 8. Run via Docker

```bash
docker-compose up --build
```

---

## Future Work

- **Threshold tuning for LOF and OC-SVM** — apply the same PR curve sweep to determine whether their default thresholds are similarly suboptimal
- **Supervised threshold tuning** — tune the RF decision threshold for a fair head-to-head comparison with threshold-tuned IF
- **Dimensionality reduction** — evaluate PCA-reduced feature sets (e.g. 15 components) given the 13 highly correlated feature pairs
- **R2L detection improvement** — the hardest attack category (59% detection rate) requires payload-level or session-aggregated features beyond flow statistics
- **Expanded feature engineering** — add features for encrypted traffic (TLS metadata, certificate fields)
- **Live alerting** — webhook or email notifications for flagged anomalies from the dashboard

---

## License

MIT License © 2025 Luca Accomando

---

## Acknowledgements

Built as a CS senior independent study.

Dataset: [NSL-KDD — University of New Brunswick](https://www.unb.ca/cic/datasets/nsl.html)
