# 🕵️‍♂️ Adaptive Threat Hunt

### Machine Learning–Driven Network Anomaly Detection

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.5-orange?logo=scikitlearn)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)
![Dataset](https://img.shields.io/badge/Dataset-NSL--KDD-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

Adaptive Threat Hunt is a cybersecurity research project that captures, analyzes, and detects anomalous network traffic using **Python**, **Scapy**, **Scikit-learn**, and **Flask** — containerized with **Docker** for reproducible deployment.

The project benchmarks three unsupervised anomaly detection models on the **NSL-KDD** intrusion detection dataset and surfaces results through an interactive Flask dashboard.

---

## 📊 Benchmark Results (NSL-KDD)

| Model | F1 | Precision | Recall | Accuracy | ROC-AUC | Train Time |
|---|---|---|---|---|---|---|
| Isolation Forest | 0.4476 | **0.9535** | 0.2924 | 0.5891 | **0.8701** | 1.4s |
| Local Outlier Factor | **0.6245** | 0.7464 | **0.5369** | **0.6325** | 0.6834 | 16.7s |
| One-Class SVM | 0.4191 | 0.8276 | 0.2806 | 0.5572 | 0.7764 | 1.7s |

🏆 **Best F1:** Local Outlier Factor · 🎯 **Best ROC-AUC:** Isolation Forest

> Full methodology and interpretation → [`RESULTS.md`](RESULTS.md)

To reproduce:
```bash
python models/evaluate.py
```

---

## 🚀 Features

- Real-time or `.pcap`-based network traffic analysis
- Automatic feature extraction (packet size, entropy, inter-arrival time, flow stats)
- Multi-model anomaly detection: **Isolation Forest**, **Local Outlier Factor**, **One-Class SVM**
- Model evaluation pipeline with precision / recall / F1 / ROC-AUC benchmarking on NSL-KDD
- Flask dashboard for live visualization and model comparison
- Fully containerized environment for reproducible deployment

---

## 🧠 Tech Stack

| Layer | Technology |
|--------|-------------|
| Language | Python 3.12 |
| Framework | Flask 3.0 |
| Network Capture | Scapy / tcpdump |
| ML & Analytics | Scikit-learn, Pandas, NumPy |
| Containerization | Docker & Docker Compose |
| Dataset | NSL-KDD (UNB) |

---

## 🧩 Project Structure

```
adaptive-threat-hunt/
┣ dashboard/              # Flask web interface
┣ feature_extractor/      # Packet feature extraction (Scapy)
┣ models/
┃  ┣ evaluate.py          # Multi-model benchmark on NSL-KDD
┃  ┣ train.py             # Train a selected model (IF / LOF / OCSVM)
┃  ┗ score.py             # Score new traffic against a trained model
┣ results/
┃  ┗ benchmark.json       # Saved benchmark metrics
┣ data/                   # Sample pcap files
┣ Dockerfile
┣ docker-compose.yml
┣ requirements.txt
┣ RESULTS.md              # Full benchmark analysis
┗ README.md
```

---

## ⚙️ Installation and Usage

### 1️⃣ Clone the repository

```bash
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
```

### 2️⃣ Create a virtual environment and install dependencies

```bash
python -m venv .venv
source .venv/Scripts/activate   # Windows (Git Bash)
# or: source .venv/bin/activate  # macOS / Linux
python -m pip install -r requirements.txt
```

### 3️⃣ Run the multi-model benchmark

```bash
python models/evaluate.py
```

NSL-KDD is auto-downloaded on first run (~1MB). Results are saved to `results/benchmark.json`.

### 4️⃣ Train a specific model

```bash
python models/train.py --model-type isolation_forest   # or: lof, ocsvm
```

### 5️⃣ Launch the Flask dashboard

```bash
python dashboard/app.py
```

Then open: 👉 **http://localhost:5000**

### 6️⃣ (Optional) Run via Docker

```bash
docker build -t adaptive-threat-hunt .
docker run -p 5000:5000 adaptive-threat-hunt
```

For live packet capture (requires elevated permissions):

```bash
sudo docker run --network host --cap-add=NET_ADMIN --cap-add=NET_RAW adaptive-threat-hunt
```

---

## 🧰 Notes

### File Paths
All scripts use relative paths. If you see absolute paths like `/home/user/...`, replace with:
```python
import os
BASE_DIR = os.path.dirname(__file__)
pcap_path = os.path.join(BASE_DIR, '../data/example.pcap')
```

### Model Files
If `model.pkl` is missing, regenerate with:
```bash
python models/train.py --model-type isolation_forest
```

---

## 💡 Future Improvements

- Threshold tuning with precision-recall curve analysis
- Semi-supervised model (XGBoost / Random Forest) for improved recall
- ELK stack integration for security event visualization
- Live alerting via webhooks or email notifications
- Jupyter notebook with exploratory analysis and feature visualizations
- Expanded feature engineering for encrypted traffic

---

## 📜 License

MIT License © 2025 Luca Accomando

---

## 🤝 Acknowledgements

Developed as part of a cybersecurity research project exploring adaptive machine-learning approaches for intrusion detection.

Dataset: [NSL-KDD — University of New Brunswick](https://www.unb.ca/cic/datasets/nsl.html)
