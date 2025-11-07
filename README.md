# 🕵️‍♂️ Adaptive Threat Hunt  
### Machine Learning–Driven Network Anomaly Detection

Adaptive Threat Hunt is a cybersecurity research project that captures, analyzes, and detects anomalous network traffic using **Python**, **Scapy**, **Pandas**, and **Flask** — all containerized with **Docker** for easy deployment.

---

## 🚀 Features
- Real-time or `.pcap`-based network traffic analysis  
- Automatic feature extraction (packet size, entropy, inter-arrival time, etc.)  
- Machine learning–based anomaly detection  
- Flask dashboard for visualization  
- Fully containerized environment for reproducible deployment  

---

## 🧠 Tech Stack

| Layer | Technology |
|--------|-------------|
| Language | Python 3.13 |
| Framework | Flask |
| Network Capture | Scapy / tcpdump |
| ML & Analytics | Pandas, Scikit-learn |
| Containerization | Docker & Docker Compose |

---

## 🧩 Project Structure
```
adaptive-threat-hunt/
 ┣ dashboard/              # Flask web interface
 ┣ feature_extractor/      # Feature extraction scripts
 ┣ models/                 # Pretrained ML models (.pkl)
 ┣ data/                   # Sample pcap files
 ┣ Dockerfile              # Build instructions
 ┣ docker-compose.yml      # (Optional) multi-service setup
 ┣ requirements.txt
 ┗ README.md
```

---

## ⚙️ Installation and Usage

### 1️⃣ Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/adaptive-threat-hunt.git
cd adaptive-threat-hunt
```

### 2️⃣ Build the Docker image
```bash
docker build -t adaptive-threat-hunt .
```

### 3️⃣ Run the app
```bash
docker run -p 5000:5000 adaptive-threat-hunt
```

Then open your browser at:  
👉 **http://localhost:5000**

---

## ⚠️ Nota Bene (Important Notes)

### 🔒 Permissions for Packet Capture
To analyze **live traffic** (not `.pcap` files), the container must be given network privileges.  
Use:
```bash
sudo docker run --network host --cap-add=NET_ADMIN --cap-add=NET_RAW adaptive-threat-hunt
```
Alternatively, you can analyze saved `.pcap` files inside `/data/` without elevated permissions.

---

### 📁 File Paths
All scripts should use **relative paths** (already configured in this version).  
If you see an absolute path in your code like `/home/luca/...`, replace it with:
```python
import os
BASE_DIR = os.path.dirname(__file__)
pcap_path = os.path.join(BASE_DIR, '../data/example.pcap')
```

This ensures portability across systems.

---

### 🧰 Model Files
If your model file (`model.pkl`) is missing, generate it by running:
```bash
python feature_extractor/extract.py data/example.pcap
```
or use the pretrained model included in `/models/`.

---

## 🧪 Example Usage

Analyze a stored capture file:
```bash
python feature_extractor/extract.py data/example.pcap
```

View detection results on the dashboard:
```bash
python dashboard/app.py
```

---

## 🧱 Docker Compose (Optional)
You can also use Docker Compose for a single-command launch:

```yaml
version: '3.9'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host
```

Then simply run:
```bash
docker compose up --build
```

---

## 💡 Future Improvements
- Persistent database for storing anomaly logs  
- Integration with ELK stack for security visualization  
- Expanded feature set for encrypted traffic analysis  
- Live alerting through webhooks or email  

---

## 📜 License
MIT License © 2025 [Luca Accomando]

---

## 🤝 Acknowledgements
Developed as part of a cybersecurity project exploring adaptive machine-learning approaches for intrusion detection.
