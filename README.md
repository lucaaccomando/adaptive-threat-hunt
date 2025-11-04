# Adaptive Network Threat Hunting & CTF Playground

Beginner-friendly starter for a portfolio-grade cybersecurity project:
capture → feature extraction → anomaly detection → alerting UI → CTF-style reproduction.

## Quickstart
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python dashboard/app.py
```
Then open http://localhost:5000

## Structure
- `dashboard/` — Flask UI to trigger feature generation and training
- `feature_extractor/` — PCAP → CSV of features
- `models/` — ML training (Isolation Forest baseline)
- `sensors/` — capture scripts (tshark/tcpdump stubs)
- `attacks/` — lab-only attack scripts to generate traffic
- `scripts/` — helper scripts (venv, run all)
- `docs/` — proposal, report
- `data/` — your pcaps/CSVs (gitignored)