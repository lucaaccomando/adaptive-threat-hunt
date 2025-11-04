#!/usr/bin/env bash
set -euo pipefail

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

python feature_extractor/extract.py
python models/train.py --csv data/features.csv --model models/model.pkl
python dashboard/app.py