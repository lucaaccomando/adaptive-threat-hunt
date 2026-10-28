#!/usr/bin/env bash
# runs the whole study from a fresh clone: tests, NSL-KDD benchmarks and ablations, leave-one-out, detection map,
# hybrid, pitfalls table. on my laptop the six benchmarks took about 35 minutes and leave-one-out about 80.
# --with-cic adds the CIC-IDS2017 study; it downloads 344 MB (sha256 checked) and needs plenty of memory (the prepared array alone is 926 MB).
#
# usage:
#   bash scripts/run_all.sh
#   bash scripts/run_all.sh --with-cic
set -euo pipefail
cd "$(dirname "$0")/.."

with_cic=0
for arg in "$@"; do
  case "$arg" in
    --with-cic) with_cic=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
else
  source .venv/Scripts/activate
fi

python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt

python -m pytest -q

python models/evaluate.py
python models/evaluate.py --train-on normal
python models/evaluate.py --categorical onehot
python models/evaluate.py --train-on normal --categorical onehot
python models/evaluate.py --transform log1p
python models/evaluate.py --tune

python models/leave_one_out.py
python models/detection_map.py
python models/hybrid.py

if [ "$with_cic" -eq 1 ]; then
  for tfm in none slog1p; do
    python models/cicids2017.py benchmark --transform "$tfm"
    python models/cicids2017.py benchmark --transform "$tfm" --train-on normal
    python models/cicids2017.py leave-one-out --transform "$tfm"
    python models/cicids2017.py map --transform "$tfm"
  done
fi

python models/pitfalls.py
python models/feature_analysis.py
