#!/usr/bin/env python3
# random forest on its own, same protocol as evaluate.py (validation-chosen threshold, several seeds)
#
# usage:
#   python models/supervised_baseline.py
#   python models/supervised_baseline.py --seeds 0 1 2

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from evaluate import main

if __name__ == "__main__":
    main(["--models", "rf", "--out", "results/supervised_baseline.json", *sys.argv[1:]])
