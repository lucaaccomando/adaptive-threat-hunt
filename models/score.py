#!/usr/bin/env python3
# takes a CSV of network flows and a trained model, outputs anomaly scores
# adds two columns to the CSV: anomaly_score (higher = more suspicious) and is_anomaly (0 or 1)
#
# usage:
#   python models/score.py --csv data/features.csv --model models/model.pkl --out data/scored.csv
#   python models/score.py --csv data/features.csv --model models/model.pkl --out data/scored.csv --threshold 0.15

import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from models.train import NUMERIC

FEATURE_COLS = NUMERIC


def main() -> None:
    ap = argparse.ArgumentParser(description="score network flows for anomalies")
    ap.add_argument("--csv", required=True, help="input features CSV")
    ap.add_argument("--model", required=True, help="trained model .pkl file")
    ap.add_argument("--out", required=True, help="output CSV with scores added")
    ap.add_argument("--threshold", type=float, default=None,
                    help="anomaly score cutoff (overrides model default); higher = more suspicious")
    args = ap.parse_args()

    in_path = Path(args.csv)
    model_path = Path(args.model)
    out_path = Path(args.out)

    if not in_path.exists():
        raise SystemExit(f"can't find input CSV: {in_path}")
    if not model_path.exists():
        raise SystemExit(f"can't find model file: {model_path}")

    print(f"reading data from {in_path}")
    df = pd.read_csv(in_path)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing these columns: {missing}")

    print(f"loading model from {model_path}")
    # model files use pickle; only load files you created yourself
    bundle = joblib.load(model_path)

    if isinstance(bundle, dict):
        clf = bundle["model"]
        scaler = bundle.get("scaler")
        threshold = args.threshold if args.threshold is not None else bundle.get("threshold")
    else:
        clf = bundle
        scaler = None
        threshold = args.threshold

    X = df[FEATURE_COLS].fillna(0.0).values.astype(float)
    if scaler is not None:
        X = scaler.transform(X)

    # negate so that higher score = more suspicious (models return higher = more normal)
    scores = -clf.decision_function(X)

    if threshold is not None:
        is_anomaly = (scores > threshold).astype(int)
    else:
        preds = clf.predict(X)  # +1 = normal, -1 = anomaly
        is_anomaly = (preds == -1).astype(int)

    df["anomaly_score"] = scores
    df["is_anomaly"] = is_anomaly

    df_sorted = df.sort_values("anomaly_score", ascending=False)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_sorted.to_csv(out_path, index=False)

    n_anom = int(df["is_anomaly"].sum())
    total = len(df)
    print(f"scored {total} flows, found {n_anom} anomalies ({n_anom / total * 100:.1f}%)")
    print(f"saved results to {out_path}")


if __name__ == "__main__":
    main()
