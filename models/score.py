#!/usr/bin/env python3
# takes a CSV of network flows and a trained model, outputs anomaly scores
# adds two columns to the CSV: anomaly_score (higher = more suspicious) and is_anomaly (0 or 1)
#
# usage:
#   python models/score.py --csv data/features.csv --model models/model.pkl --out data/scored.csv

import argparse
from pathlib import Path

import joblib
import pandas as pd

# must match NUMERIC in train.py exactly
FEATURE_COLS = [
    "pkt_count", "bytes", "duration_ms", "avg_pkt_size",
    "iat_mean_ms", "iat_std_ms", "payload_entropy", "proto",
]


def main() -> None:
    ap = argparse.ArgumentParser(description="score network flows for anomalies")
    ap.add_argument("--csv", required=True, help="input features CSV")
    ap.add_argument("--model", required=True, help="trained model .pkl file")
    ap.add_argument("--out", required=True, help="output CSV with scores added")
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
    bundle = joblib.load(model_path)

    # handle both old format (just the model) and new format (dict with scaler)
    if isinstance(bundle, dict):
        clf = bundle["model"]
        scaler = bundle.get("scaler")
    else:
        clf = bundle
        scaler = None

    X = df[FEATURE_COLS].fillna(0.0).values.astype(float)
    if scaler is not None:
        X = scaler.transform(X)

    # negate so that higher score = more suspicious (models return higher = more normal)
    scores = -clf.decision_function(X)
    preds = clf.predict(X)  # +1 = normal, -1 = anomaly

    df["anomaly_score"] = scores
    df["is_anomaly"] = (preds == -1).astype(int)

    df_sorted = df.sort_values("anomaly_score", ascending=False)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_sorted.to_csv(out_path, index=False)

    n_anom = int(df["is_anomaly"].sum())
    total = len(df)
    print(f"scored {total} flows, found {n_anom} anomalies ({n_anom / total * 100:.1f}%)")
    print(f"saved results to {out_path}")


if __name__ == "__main__":
    main()
