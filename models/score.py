#!/usr/bin/env python3
"""
score.py — Score network flows for anomalies
=============================================
Loads a model bundle produced by train.py (which may include a fitted
StandardScaler) and assigns each flow an anomaly score + binary label.

Output columns added to the CSV:
  anomaly_score   float   higher = more suspicious
  is_anomaly      int     1 = anomaly, 0 = normal

Usage
-----
    python models/score.py --csv data/features.csv \
                           --model models/model.pkl \
                           --out data/scored.csv
"""

import argparse
from pathlib import Path

import joblib
import pandas as pd

FEATURE_COLS = [
    "pkt_count", "bytes", "duration_ms", "avg_pkt_size",
    "iat_mean_ms", "iat_std_ms", "payload_entropy", "proto",
]


def main() -> None:
    ap = argparse.ArgumentParser(description="Score flows for anomalies")
    ap.add_argument("--csv",   required=True, help="Input features CSV")
    ap.add_argument("--model", required=True, help="Trained model .pkl")
    ap.add_argument("--out",   required=True, help="Output scored CSV")
    args = ap.parse_args()

    in_path    = Path(args.csv)
    model_path = Path(args.model)
    out_path   = Path(args.out)

    if not in_path.exists():
        raise SystemExit(f"[err] input CSV not found: {in_path}")
    if not model_path.exists():
        raise SystemExit(f"[err] model file not found: {model_path}")

    # --- Load ----------------------------------------------------------------
    print(f"[ok] loading data from {in_path}")
    df = pd.read_csv(in_path)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise SystemExit(f"[err] CSV is missing columns: {missing}")

    print(f"[ok] loading model from {model_path}")
    bundle = joblib.load(model_path)

    # Support both old format (bare model) and new format (dict bundle)
    if isinstance(bundle, dict):
        clf    = bundle["model"]
        scaler = bundle.get("scaler")
    else:
        clf    = bundle
        scaler = None

    # --- Prepare features ----------------------------------------------------
    X = df[FEATURE_COLS].fillna(0.0).values.astype(float)
    if scaler is not None:
        X = scaler.transform(X)

    # --- Score ---------------------------------------------------------------
    # decision_function: higher = more normal → invert so higher = more anomalous
    scores = -clf.decision_function(X)
    preds  = clf.predict(X)          # +1 normal, -1 anomaly

    df["anomaly_score"] = scores
    df["is_anomaly"]    = (preds == -1).astype(int)

    # Sort most suspicious first
    df_sorted = df.sort_values("anomaly_score", ascending=False)

    # --- Save ----------------------------------------------------------------
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_sorted.to_csv(out_path, index=False)

    n_anom = int(df["is_anomaly"].sum())
    total  = len(df)
    print(f"[ok] scored {total:,} flows → {n_anom:,} anomalies "
          f"({n_anom/total*100:.1f}%)")
    print(f"[ok] wrote scored flows → {out_path}")


if __name__ == "__main__":
    main()