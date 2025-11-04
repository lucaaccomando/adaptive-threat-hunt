#!/usr/bin/env python3
"""Train Isolation Forest on feature CSV."""
import argparse
from pathlib import Path
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

NUMERIC = ["pkt_count","bytes","duration_ms","avg_pkt_size","iat_mean_ms","iat_std_ms","payload_entropy","proto"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=str, default="data/features.csv")
    ap.add_argument("--model", type=str, default="models/model.pkl")
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    X = df[NUMERIC].fillna(0.0)

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    out = Path(args.model)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out)
    print(f"[ok] saved model to {out}")

if __name__ == "__main__":
    main()