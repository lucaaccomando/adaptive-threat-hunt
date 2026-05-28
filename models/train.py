#!/usr/bin/env python3
# trains an anomaly detection model on a CSV of network flow features
# supports isolation forest, local outlier factor, and one-class svm
#
# usage:
#   python models/train.py
#   python models/train.py --model-type lof --model models/lof.pkl
#   python models/train.py --csv data/features.csv --contamination 0.05

import argparse
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# these are the 8 features we extract from pcap files
NUMERIC = [
    "pkt_count", "bytes", "duration_ms", "avg_pkt_size",
    "iat_mean_ms", "iat_std_ms", "payload_entropy", "proto",
]


def build_isolation_forest(contamination: float) -> IsolationForest:
    return IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )


def build_lof(contamination: float) -> LocalOutlierFactor:
    # novelty=True is required so we can call predict() on new data later
    return LocalOutlierFactor(
        n_neighbors=20,
        contamination=contamination,
        novelty=True,
        n_jobs=-1,
    )


def build_ocsvm(contamination: float) -> OneClassSVM:
    return OneClassSVM(kernel="rbf", nu=contamination, gamma="scale")


MODEL_BUILDERS = {
    "isolation_forest": build_isolation_forest,
    "lof": build_lof,
    "ocsvm": build_ocsvm,
}


def main() -> None:
    ap = argparse.ArgumentParser(description="train an anomaly detection model on a features CSV")
    ap.add_argument("--csv", default="data/features.csv", help="input features CSV")
    ap.add_argument("--model", default="models/model.pkl", help="where to save the model")
    ap.add_argument("--model-type", default="isolation_forest",
                    choices=list(MODEL_BUILDERS),
                    help="which algorithm to use (default: isolation_forest)")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="expected fraction of anomalies, between 0 and 0.5 (default: 0.1)")
    ap.add_argument("--scale", action="store_true",
                    help="normalize features with StandardScaler before training")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    model_path = Path(args.model)

    if not csv_path.exists():
        raise SystemExit(f"can't find CSV file: {csv_path}")

    df = pd.read_csv(csv_path)
    missing = [c for c in NUMERIC if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing these columns: {missing}")

    X = df[NUMERIC].fillna(0.0).values.astype(float)
    print(f"loaded {len(X)} rows with {X.shape[1]} features from {csv_path}")

    # scale features if asked, or if using ocsvm (which needs it)
    scaler = None
    if args.scale or args.model_type == "ocsvm":
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
        print("scaled features with StandardScaler")

    # ocsvm is really slow on large datasets so we subsample down to 15k rows
    if args.model_type == "ocsvm" and len(X) > 15_000:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), 15_000, replace=False)
        X = X[idx]
        print("subsampled down to 15000 rows so ocsvm doesn't take forever")

    builder = MODEL_BUILDERS[args.model_type]
    clf = builder(args.contamination)
    print(f"training {args.model_type} (contamination={args.contamination})...")
    t0 = time.time()
    clf.fit(X)
    elapsed = round(time.time() - t0, 3)
    print(f"done! took {elapsed}s")

    # save the model and scaler together in one file so scoring works later
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "scaler": scaler, "features": NUMERIC}, model_path)
    print(f"model saved to {model_path}")

    meta = {
        "model_type": args.model_type,
        "contamination": args.contamination,
        "scaled": scaler is not None,
        "features": NUMERIC,
        "train_rows": len(df),
        "train_time_s": elapsed,
    }
    meta_path = model_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"metadata saved to {meta_path}")


if __name__ == "__main__":
    main()
