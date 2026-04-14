#!/usr/bin/env python3
"""
train.py — Train an anomaly-detection model on a feature CSV
=============================================================
Supports three model types selectable via --model-type:

  isolation_forest  (default) — fast, works well at scale
  lof               — Local Outlier Factor (novelty mode)
  ocsvm             — One-Class SVM (slower; auto-subsamples large sets)

The trained model is serialised with joblib alongside a small
metadata sidecar (<model>.meta.json) for reproducibility.

Usage
-----
    python models/train.py
    python models/train.py --model-type lof --out models/lof.pkl
    python models/train.py --csv data/features.csv --contamination 0.05
"""

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

# ---------------------------------------------------------------------------
# Feature columns expected in the input CSV (produced by feature_extractor)
# ---------------------------------------------------------------------------
NUMERIC = [
    "pkt_count", "bytes", "duration_ms", "avg_pkt_size",
    "iat_mean_ms", "iat_std_ms", "payload_entropy", "proto",
]


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_isolation_forest(contamination: float) -> IsolationForest:
    return IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )


def build_lof(contamination: float) -> LocalOutlierFactor:
    # novelty=True is REQUIRED to call .predict() on unseen data
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
    "lof":              build_lof,
    "ocsvm":            build_ocsvm,
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Train an anomaly-detection model on a features CSV"
    )
    ap.add_argument("--csv",          default="data/features.csv",
                    help="Input features CSV")
    ap.add_argument("--model",        default="models/model.pkl",
                    help="Output model .pkl path")
    ap.add_argument("--model-type",   default="isolation_forest",
                    choices=list(MODEL_BUILDERS),
                    help="Algorithm to train (default: isolation_forest)")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="Expected fraction of anomalies (default: 0.1)")
    ap.add_argument("--scale",        action="store_true",
                    help="StandardScaler-normalise features before training")
    args = ap.parse_args()

    csv_path   = Path(args.csv)
    model_path = Path(args.model)

    if not csv_path.exists():
        raise SystemExit(f"[err] CSV not found: {csv_path}")

    # --- Load features -------------------------------------------------------
    df = pd.read_csv(csv_path)
    missing = [c for c in NUMERIC if c not in df.columns]
    if missing:
        raise SystemExit(f"[err] CSV missing columns: {missing}")

    X = df[NUMERIC].fillna(0.0).values.astype(float)
    print(f"[ok] loaded {len(X):,} rows × {X.shape[1]} features from {csv_path}")

    # --- Optional scaling ----------------------------------------------------
    scaler = None
    if args.scale or args.model_type == "ocsvm":
        scaler = StandardScaler()
        X = scaler.fit_transform(X)
        print("[ok] features normalised with StandardScaler")

    # OC-SVM: subsample if needed for speed
    if args.model_type == "ocsvm" and len(X) > 15_000:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X), 15_000, replace=False)
        X = X[idx]
        print(f"[ok] OC-SVM: subsampled to 15,000 rows for tractable training")

    # --- Train ---------------------------------------------------------------
    builder = MODEL_BUILDERS[args.model_type]
    clf     = builder(args.contamination)
    print(f"[training] {args.model_type}  (contamination={args.contamination}) …")
    t0 = time.time()
    clf.fit(X)
    elapsed = round(time.time() - t0, 3)
    print(f"[ok] training complete in {elapsed}s")

    # --- Persist model + metadata -------------------------------------------
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "scaler": scaler, "features": NUMERIC}, model_path)
    print(f"[ok] model saved → {model_path}")

    meta = {
        "model_type":    args.model_type,
        "contamination": args.contamination,
        "scaled":        scaler is not None,
        "features":      NUMERIC,
        "train_rows":    len(df),
        "train_time_s":  elapsed,
    }
    meta_path = model_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"[ok] metadata saved → {meta_path}")


if __name__ == "__main__":
    main()