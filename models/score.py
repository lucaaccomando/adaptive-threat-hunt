import argparse
import pandas as pd
import joblib
from pathlib import Path


FEATURE_COLS = [
    "pkt_count",
    "bytes",
    "duration_ms",
    "avg_pkt_size",
    "iat_mean_ms",
    "iat_std_ms",
    "payload_entropy",
    "proto",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Score flows for anomalies")
    parser.add_argument("--csv", required=True, help="Input features CSV")
    parser.add_argument("--model", required=True, help="Trained model .pkl")
    parser.add_argument("--out", required=True, help="Output scored CSV")
    args = parser.parse_args()

    in_path = Path(args.csv)
    model_path = Path(args.model)
    out_path = Path(args.out)

    if not in_path.exists():
        raise SystemExit(f"[err] input CSV not found: {in_path}")

    if not model_path.exists():
        raise SystemExit(f"[err] model file not found: {model_path}")

    print(f"[ok] loading data from {in_path}")
    df = pd.read_csv(in_path)

    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        raise SystemExit(f"[err] CSV is missing columns: {missing}")

    X = df[FEATURE_COLS].values

    print(f"[ok] loading model from {model_path}")
    model = joblib.load(model_path)

    # decision_function: higher = more normal. We invert so higher = more anomalous.
    scores = model.decision_function(X)
    preds = model.predict(X)  # 1 = normal, -1 = anomaly

    df["anomaly_score"] = -scores
    df["is_anomaly"] = (preds == -1).astype(int)

    # sort: most suspicious first
    df_sorted = df.sort_values("anomaly_score", ascending=False)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    df_sorted.to_csv(out_path, index=False)

    print(f"[ok] wrote scored flows to {out_path}")


if __name__ == "__main__":
    main()
