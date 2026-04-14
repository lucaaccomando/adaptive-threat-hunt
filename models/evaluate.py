#!/usr/bin/env python3
"""
evaluate.py — Multi-model benchmark for adaptive-threat-hunt
=============================================================
Downloads NSL-KDD (KDDTrain+.txt / KDDTest+.txt) if not present,
engineers features, then trains and evaluates three unsupervised
anomaly-detection models:

  1. Isolation Forest
  2. Local Outlier Factor  (novelty=True so we can call predict on test set)
  3. One-Class SVM

Metrics saved to results/benchmark.json and printed as a table.

Usage
-----
    python models/evaluate.py                         # auto-download NSL-KDD
    python models/evaluate.py --train path/train.csv --test path/test.csv
    python models/evaluate.py --out results/benchmark.json
"""

import argparse
import json
import time
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# ---------------------------------------------------------------------------
# NSL-KDD column schema
# ---------------------------------------------------------------------------
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

NUMERIC_COLS = [
    "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# NSL-KDD download URLs (University of New Brunswick mirror)
TRAIN_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
)
TEST_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def download_if_missing(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  [cache] {dest} already present, skipping download.")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  [download] {url}")
    print(f"          -> {dest}")
    urllib.request.urlretrieve(url, dest)
    print(f"  [ok] downloaded {dest.stat().st_size / 1024:.1f} KB")


def load_nslkdd(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    # Binary label: "normal" → 0, everything else → 1 (attack)
    df["binary_label"] = (df["label"] != "normal").astype(int)
    return df


def engineer_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return (X, y) where X is the numeric feature matrix."""
    X = df[NUMERIC_COLS].fillna(0.0).values.astype(float)
    y = df["binary_label"].values
    return X, y


def _metrics(y_true: np.ndarray, y_pred_binary: np.ndarray,
             y_scores: np.ndarray | None = None) -> dict:
    """Compute precision, recall, F1, accuracy, and optionally ROC-AUC."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_binary).ravel()
    result = {
        "precision":  round(float(precision_score(y_true, y_pred_binary, zero_division=0)), 4),
        "recall":     round(float(recall_score(y_true, y_pred_binary, zero_division=0)), 4),
        "f1":         round(float(f1_score(y_true, y_pred_binary, zero_division=0)), 4),
        "accuracy":   round(float((tp + tn) / len(y_true)), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }
    if y_scores is not None:
        try:
            result["roc_auc"] = round(float(roc_auc_score(y_true, y_scores)), 4)
        except ValueError:
            result["roc_auc"] = None
    return result


# ---------------------------------------------------------------------------
# Model runners
# ---------------------------------------------------------------------------

def run_isolation_forest(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    contamination: float = 0.1,
) -> dict:
    print("\n[1/3] Training Isolation Forest …")
    t0 = time.time()
    clf = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train)
    elapsed = time.time() - t0

    raw_pred = clf.predict(X_test)       # +1 normal, -1 anomaly
    y_pred = (raw_pred == -1).astype(int)
    scores = -clf.decision_function(X_test)   # higher → more anomalous

    m = _metrics(y_test, y_pred, scores)
    m["train_time_s"] = round(elapsed, 3)
    print(f"     F1={m['f1']:.4f}  Precision={m['precision']:.4f}  "
          f"Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m


def run_lof(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    contamination: float = 0.1,
) -> dict:
    print("\n[2/3] Training Local Outlier Factor (novelty mode) …")
    t0 = time.time()
    clf = LocalOutlierFactor(
        n_neighbors=20,
        contamination=contamination,
        novelty=True,       # MUST be True to call predict on unseen data
        n_jobs=-1,
    )
    clf.fit(X_train)
    elapsed = time.time() - t0

    raw_pred = clf.predict(X_test)
    y_pred = (raw_pred == -1).astype(int)
    scores = -clf.decision_function(X_test)

    m = _metrics(y_test, y_pred, scores)
    m["train_time_s"] = round(elapsed, 3)
    print(f"     F1={m['f1']:.4f}  Precision={m['precision']:.4f}  "
          f"Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m


def run_ocsvm(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    nu: float = 0.1,
) -> dict:
    print("\n[3/3] Training One-Class SVM …")
    # OC-SVM is sensitive to scale and slow on large sets — subsample train
    MAX_TRAIN = 15_000
    if len(X_train) > MAX_TRAIN:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_train), MAX_TRAIN, replace=False)
        X_tr = X_train[idx]
        print(f"     (subsampled training set to {MAX_TRAIN} rows for speed)")
    else:
        X_tr = X_train

    t0 = time.time()
    clf = OneClassSVM(kernel="rbf", nu=nu, gamma="scale")
    clf.fit(X_tr)
    elapsed = time.time() - t0

    raw_pred = clf.predict(X_test)
    y_pred = (raw_pred == -1).astype(int)
    scores = -clf.decision_function(X_test)

    m = _metrics(y_test, y_pred, scores)
    m["train_time_s"] = round(elapsed, 3)
    print(f"     F1={m['f1']:.4f}  Precision={m['precision']:.4f}  "
          f"Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m


# ---------------------------------------------------------------------------
# Pretty-print table
# ---------------------------------------------------------------------------

def print_table(results: dict) -> None:
    header = f"{'Model':<28} {'F1':>7} {'Precision':>10} {'Recall':>8} {'Accuracy':>9} {'ROC-AUC':>8} {'Train(s)':>9}"
    sep = "-" * len(header)
    print(f"\n{'=' * len(header)}")
    print("  BENCHMARK RESULTS — NSL-KDD dataset")
    print(f"{'=' * len(header)}")
    print(header)
    print(sep)
    for name, m in results["models"].items():
        roc = f"{m.get('roc_auc', 0.0):.4f}" if m.get("roc_auc") else "  N/A  "
        print(
            f"{name:<28} {m['f1']:>7.4f} {m['precision']:>10.4f} "
            f"{m['recall']:>8.4f} {m['accuracy']:>9.4f} {roc:>8} {m['train_time_s']:>9.3f}"
        )
    print(f"{'=' * len(header)}\n")

    best = max(results["models"].items(), key=lambda kv: kv[1]["f1"])
    print(f"  🏆  Best F1: {best[0]}  ({best[1]['f1']:.4f})\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Multi-model anomaly detection benchmark on NSL-KDD")
    ap.add_argument("--train", default="", help="Path to KDDTrain+.txt (auto-downloaded if blank)")
    ap.add_argument("--test",  default="", help="Path to KDDTest+.txt  (auto-downloaded if blank)")
    ap.add_argument("--out",   default="results/benchmark.json", help="Output JSON path")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="Expected anomaly fraction (default 0.1)")
    args = ap.parse_args()

    # --- Resolve dataset paths -----------------------------------------------
    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path  = Path(args.test)  if args.test  else data_dir / "KDDTest+.txt"

    print("=== Adaptive Threat Hunt — Multi-Model Evaluator ===\n")
    print("[step 1] Acquiring NSL-KDD dataset …")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL,  test_path)

    # --- Load & engineer features --------------------------------------------
    print("\n[step 2] Loading and engineering features …")
    df_train = load_nslkdd(train_path)
    df_test  = load_nslkdd(test_path)

    X_train_raw, y_train = engineer_features(df_train)
    X_test_raw,  y_test  = engineer_features(df_test)

    # Fit scaler on TRAIN only, transform both — no data leakage
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test  = scaler.transform(X_test_raw)

    train_attacks = int(y_train.sum())
    test_attacks  = int(y_test.sum())
    print(f"  Train: {len(X_train):,} flows  ({train_attacks:,} attacks, "
          f"{len(X_train)-train_attacks:,} normal)")
    print(f"  Test:  {len(X_test):,} flows  ({test_attacks:,} attacks, "
          f"{len(X_test)-test_attacks:,} normal)")
    print(f"  Features: {X_train.shape[1]}")

    # --- Run models ----------------------------------------------------------
    print("\n[step 3] Training and evaluating models …")
    results = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "train_samples": len(X_train),
        "test_samples":  len(X_test),
        "n_features": X_train.shape[1],
        "contamination": args.contamination,
        "models": {
            "Isolation Forest": run_isolation_forest(
                X_train, X_test, y_test, args.contamination
            ),
            "Local Outlier Factor": run_lof(
                X_train, X_test, y_test, args.contamination
            ),
            "One-Class SVM": run_ocsvm(
                X_train, X_test, y_test, nu=args.contamination
            ),
        },
    }

    # --- Save results ---------------------------------------------------------
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n[ok] benchmark saved → {out_path}")

    # --- Pretty print --------------------------------------------------------
    print_table(results)


if __name__ == "__main__":
    main()