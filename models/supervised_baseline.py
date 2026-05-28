#!/usr/bin/env python3
# trains a supervised random forest on NSL-KDD as a baseline to compare against the unsupervised models
# the point isn't that supervised wins (it will) - it's to see how close we get without labels
#
# usage:
#   python models/supervised_baseline.py
#   python models/supervised_baseline.py --out results/benchmark.json

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# import from evaluate.py so we don't have to copy all that data loading code
sys.path.insert(0, str(Path(__file__).parent))
from evaluate import (
    TEST_URL,
    TRAIN_URL,
    _metrics,
    download_if_missing,
    engineer_features,
    load_nslkdd,
)


def run_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> dict:
    print("\ntraining random forest...")
    t0 = time.time()
    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)
    elapsed = round(time.time() - t0, 3)

    y_pred = clf.predict(X_test)
    y_scores = clf.predict_proba(X_test)[:, 1]  # probability of being an attack

    m = _metrics(y_test, y_pred, y_scores)
    m["train_time_s"] = elapsed
    print(f"  F1={m['f1']:.4f}  Precision={m['precision']:.4f}  Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A'):.4f}")
    return m


def print_comparison(benchmark: dict, supervised: dict) -> None:
    # print a side-by-side table of supervised vs all the unsupervised models
    models = benchmark.get("models", {})
    tuning = benchmark.get("threshold_tuning", {}).get("isolation_forest", {})

    header = (f"{'Model':<38} {'F1':>7} {'Precision':>10} "
              f"{'Recall':>8} {'Accuracy':>9} {'ROC-AUC':>8}")
    width = len(header)
    sep = "-" * width

    print(f"\n{'=' * width}")
    print("  SUPERVISED vs UNSUPERVISED COMPARISON (NSL-KDD)")
    print(f"{'=' * width}")
    print(header)
    print(sep)

    def row(label: str, m: dict | None) -> None:
        if not m:
            return
        roc = f"{m['roc_auc']:.4f}" if m.get("roc_auc") else "   N/A"
        print(f"  {label:<36} {m['f1']:>7.4f} {m['precision']:>10.4f} "
              f"{m['recall']:>8.4f} {m['accuracy']:>9.4f} {roc:>8}")

    row("Random Forest (supervised)", supervised)
    print(sep)
    for name, m in models.items():
        row(name, m)
    if tuning.get("max_f1"):
        row("Isolation Forest (tuned F1)", tuning["max_f1"])
    print("=" * width)

    # show how much of the supervised performance gap the unsupervised model closes
    best_unsup = tuning.get("max_f1") or {}
    if supervised.get("f1") and best_unsup.get("f1"):
        gap = supervised["f1"] - best_unsup["f1"]
        print(f"\n  Supervised ceiling (RF, default threshold): F1 = {supervised['f1']:.4f}")
        print(f"  Best unsupervised (IF, tuned threshold):    F1 = {best_unsup['f1']:.4f}")
        if gap > 0:
            pct = (1 - gap / supervised["f1"]) * 100
            print(f"  Gap: {gap:+.4f}  (unsupervised closes {pct:.1f}% of supervised ceiling)")
        else:
            print(f"  Gap: {gap:+.4f}  (tuned unsupervised actually beats the supervised baseline)")
            print(f"  note: RF uses a fixed 0.5 threshold - tuning it would probably close this gap")
        print()


def main() -> None:
    ap = argparse.ArgumentParser(description="supervised random forest baseline on NSL-KDD")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt")
    ap.add_argument("--test", default="", help="path to KDDTest+.txt")
    ap.add_argument("--out", default="results/benchmark.json",
                    help="benchmark.json to update (default: results/benchmark.json)")
    args = ap.parse_args()

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"

    print("=== Supervised Baseline ===\n")

    print("step 1: getting the dataset")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    print("\nstep 2: loading features")
    df_train = load_nslkdd(train_path)
    df_test = load_nslkdd(test_path)

    X_train_raw, y_train = engineer_features(df_train)
    X_test_raw, y_test = engineer_features(df_test)

    # fit scaler on training data only so there's no data leakage into the test set
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    supervised_m = run_random_forest(X_train, y_train, X_test, y_test)

    # load existing benchmark.json and add our results to it
    out_path = Path(args.out)
    benchmark: dict = {}
    if out_path.exists():
        benchmark = json.loads(out_path.read_text())

    benchmark["supervised_baseline"] = {
        "model": "RandomForestClassifier",
        "n_estimators": 200,
        "class_weight": "balanced",
        "note": "trained with binary labels - upper bound for the unsupervised models",
        "metrics": supervised_m,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(benchmark, indent=2))
    print(f"\nbenchmark updated and saved to {out_path}")

    print_comparison(benchmark, supervised_m)


if __name__ == "__main__":
    main()
