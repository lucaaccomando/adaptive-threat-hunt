#!/usr/bin/env python3
# benchmarks three unsupervised anomaly detection models on NSL-KDD
# also tunes the isolation forest threshold and breaks down results by attack category
#
# usage:
#   python models/evaluate.py
#   python models/evaluate.py --train path/train.csv --test path/test.csv
#   python models/evaluate.py --out results/benchmark.json

import argparse
import json
import time
import urllib.request
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# all 43 column names in the NSL-KDD dataset
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

# we drop the 3 categorical columns and use these 38 numeric ones
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

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"

# maps each NSL-KDD attack name to its category (DoS, Probe, R2L, or U2R)
ATTACK_CATEGORIES: dict[str, set[str]] = {
    "DoS":   {"back", "land", "neptune", "pod", "smurf", "teardrop",
              "apache2", "udpstorm", "processtable", "mailbomb"},
    "Probe": {"satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"},
    "R2L":   {"guess_passwd", "ftp_write", "imap", "phf", "multihop",
              "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
              "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"},
    "U2R":   {"buffer_overflow", "loadmodule", "rootkit", "perl",
              "sqlattack", "xterm", "ps"},
}


def download_if_missing(url: str, dest: Path) -> None:
    if dest.exists():
        print(f"  {dest} already downloaded, skipping")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {url}")
    urllib.request.urlretrieve(url, dest)
    print(f"  saved to {dest} ({dest.stat().st_size / 1024:.1f} KB)")


def load_nslkdd(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    # convert the label to binary: 0 = normal, 1 = attack
    df["binary_label"] = (df["label"] != "normal").astype(int)
    return df


def engineer_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    # pull out just the numeric columns as a numpy array
    X = df[NUMERIC_COLS].fillna(0.0).values.astype(float)
    y = df["binary_label"].values
    return X, y


def _metrics(y_true: np.ndarray, y_pred_binary: np.ndarray,
             y_scores: np.ndarray | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred_binary).ravel()
    result = {
        "precision": round(float(precision_score(y_true, y_pred_binary, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred_binary, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred_binary, zero_division=0)), 4),
        "accuracy":  round(float((tp + tn) / len(y_true)), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }
    if y_scores is not None:
        try:
            result["roc_auc"] = round(float(roc_auc_score(y_true, y_scores)), 4)
        except ValueError:
            result["roc_auc"] = None
    return result


def run_isolation_forest(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    contamination: float = 0.1,
) -> tuple[dict, np.ndarray]:
    # also returns the raw scores so we can tune the threshold later
    print("\n[1/3] training isolation forest...")
    t0 = time.time()
    clf = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train)
    elapsed = time.time() - t0

    raw_pred = clf.predict(X_test)  # +1 = normal, -1 = anomaly
    y_pred = (raw_pred == -1).astype(int)
    scores = -clf.decision_function(X_test)  # flip so higher = more suspicious

    m = _metrics(y_test, y_pred, scores)
    m["train_time_s"] = round(elapsed, 3)
    print(f"  F1={m['f1']:.4f}  Precision={m['precision']:.4f}  Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m, scores


def run_lof(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    contamination: float = 0.1,
) -> dict:
    print("\n[2/3] training local outlier factor...")
    t0 = time.time()
    clf = LocalOutlierFactor(
        n_neighbors=20,
        contamination=contamination,
        novelty=True,  # novelty=True lets us call predict() on the test set
        n_jobs=-1,
    )
    clf.fit(X_train)
    elapsed = time.time() - t0

    raw_pred = clf.predict(X_test)
    y_pred = (raw_pred == -1).astype(int)
    scores = -clf.decision_function(X_test)

    m = _metrics(y_test, y_pred, scores)
    m["train_time_s"] = round(elapsed, 3)
    print(f"  F1={m['f1']:.4f}  Precision={m['precision']:.4f}  Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m


def run_ocsvm(
    X_train: np.ndarray, X_test: np.ndarray, y_test: np.ndarray,
    nu: float = 0.1,
) -> dict:
    print("\n[3/3] training one-class svm...")
    # ocsvm is really slow on big datasets so we only use 15k training rows
    MAX_TRAIN = 15_000
    if len(X_train) > MAX_TRAIN:
        rng = np.random.default_rng(42)
        idx = rng.choice(len(X_train), MAX_TRAIN, replace=False)
        X_tr = X_train[idx]
        print(f"  (subsampled to {MAX_TRAIN} rows so this doesn't take forever)")
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
    print(f"  F1={m['f1']:.4f}  Precision={m['precision']:.4f}  Recall={m['recall']:.4f}  ROC-AUC={m.get('roc_auc', 'N/A')}")
    return m


def attack_type_breakdown(
    labels: np.ndarray,
    y_pred: np.ndarray,
    out_path: Path,
) -> dict:
    # how well does the tuned isolation forest do on each attack category?
    breakdown: dict = {}

    for category, attack_set in ATTACK_CATEGORIES.items():
        mask = np.array([lbl in attack_set for lbl in labels])
        if not mask.any():
            continue
        total = int(mask.sum())
        detected = int(y_pred[mask].sum())
        breakdown[category] = {
            "total": total,
            "detected": detected,
            "missed": total - detected,
            "detection_rate_pct": round(detected / total * 100, 2),
        }

    # also track how often normal traffic gets falsely flagged
    normal_mask = np.array([lbl == "normal" for lbl in labels])
    if normal_mask.any():
        total_n = int(normal_mask.sum())
        fp = int(y_pred[normal_mask].sum())
        breakdown["normal"] = {
            "total": total_n,
            "correctly_classified": total_n - fp,
            "false_positives": fp,
            "false_positive_rate_pct": round(fp / total_n * 100, 2),
        }

    print_breakdown_table(breakdown)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(breakdown, indent=2))
    print(f"attack breakdown saved to {out_path}")
    return breakdown


def print_breakdown_table(breakdown: dict) -> None:
    header = (f"{'Category':<10} {'Total':>8} {'Detected':>10} "
              f"{'Missed':>8} {'Rate':>10}")
    width = len(header)
    print(f"\n{'=' * width}")
    print("  ATTACK TYPE BREAKDOWN -- Isolation Forest (tuned threshold)")
    print(f"{'=' * width}")
    print(header)
    print("-" * width)

    for cat in ("DoS", "Probe", "R2L", "U2R"):
        m = breakdown.get(cat)
        if not m:
            continue
        print(f"  {cat:<8} {m['total']:>8,} {m['detected']:>10,} "
              f"{m['missed']:>8,} {m['detection_rate_pct']:>9.1f}%")

    norm = breakdown.get("normal")
    if norm:
        print("-" * width)
        print(f"  {'normal':<8} {norm['total']:>8,} "
              f"{norm['correctly_classified']:>10,} "
              f"{norm['false_positives']:>8,} "
              f"{'FP: ' + str(norm['false_positive_rate_pct']) + '%':>10}")
    print("=" * width + "\n")


def tune_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    recall_min: float = 0.80,
) -> dict:
    # contamination=0.10 only flags the top 10% as anomalies, but the test set is ~57% attacks
    thresholds = np.unique(np.percentile(scores, np.linspace(0.5, 99.5, 500)))

    best_f1_val, best_f1_thresh = 0.0, thresholds[0]
    best_r_prec, best_r_thresh = -1.0, None

    for t in thresholds:
        yp = (scores >= t).astype(int)
        p = float(precision_score(y_true, yp, zero_division=0))
        r = float(recall_score(y_true, yp, zero_division=0))
        f = float(f1_score(y_true, yp, zero_division=0))
        if f > best_f1_val:
            best_f1_val = f
            best_f1_thresh = t
        if r >= recall_min and p > best_r_prec:
            best_r_prec = p
            best_r_thresh = t

    result: dict = {}

    yp_f1 = (scores >= best_f1_thresh).astype(int)
    m_f1 = _metrics(y_true, yp_f1)
    m_f1["threshold"] = round(float(best_f1_thresh), 6)
    result["max_f1"] = m_f1

    if best_r_thresh is not None:
        yp_r = (scores >= best_r_thresh).astype(int)
        m_r = _metrics(y_true, yp_r)
        m_r["threshold"] = round(float(best_r_thresh), 6)
        result["recall_gte_80"] = m_r
    else:
        result["recall_gte_80"] = None

    return result


def plot_pr_curve(
    y_true: np.ndarray,
    scores: np.ndarray,
    out_path: Path,
    thresh_f1: float | None = None,
    thresh_r80: float | None = None,
) -> None:
    # plot the precision-recall curve and mark our two best operating points
    precisions, recalls, _ = precision_recall_curve(y_true, scores)
    pr_auc = auc(recalls, precisions)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(recalls, precisions, color="blue", lw=2,
            label=f"Isolation Forest (PR-AUC = {pr_auc:.3f})")

    if thresh_f1 is not None:
        yp = (scores >= thresh_f1).astype(int)
        p = float(precision_score(y_true, yp, zero_division=0))
        r = float(recall_score(y_true, yp, zero_division=0))
        f = float(f1_score(y_true, yp, zero_division=0))
        ax.scatter([r], [p], color="orange", s=140, zorder=5,
                   label=f"Max-F1 point  (F1={f:.3f}, P={p:.3f}, R={r:.3f})")

    if thresh_r80 is not None:
        yp = (scores >= thresh_r80).astype(int)
        p = float(precision_score(y_true, yp, zero_division=0))
        r = float(recall_score(y_true, yp, zero_division=0))
        ax.scatter([r], [p], color="green", s=140, zorder=5,
                   label=f"Recall>=0.80 point  (P={p:.3f}, R={r:.3f})")

    # also show where the default threshold lands
    default_thresh = float(np.percentile(scores, 90))
    yp_def = (scores >= default_thresh).astype(int)
    p_def = float(precision_score(y_true, yp_def, zero_division=0))
    r_def = float(recall_score(y_true, yp_def, zero_division=0))
    ax.scatter([r_def], [p_def], color="red", s=100, marker="x", zorder=5,
               label=f"Default threshold  (P={p_def:.3f}, R={r_def:.3f})")

    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall Curve - Isolation Forest (NSL-KDD)", fontsize=13)
    ax.legend(loc="upper right", fontsize=9)
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.grid(True, alpha=0.3)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"PR curve saved to {out_path}")


def print_tuning_table(default_m: dict, tuning: dict) -> None:
    header = (f"{'Threshold setting':<32} {'F1':>7} {'Precision':>10} "
              f"{'Recall':>8} {'Accuracy':>9}")
    sep = "-" * len(header)
    print(f"\n{'=' * len(header)}")
    print("  ISOLATION FOREST - THRESHOLD TUNING (NSL-KDD)")
    print(f"{'=' * len(header)}")
    print(header)
    print(sep)

    def row(label: str, m: dict | None) -> None:
        if m is None:
            print(f"  {label:<30} {'N/A':>7}")
            return
        print(f"  {label:<30} {m['f1']:>7.4f} {m['precision']:>10.4f} "
              f"{m['recall']:>8.4f} {m['accuracy']:>9.4f}")

    row("Default (contamination=0.10)", default_m)
    row("Tuned - max F1", tuning.get("max_f1"))
    row("Tuned - recall >= 0.80", tuning.get("recall_gte_80"))
    print(f"{'=' * len(header)}")

    max_f1 = tuning.get("max_f1")
    if max_f1:
        delta = max_f1["f1"] - default_m["f1"]
        print(f"\n  F1 improvement from tuning: +{delta:.4f}  ({default_m['f1']:.4f} -> {max_f1['f1']:.4f})\n")


def print_table(results: dict) -> None:
    header = f"{'Model':<28} {'F1':>7} {'Precision':>10} {'Recall':>8} {'Accuracy':>9} {'ROC-AUC':>8} {'Train(s)':>9}"
    sep = "-" * len(header)
    print(f"\n{'=' * len(header)}")
    print("  BENCHMARK RESULTS - NSL-KDD dataset")
    print(f"{'=' * len(header)}")
    print(header)
    print(sep)
    for name, m in results["models"].items():
        roc = f"{m.get('roc_auc', 0.0):.4f}" if m.get("roc_auc") else "  N/A  "
        print(f"{name:<28} {m['f1']:>7.4f} {m['precision']:>10.4f} "
              f"{m['recall']:>8.4f} {m['accuracy']:>9.4f} {roc:>8} {m['train_time_s']:>9.3f}")
    print(f"{'=' * len(header)}\n")

    best = max(results["models"].items(), key=lambda kv: kv[1]["f1"])
    print(f"  Best F1: {best[0]}  ({best[1]['f1']:.4f})\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="multi-model anomaly detection benchmark on NSL-KDD")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt (auto-downloaded if blank)")
    ap.add_argument("--test", default="", help="path to KDDTest+.txt (auto-downloaded if blank)")
    ap.add_argument("--out", default="results/benchmark.json", help="output JSON path")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="expected fraction of anomalies (default: 0.1)")
    args = ap.parse_args()

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"

    print("=== Adaptive Threat Hunt - Multi-Model Benchmark ===\n")

    print("step 1: getting the dataset")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    print("\nstep 2: loading and preparing features")
    df_train = load_nslkdd(train_path)
    df_test = load_nslkdd(test_path)
    test_labels = df_test["label"].values  # keep the raw label strings for the breakdown

    X_train_raw, y_train = engineer_features(df_train)
    X_test_raw, y_test = engineer_features(df_test)

    # fit the scaler on training data only so we don't leak test info
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    train_attacks = int(y_train.sum())
    test_attacks = int(y_test.sum())
    print(f"  train: {len(X_train):,} flows ({train_attacks:,} attacks, {len(X_train) - train_attacks:,} normal)")
    print(f"  test:  {len(X_test):,} flows ({test_attacks:,} attacks, {len(X_test) - test_attacks:,} normal)")
    print(f"  features: {X_train.shape[1]}")

    print("\nstep 3: training and evaluating all three models")
    if_metrics, if_scores = run_isolation_forest(X_train, X_test, y_test, args.contamination)
    results = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "n_features": X_train.shape[1],
        "contamination": args.contamination,
        "models": {
            "Isolation Forest": if_metrics,
            "Local Outlier Factor": run_lof(X_train, X_test, y_test, args.contamination),
            "One-Class SVM": run_ocsvm(X_train, X_test, y_test, nu=args.contamination),
        },
    }

    print("\nstep 4: tuning the isolation forest threshold")
    tuning = tune_threshold(y_test, if_scores)
    results["threshold_tuning"] = {"isolation_forest": tuning}

    out_path = Path(args.out)
    pr_curve_path = out_path.parent / "pr_curve_isolation_forest.png"
    thresh_f1 = (tuning.get("max_f1") or {}).get("threshold")
    thresh_r80 = (tuning.get("recall_gte_80") or {}).get("threshold")
    plot_pr_curve(y_test, if_scores, pr_curve_path, thresh_f1, thresh_r80)

    print("\nstep 5: breaking down results by attack category")
    if thresh_f1 is not None:
        y_pred_tuned = (if_scores >= thresh_f1).astype(int)
        breakdown_path = out_path.parent / "attack_breakdown.json"
        results["attack_breakdown"] = attack_type_breakdown(
            test_labels, y_pred_tuned, breakdown_path
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"benchmark saved to {out_path}")

    print_table(results)
    print_tuning_table(if_metrics, tuning)


if __name__ == "__main__":
    main()
