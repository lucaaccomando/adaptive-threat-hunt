#!/usr/bin/env python3
# benchmarks isolation forest, LOF, one-class svm and a random forest on NSL-KDD
# models train on 80% of KDDTrain+, the alert threshold (max F1) is picked on the other 20%
# and applied unchanged to KDDTest+; repeated over several seeds
#
# usage:
#   python models/evaluate.py
#   python models/evaluate.py --seeds 0 1 2 --models iforest rf
#   python models/evaluate.py --train-on normal      # unsupervised models fit on normal flows only
#   python models/evaluate.py --categorical onehot   # keep protocol_type, service and flag

import argparse
import json
import urllib.request
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
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

# the default feature set: these 38 numeric columns, the 3 categorical ones are dropped
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
# worm (2 test rows) is listed as DoS in the NSL-KDD tables I found; the dataset ships no mapping file
ATTACK_CATEGORIES: dict[str, set[str]] = {
    "DoS":   {"back", "land", "neptune", "pod", "smurf", "teardrop",
              "apache2", "udpstorm", "processtable", "mailbomb", "worm"},
    "Probe": {"satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"},
    "R2L":   {"guess_passwd", "ftp_write", "imap", "phf", "multihop",
              "warezmaster", "warezclient", "spy", "xlock", "xsnoop",
              "snmpguess", "snmpgetattack", "httptunnel", "sendmail", "named"},
    "U2R":   {"buffer_overflow", "loadmodule", "rootkit", "perl",
              "sqlattack", "xterm", "ps"},
}

CATEGORY_OF = {a: c for c, names in ATTACK_CATEGORIES.items() for a in names}

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

MODELS = {
    "iforest": "Isolation Forest",
    "lof": "Local Outlier Factor",
    "ocsvm": "One-Class SVM",
    "rf": "Random Forest",
}
VAL_FRACTION = 0.2
# ocsvm is too slow to fit on the full training split
OCSVM_MAX_TRAIN = 15_000
SUMMARY_METRICS = ("f1", "precision", "recall", "fpr", "accuracy")


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


def category_levels(df: pd.DataFrame) -> dict[str, list[str]]:
    return {c: sorted(df[c].unique()) for c in CATEGORICAL_COLS}


def engineer_features(df: pd.DataFrame, levels: dict[str, list[str]] | None = None
                      ) -> tuple[np.ndarray, np.ndarray]:
    # pull out just the numeric columns as a numpy array
    X = df[NUMERIC_COLS].fillna(0.0).values.astype(float)
    if levels:
        # levels come from KDDTrain+, so a test value never seen in training is all zeros
        onehot = [(df[c].values[:, None] == np.array(vals)[None, :]).astype(float)
                  for c, vals in levels.items()]
        X = np.hstack([X] + onehot)
    y = df["binary_label"].values
    return X, y


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "fpr":       round(float(fp / max(fp + tn, 1)), 4),
        "accuracy":  round(float((tp + tn) / len(y_true)), 4),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def check_categories(labels) -> None:
    missing = sorted(set(labels) - set(CATEGORY_OF) - {"normal"})
    if missing:
        raise ValueError(f"attack labels with no category: {missing}")


def attack_groups(train_labels, test_labels) -> dict[str, np.ndarray]:
    # boolean masks over the test rows; "seen" = attack type that appears anywhere in KDDTrain+
    test_labels = np.asarray(test_labels)
    is_attack = test_labels != "normal"
    seen_types = list(set(train_labels) - {"normal"})
    seen = is_attack & np.isin(test_labels, seen_types)
    groups = {"seen": seen, "unseen": is_attack & ~seen}
    for cat, names in ATTACK_CATEGORIES.items():
        groups[cat] = np.isin(test_labels, list(names))
    return groups


def build_model(key: str, seed: int, contamination: float):
    if key == "iforest":
        return IsolationForest(n_estimators=200, contamination=contamination,
                               random_state=seed, n_jobs=-1)
    if key == "lof":
        # novelty=True lets us score data the model wasn't fit on
        return LocalOutlierFactor(n_neighbors=20, contamination=contamination,
                                  novelty=True, n_jobs=-1)
    if key == "ocsvm":
        return OneClassSVM(kernel="rbf", nu=contamination, gamma="scale")
    return RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1,
                                  class_weight="balanced")


def score_samples(key: str, clf, X: np.ndarray) -> np.ndarray:
    # higher = more suspicious for every model
    if key == "rf":
        return clf.predict_proba(X)[:, 1]
    return -clf.decision_function(X)


def default_predict(key: str, clf, X: np.ndarray) -> np.ndarray:
    pred = clf.predict(X)
    return pred if key == "rf" else (pred == -1).astype(int)


def pick_threshold(y_val: np.ndarray, scores_val: np.ndarray) -> float:
    # score >= threshold is an alert; max-F1 point on the validation split only
    p, r, thr = precision_recall_curve(y_val, scores_val)
    f1 = 2 * p[:-1] * r[:-1] / np.maximum(p[:-1] + r[:-1], 1e-12)
    return float(thr[np.argmax(f1)])


def evaluate_model(key, X_tr, y_tr, X_val, y_val, X_test, y_test, groups, seed, contamination,
                   normal_only=False):
    clf = build_model(key, seed, contamination)
    if key == "rf":
        clf.fit(X_tr, y_tr)
    else:
        X_fit = X_tr[y_tr == 0] if normal_only else X_tr
        if key == "ocsvm" and len(X_fit) > OCSVM_MAX_TRAIN:
            idx = np.random.default_rng(seed).choice(len(X_fit), OCSVM_MAX_TRAIN, replace=False)
            X_fit = X_fit[idx]
        clf.fit(X_fit)

    s_val = score_samples(key, clf, X_val)
    s_test = score_samples(key, clf, X_test)
    thr = pick_threshold(y_val, s_val)
    pred = (s_test >= thr).astype(int)

    result = {
        "roc_auc": round(float(roc_auc_score(y_test, s_test)), 4),
        "pr_auc": round(float(average_precision_score(y_test, s_test)), 4),
        "default": _metrics(y_test, default_predict(key, clf, X_test)),
        "val_threshold": {
            **_metrics(y_test, pred),
            "threshold": round(thr, 6),
            "val_f1": round(float(f1_score(y_val, (s_val >= thr).astype(int))), 4),
            "recall_by_group": {
                g: round(float(pred[m].mean()), 4) for g, m in groups.items() if m.any()
            },
        },
    }
    return result, s_test


def mean_std(values: list[float]) -> dict:
    return {
        "mean": round(float(np.mean(values)), 4),
        "std": round(float(np.std(values, ddof=1)), 4) if len(values) > 1 else 0.0,
    }


def summarize(per_seed: dict) -> dict:
    runs = list(per_seed.values())
    summary = {}
    for name in runs[0]:
        summary[name] = {
            "roc_auc": mean_std([r[name]["roc_auc"] for r in runs]),
            "pr_auc": mean_std([r[name]["pr_auc"] for r in runs]),
        }
        for setting in ("default", "val_threshold"):
            summary[name][setting] = {
                m: mean_std([r[name][setting][m] for r in runs]) for m in SUMMARY_METRICS
            }
        by_group = [r[name]["val_threshold"]["recall_by_group"] for r in runs]
        summary[name]["val_threshold"]["recall_by_group"] = {
            g: mean_std([r[g] for r in by_group]) for g in by_group[0]
        }
    return summary


def run_benchmark(keys, train_path, test_path, seeds, contamination,
                  train_on="mixed", categorical="drop"):
    df_train = load_nslkdd(train_path)
    df_test = load_nslkdd(test_path)
    levels = category_levels(df_train) if categorical == "onehot" else None
    X_all, y_all = engineer_features(df_train, levels)
    X_test_raw, y_test = engineer_features(df_test, levels)
    check_categories(df_train["label"])
    check_categories(df_test["label"])
    groups = attack_groups(df_train["label"], df_test["label"])
    unseen_types = df_test.loc[groups["unseen"], "label"].value_counts()
    print(f"  train: {len(y_all):,} flows ({int(y_all.sum()):,} attacks)")
    print(f"  test:  {len(y_test):,} flows ({int(y_test.sum()):,} attacks)")
    print(f"  unseen attack types in test: {len(unseen_types)} ({int(groups['unseen'].sum()):,} flows)")
    print(f"  features: {X_all.shape[1]}")

    per_seed: dict = {}
    first_scores: dict = {}
    for seed in seeds:
        print(f"\nseed {seed}")
        idx_tr, idx_val = train_test_split(
            np.arange(len(y_all)), test_size=VAL_FRACTION, stratify=y_all, random_state=seed
        )
        # scaler sees the training split only
        scaler = StandardScaler().fit(X_all[idx_tr])
        X_tr, y_tr = scaler.transform(X_all[idx_tr]), y_all[idx_tr]
        X_val, y_val = scaler.transform(X_all[idx_val]), y_all[idx_val]
        X_test = scaler.transform(X_test_raw)

        per_seed[str(seed)] = {}
        for key in keys:
            res, s_test = evaluate_model(key, X_tr, y_tr, X_val, y_val, X_test, y_test,
                                         groups, seed, contamination,
                                         normal_only=train_on == "normal")
            per_seed[str(seed)][MODELS[key]] = res
            if seed == seeds[0]:
                first_scores[MODELS[key]] = s_test
            v = res["val_threshold"]
            rg = v["recall_by_group"]
            print(f"  {MODELS[key]:<22} F1={v['f1']:.4f}  recall={v['recall']:.4f}  "
                  f"fpr={v['fpr']:.4f}  roc_auc={res['roc_auc']:.4f}  "
                  f"recall seen/unseen={rg.get('seen', float('nan')):.3f}/{rg.get('unseen', float('nan')):.3f}")

    results = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "n_features": int(X_all.shape[1]),
        "train_flows": int(len(y_all)),
        "test_flows": int(len(y_test)),
        "contamination": contamination,
        "ablation": {
            "train_on": train_on,
            "categorical": categorical,
            "note": "train_on=normal only changes the unsupervised models; rf always sees both classes",
        },
        "protocol": {
            "validation_fraction": VAL_FRACTION,
            "split": "stratified on the binary label, new split per seed",
            "threshold": "max F1 on the validation split, applied unchanged to KDDTest+",
            "scaler": "fit on the training split only",
            "ocsvm_max_train_rows": OCSVM_MAX_TRAIN,
            "std": "sample std over seeds (ddof=1)",
        },
        "test_groups": {
            "flows_per_group": {g: int(m.sum()) for g, m in groups.items()},
            "unseen_attack_types": {t: int(n) for t, n in unseen_types.items()},
            "seen": "attack type appears anywhere in KDDTrain+ (fixed across seeds)",
        },
        "seeds": list(seeds),
        "summary": summarize(per_seed),
        "per_seed": per_seed,
    }
    return results, first_scores, y_test


def plot_pr_curves(y_true, scores_by_model: dict, seed_results: dict, out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 5))
    for i, (name, scores) in enumerate(scores_by_model.items()):
        precisions, recalls, _ = precision_recall_curve(y_true, scores)
        res = seed_results[name]
        color = f"C{i}"
        ax.plot(recalls, precisions, color=color, lw=2,
                label=f"{name} (PR-AUC {res['pr_auc']:.3f})")
        v, d = res["val_threshold"], res["default"]
        ax.scatter([v["recall"]], [v["precision"]], color=color, s=90, zorder=5,
                   edgecolor="black")
        ax.scatter([d["recall"]], [d["precision"]], color=color, s=70, marker="x", zorder=5)

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("KDDTest+ (circle: validation threshold, x: model default)", fontsize=11)
    ax.legend(loc="lower left", fontsize=9)
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.05)
    ax.grid(True, alpha=0.3)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"pr curves saved to {out_path}")


def print_table(results: dict) -> None:
    def ms(d: dict) -> str:
        return f"{d['mean']:.3f} +/- {d['std']:.3f}"

    header = (f"{'Model':<22} {'F1':>15} {'Precision':>15} {'Recall':>15} "
              f"{'FPR':>15} {'F1 default':>15} {'ROC-AUC':>15} {'PR-AUC':>15}")
    print(f"\n{'=' * len(header)}")
    ab = results["ablation"]
    print(f"  NSL-KDD, threshold from validation split, seeds {results['seeds']}")
    print(f"  unsupervised training rows: {ab['train_on']}, categorical columns: {ab['categorical']}")
    print(f"{'=' * len(header)}")
    print(header)
    print("-" * len(header))
    for name, s in results["summary"].items():
        v = s["val_threshold"]
        print(f"{name:<22} {ms(v['f1']):>15} {ms(v['precision']):>15} {ms(v['recall']):>15} "
              f"{ms(v['fpr']):>15} {ms(s['default']['f1']):>15} "
              f"{ms(s['roc_auc']):>15} {ms(s['pr_auc']):>15}")
    print(f"{'=' * len(header)}\n")

    cols = ["seen", "unseen", "DoS", "Probe", "R2L", "U2R"]
    counts = results["test_groups"]["flows_per_group"]
    header = f"{'Recall at val threshold':<24}" + "".join(
        f"{c + ' (' + format(counts[c], ',') + ')':>17}" for c in cols)
    print(header)
    print("-" * len(header))
    for name, s in results["summary"].items():
        rg = s["val_threshold"]["recall_by_group"]
        print(f"{name:<24}" + "".join(f"{ms(rg[c]):>17}" for c in cols))
    print()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="NSL-KDD benchmark with a validation-chosen threshold")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt (auto-downloaded if blank)")
    ap.add_argument("--test", default="", help="path to KDDTest+.txt (auto-downloaded if blank)")
    ap.add_argument("--out", default="", help="output JSON path (default depends on the ablation flags)")
    ap.add_argument("--train-on", choices=["mixed", "normal"], default="mixed",
                    help="training rows for the unsupervised models (default: mixed, as in KDDTrain+)")
    ap.add_argument("--categorical", choices=["drop", "onehot"], default="drop",
                    help="drop protocol_type/service/flag or one-hot them (default: drop)")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="expected fraction of anomalies for the unsupervised models (default: 0.1)")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--models", nargs="+", choices=list(MODELS), default=list(MODELS))
    args = ap.parse_args(argv)

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"

    print("getting the dataset")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    results, first_scores, y_test = run_benchmark(
        args.models, train_path, test_path, args.seeds, args.contamination,
        args.train_on, args.categorical
    )

    suffix = ("_normal_only" if args.train_on == "normal" else "") + \
             ("_onehot" if args.categorical == "onehot" else "")
    out_path = Path(args.out or f"results/benchmark{suffix}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nresults saved to {out_path}")

    plot_pr_curves(y_test, first_scores, results["per_seed"][str(args.seeds[0])],
                   out_path.with_name(out_path.stem + "_pr_curves.png"))
    print_table(results)


if __name__ == "__main__":
    main()
