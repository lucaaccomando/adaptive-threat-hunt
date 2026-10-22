#!/usr/bin/env python3
# benchmarks isolation forest, LOF, one-class svm and a random forest on NSL-KDD
# models train on 80% of KDDTrain+; alert thresholds (max F1, and 1% / 5% false alarms on normal
# flows) are picked on the other 20% and applied unchanged to KDDTest+; repeated over several seeds
#
# usage:
#   python models/evaluate.py
#   python models/evaluate.py --seeds 0 1 2 --models iforest rf
#   python models/evaluate.py --train-on normal      # unsupervised models fit on normal flows only
#   python models/evaluate.py --categorical onehot   # keep protocol_type, service and flag
#   python models/evaluate.py --transform log1p      # log1p on the heavy-tailed columns before scaling
#   python models/evaluate.py --tune                 # small hyperparameter grid, chosen on validation

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

# non-negative count / size columns with a huge range; the rest are binary or bounded rates
HEAVY_TAILED_COLS = [
    "duration", "src_bytes", "dst_bytes", "hot", "num_compromised", "num_root",
    "num_file_creations", "count", "srv_count",
]
HEAVY_TAILED_IDX = [NUMERIC_COLS.index(c) for c in HEAVY_TAILED_COLS]

# the first entry of each grid is the setting used without --tune, and ties on validation keep the
# earlier entry; ocsvm nu None means the contamination argument
GRIDS = {
    "iforest": [{"n_estimators": t, "max_samples": m} for t, m in
                [(200, 256), (200, 1024), (200, 4096), (500, 256), (500, 1024), (500, 4096)]],
    "lof": [{"n_neighbors": k} for k in (20, 10, 50)],
    "ocsvm": [{"gamma_mult": g, "nu": nu} for g, nu in
              [(1.0, None), (0.1, None), (10.0, None), (1.0, 0.05), (1.0, 0.2)]],
    "rf": [{"max_depth": d} for d in (None, 10, 20)],
}

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
FPR_TARGETS = {"fpr_1pct": 0.01, "fpr_5pct": 0.05}
OP_SETTINGS = ["val_threshold", *FPR_TARGETS]
# attack base rates for the re-weighted precision (Axelsson)
PREVALENCES = {"precision_prev1": 0.01, "precision_prev10": 0.10}
OP_METRICS = SUMMARY_METRICS + ("val_f1", "val_fpr", "f1_gap", "fpr_gap",
                                "alerts_per_10k_normal") + tuple(PREVALENCES)


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


def apply_transform(X: np.ndarray, transform: str) -> np.ndarray:
    if transform == "none":
        return X
    X = X.copy()
    X[:, HEAVY_TAILED_IDX] = np.log1p(X[:, HEAVY_TAILED_IDX])
    return X


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


def build_model(key: str, seed: int, contamination: float, **p):
    if key == "iforest":
        return IsolationForest(n_estimators=p.get("n_estimators", 200),
                               max_samples=p.get("max_samples", "auto"),
                               contamination=contamination, random_state=seed, n_jobs=-1)
    if key == "lof":
        # novelty=True lets us score data the model wasn't fit on
        return LocalOutlierFactor(n_neighbors=p.get("n_neighbors", 20), contamination=contamination,
                                  novelty=True, n_jobs=-1)
    if key == "ocsvm":
        return OneClassSVM(kernel="rbf", nu=p.get("nu") or contamination, gamma=p.get("gamma", "scale"))
    return RandomForestClassifier(n_estimators=200, max_depth=p.get("max_depth"),
                                  random_state=seed, n_jobs=-1, class_weight="balanced")


def fit_model(key, X_tr, y_tr, seed, contamination, params, normal_only=False):
    p = dict(params)
    if key == "rf":
        return build_model(key, seed, contamination, **p).fit(X_tr, y_tr)
    X_fit = X_tr[y_tr == 0] if normal_only else X_tr
    if key == "ocsvm":
        if len(X_fit) > OCSVM_MAX_TRAIN:
            idx = np.random.default_rng(seed).choice(len(X_fit), OCSVM_MAX_TRAIN, replace=False)
            X_fit = X_fit[idx]
        # gamma_mult 1 is sklearn's gamma="scale"
        p["gamma"] = p.pop("gamma_mult", 1.0) / (X_fit.shape[1] * X_fit.var())
    return build_model(key, seed, contamination, **p).fit(X_fit)


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


def fpr_threshold(scores_normal: np.ndarray, fpr: float) -> float:
    # alerts are score >= threshold, so go just above the (k+1)-th highest normal score:
    # at most k = floor(fpr * n) normal rows alert, fewer if scores are tied
    if not 0 < fpr < 1:
        raise ValueError(f"fpr must be between 0 and 1, got {fpr}")
    s = np.sort(scores_normal)[::-1]
    k = int(np.floor(fpr * len(s) + 1e-9))
    return float(np.nextafter(s[k], np.inf))


def precision_at_prevalence(recall: float, fpr: float, prevalence: float) -> float:
    tp, fp = recall * prevalence, fpr * (1 - prevalence)
    return tp / (tp + fp) if tp + fp > 0 else 0.0


def operating_point(thr, s_val, y_val, s_test, y_test, groups) -> dict:
    pred = (s_test >= thr).astype(int)
    test = _metrics(y_test, pred)
    val = _metrics(y_val, (s_val >= thr).astype(int))
    recall = test["tp"] / max(test["tp"] + test["fn"], 1)
    fpr = test["fp"] / max(test["fp"] + test["tn"], 1)
    return {
        **test,
        "threshold": round(thr, 6),
        "val_f1": val["f1"],
        "val_fpr": val["fpr"],
        "f1_gap": round(test["f1"] - val["f1"], 4),
        "fpr_gap": round(test["fpr"] - val["fpr"], 4),
        "alerts_per_10k_normal": round(fpr * 10_000, 1),
        **{name: round(precision_at_prevalence(recall, fpr, p), 4)
           for name, p in PREVALENCES.items()},
        "recall_by_group": {
            g: round(float(pred[m].mean()), 4) for g, m in groups.items() if m.any()
        },
    }


def evaluate_model(key, X_tr, y_tr, X_val, y_val, X_test, y_test, groups, seed, contamination,
                   normal_only=False, tune=False):
    # candidates are compared on validation PR-AUC only
    best = None
    for params in (GRIDS[key] if tune else GRIDS[key][:1]):
        clf = fit_model(key, X_tr, y_tr, seed, contamination, params, normal_only)
        s_val = score_samples(key, clf, X_val)
        val_pr = float(average_precision_score(y_val, s_val))
        if best is None or val_pr > best[0]:
            best = (val_pr, params, clf, s_val)
    val_pr, params, clf, s_val = best

    s_test = score_samples(key, clf, X_test)
    thresholds = {"val_threshold": pick_threshold(y_val, s_val)}
    for name, fpr in FPR_TARGETS.items():
        thresholds[name] = fpr_threshold(s_val[y_val == 0], fpr)

    result = {
        "params": params,
        "val_pr_auc": round(val_pr, 4),
        "roc_auc": round(float(roc_auc_score(y_test, s_test)), 4),
        "pr_auc": round(float(average_precision_score(y_test, s_test)), 4),
        "default": _metrics(y_test, default_predict(key, clf, X_test)),
        **{name: operating_point(thr, s_val, y_val, s_test, y_test, groups)
           for name, thr in thresholds.items()},
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
            "val_pr_auc": mean_std([r[name]["val_pr_auc"] for r in runs]),
        }
        summary[name]["default"] = {
            m: mean_std([r[name]["default"][m] for r in runs]) for m in SUMMARY_METRICS
        }
        for setting in OP_SETTINGS:
            summary[name][setting] = {
                m: mean_std([r[name][setting][m] for r in runs]) for m in OP_METRICS
            }
            by_group = [r[name][setting]["recall_by_group"] for r in runs]
            summary[name][setting]["recall_by_group"] = {
                g: mean_std([r[g] for r in by_group]) for g in by_group[0]
            }
    return summary


def run_benchmark(keys, train_path, test_path, seeds, contamination,
                  train_on="mixed", categorical="drop", transform="none", tune=False):
    df_train = load_nslkdd(train_path)
    df_test = load_nslkdd(test_path)
    levels = category_levels(df_train) if categorical == "onehot" else None
    X_all, y_all = engineer_features(df_train, levels)
    X_test_raw, y_test = engineer_features(df_test, levels)
    # log1p is per-value, so applying it before the split leaks nothing
    X_all, X_test_raw = apply_transform(X_all, transform), apply_transform(X_test_raw, transform)
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
                                         normal_only=train_on == "normal", tune=tune)
            per_seed[str(seed)][MODELS[key]] = res
            if seed == seeds[0]:
                first_scores[MODELS[key]] = s_test
            lo, hi, v = res["fpr_1pct"], res["fpr_5pct"], res["val_threshold"]
            rg = hi["recall_by_group"]
            print(f"  {MODELS[key]:<22} roc_auc={res['roc_auc']:.4f}  "
                  f"recall@1%fpr={lo['recall']:.4f} (fpr {lo['fpr']:.4f})  "
                  f"recall@5%fpr={hi['recall']:.4f} (fpr {hi['fpr']:.4f})  "
                  f"seen/unseen@5%={rg.get('seen', float('nan')):.3f}/{rg.get('unseen', float('nan')):.3f}  "
                  f"max-F1={v['f1']:.4f}  val_pr_auc={res['val_pr_auc']:.4f}  {res['params'] or ''}")

    results = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "n_features": int(X_all.shape[1]),
        "train_flows": int(len(y_all)),
        "test_flows": int(len(y_test)),
        "attack_prevalence": {"train_and_val": round(float(y_all.mean()), 4),
                              "test": round(float(y_test.mean()), 4)},
        "contamination": contamination,
        "ablation": {
            "train_on": train_on,
            "categorical": categorical,
            "transform": transform,
            "tuned": tune,
            "note": "train_on=normal only changes the unsupervised models; rf always sees both classes",
        },
        "protocol": {
            "validation_fraction": VAL_FRACTION,
            "split": "stratified on the binary label, new split per seed",
            "threshold": "max F1 on the validation split, applied unchanged to KDDTest+",
            "fixed_fpr_thresholds": "highest-recall threshold with at most 1% / 5% false alarms on the "
                                    "validation normal rows, applied unchanged to KDDTest+",
            "precision_prev": "recall * p / (recall * p + fpr * (1 - p)) for attack base rate p = 1% and 10%; "
                              "assumes the test recall and fpr carry over to that base rate",
            "gaps": "test minus validation; f1_gap also moves with the attack prevalence, fpr_gap does not",
            "scaler": "fit on the training split only",
            "transform": f"log1p on {HEAVY_TAILED_COLS} before scaling (per-value, so no split leakage)",
            "tuning": "with --tune each model tries its grid (GRIDS in evaluate.py) and keeps the setting "
                      "with the best PR-AUC on the validation split; the first grid entry is the untuned setting",
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
    print(f"  unsupervised training rows: {ab['train_on']}, categorical columns: {ab['categorical']}, "
          f"transform: {ab['transform']}, tuned: {ab['tuned']}")
    print(f"{'=' * len(header)}")
    print(header)
    print("-" * len(header))
    for name, s in results["summary"].items():
        v = s["val_threshold"]
        print(f"{name:<22} {ms(v['f1']):>15} {ms(v['precision']):>15} {ms(v['recall']):>15} "
              f"{ms(v['fpr']):>15} {ms(s['default']['f1']):>15} "
              f"{ms(s['roc_auc']):>15} {ms(s['pr_auc']):>15}")
    print(f"{'=' * len(header)}\n")

    labels = {"fpr_1pct": "1% fpr", "fpr_5pct": "5% fpr", "val_threshold": "max F1"}
    header = (f"{'Operating point':<30} {'test FPR':>15} {'recall':>15} {'prec @1%':>15} "
              f"{'prec @10%':>15} {'alerts/10k':>20} {'FPR gap':>15}")
    print(header)
    print("-" * len(header))
    for name, s in results["summary"].items():
        for setting in ("fpr_1pct", "fpr_5pct", "val_threshold"):
            v = s[setting]
            print(f"{name + ', ' + labels[setting]:<30} {ms(v['fpr']):>15} {ms(v['recall']):>15} "
                  f"{ms(v['precision_prev1']):>15} {ms(v['precision_prev10']):>15} "
                  f"{ms(v['alerts_per_10k_normal']):>20} {ms(v['fpr_gap']):>15}")
    print()

    cols = ["seen", "unseen", "DoS", "Probe", "R2L", "U2R"]
    counts = results["test_groups"]["flows_per_group"]
    for setting in ("fpr_1pct", "fpr_5pct", "val_threshold"):
        header = f"{'Recall at ' + labels[setting]:<24}" + "".join(
            f"{c + ' (' + format(counts[c], ',') + ')':>17}" for c in cols)
        print(header)
        print("-" * len(header))
        for name, s in results["summary"].items():
            rg = s[setting]["recall_by_group"]
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
    ap.add_argument("--transform", choices=["none", "log1p"], default="none",
                    help="log1p the heavy-tailed columns before scaling (default: none)")
    ap.add_argument("--tune", action="store_true",
                    help="pick each model's hyperparameters from a small grid on the validation split")
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
        args.train_on, args.categorical, args.transform, args.tune
    )

    suffix = ("_normal_only" if args.train_on == "normal" else "") + \
             ("_onehot" if args.categorical == "onehot" else "") + \
             ("_log1p" if args.transform == "log1p" else "") + ("_tuned" if args.tune else "")
    out_path = Path(args.out or f"results/benchmark{suffix}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nresults saved to {out_path}")

    plot_pr_curves(y_test, first_scores, results["per_seed"][str(args.seeds[0])],
                   out_path.with_name(out_path.stem + "_pr_curves.png"))
    print_table(results)


if __name__ == "__main__":
    main()
