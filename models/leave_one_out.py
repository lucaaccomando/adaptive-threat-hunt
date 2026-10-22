#!/usr/bin/env python3
# leave-one-attack-type-out on KDDTrain+: how well does each detector catch a type (or category) it never saw?
# the held-out rows are removed from training and validation and only appear in the test set,
# next to 20% of the normal rows that no model or threshold ever touched
#
# usage:
#   python models/leave_one_out.py
#   python models/leave_one_out.py --seeds 0 1 --models iforest rf --holdouts neptune R2L

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from evaluate import (
    ATTACK_CATEGORIES,
    MODELS,
    TRAIN_URL,
    VAL_FRACTION,
    check_categories,
    download_if_missing,
    engineer_features,
    evaluate_model,
    load_nslkdd,
    mean_std,
)

MIN_ROWS = 20
TEST_NORMAL_FRACTION = 0.2
SETTINGS = ["val_threshold", "fpr_1pct", "fpr_5pct"]
SETTING_LABELS = {"val_threshold": "max F1", "fpr_1pct": "1% fpr", "fpr_5pct": "5% fpr"}


def holdout_sets(labels) -> tuple[dict[str, list[str]], dict[str, int]]:
    counts = pd.Series(np.asarray(labels)).value_counts()
    attacks = counts.drop("normal", errors="ignore")
    sets = {t: [t] for t, n in sorted(attacks.items()) if n >= MIN_ROWS}
    for cat, names in ATTACK_CATEGORIES.items():
        present = sorted(set(names) & set(attacks.index))
        if sum(attacks[t] for t in present) >= MIN_ROWS:
            sets[cat] = present
    skipped = {t: int(n) for t, n in sorted(attacks.items()) if n < MIN_ROWS}
    return sets, skipped


def seed_split(y: np.ndarray, seed: int):
    rng = np.random.default_rng(seed)
    normal = np.flatnonzero(y == 0)
    test_normal = np.sort(rng.choice(normal, int(round(TEST_NORMAL_FRACTION * len(normal))), replace=False))
    rest = np.setdiff1d(np.arange(len(y)), test_normal)
    idx_tr, idx_val = train_test_split(rest, test_size=VAL_FRACTION, stratify=y[rest], random_state=seed)
    return test_normal, idx_tr, idx_val


def leave_out_split(labels, test_normal, idx_tr, idx_val, names):
    held = np.isin(labels, names)
    test_idx = np.concatenate([test_normal, np.flatnonzero(held)])
    return idx_tr[~held[idx_tr]], idx_val[~held[idx_val]], test_idx, held[test_idx]


def compact(res: dict) -> dict:
    out = {"roc_auc": res["roc_auc"]}
    for s in SETTINGS:
        out[s] = {"recall": res[s]["recall"], "fpr": res[s]["fpr"], "val_fpr": res[s]["val_fpr"]}
    return out


def summarize(per_seed: dict) -> dict:
    runs = list(per_seed.values())
    summary = {}
    for hold in runs[0]:
        summary[hold] = {}
        for model in runs[0][hold]:
            r = [run[hold][model] for run in runs]
            summary[hold][model] = {"roc_auc": mean_std([x["roc_auc"] for x in r])}
            for s in SETTINGS:
                summary[hold][model][s] = {m: mean_std([x[s][m] for x in r])
                                           for m in ("recall", "fpr", "val_fpr")}
    return summary


def run_leave_one_out(keys, train_path, seeds, contamination, holdouts=None, out_path=None):
    df = load_nslkdd(train_path)
    check_categories(df["label"])
    X_all, y = engineer_features(df)
    labels = df["label"].values
    sets, skipped = holdout_sets(labels)
    if holdouts:
        sets = {h: sets[h] for h in holdouts}
    print(f"  {len(sets)} held-out sets, skipped (under {MIN_ROWS} rows): {skipped}")

    per_seed: dict = {}
    for seed in seeds:
        test_normal, idx_tr, idx_val = seed_split(y, seed)
        per_seed[str(seed)] = {}
        for hold, names in sets.items():
            tr, val, test_idx, held = leave_out_split(labels, test_normal, idx_tr, idx_val, names)
            # scaler sees the training rows without the held-out type, like the models
            scaler = StandardScaler().fit(X_all[tr])
            X_tr, X_val, X_test = (scaler.transform(X_all[i]) for i in (tr, val, test_idx))
            out = per_seed[str(seed)][hold] = {}
            for key in keys:
                for normal_only in ([False, True] if key != "rf" else [False]):
                    name = MODELS[key] + ("" if key == "rf" else " (normal-only)" if normal_only else " (mixed)")
                    res, _ = evaluate_model(key, X_tr, y[tr], X_val, y[val], X_test, y[test_idx],
                                            {"held_out": held}, seed, contamination, normal_only=normal_only)
                    out[name] = compact(res)
            print(f"  seed {seed}  {hold:<16} " + "  ".join(
                f"{n.replace('Random Forest', 'RF').replace('Isolation Forest', 'IF')}={m['fpr_5pct']['recall']:.2f}"
                for n, m in out.items()), flush=True)

        results = {
            "dataset": "NSL-KDD KDDTrain+ only",
            "protocol": {
                "split": f"per seed, {TEST_NORMAL_FRACTION:.0%} of normal rows are held out as test normals, "
                         f"the rest is split {1 - VAL_FRACTION:.0%} / {VAL_FRACTION:.0%} into train / validation",
                "held_out": "all rows of the held-out type or category go to the test set and are removed "
                            "from train and validation; scaler and thresholds never see them",
                "test": "held-out rows (the only attacks) plus the test normals, so recall is recall on the held-out set",
                "thresholds": "max F1, and 1% / 5% false alarms on validation normals, as in evaluate.py",
                "mixed": "unsupervised models fit on the training rows that remain, other attack types included",
                "normal_only": "unsupervised models fit on the normal training rows",
                "models": "untuned settings, log1p off",
            },
            "min_rows": MIN_ROWS,
            "skipped_types": skipped,
            "holdouts": {h: {"types": names, "rows": int(np.isin(labels, names).sum())}
                         for h, names in sets.items()},
            "seeds": [int(s) for s in per_seed],
            "summary": summarize(per_seed),
            "per_seed": per_seed,
        }
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(results, indent=2))
    return results


def print_table(results: dict) -> None:
    models = list(next(iter(results["summary"].values())))
    short = {n: n.replace("Random Forest", "RF").replace("Isolation Forest", "IF")
                 .replace("Local Outlier Factor", "LOF").replace("One-Class SVM", "OC-SVM")
                 .replace("(normal-only)", "(n)").replace(" (mixed)", " (m)") for n in models}
    for setting in ("fpr_1pct", "fpr_5pct"):
        header = f"{'Recall at ' + SETTING_LABELS[setting]:<24}" + "".join(f"{short[m]:>12}" for m in models)
        print(header)
        print("-" * len(header))
        for hold, row in results["summary"].items():
            n = results["holdouts"][hold]["rows"]
            print(f"{hold + ' (' + format(n, ',') + ')':<24}" + "".join(
                f"{row[m][setting]['recall']['mean']:>12.3f}" for m in models))
        print()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="leave-one-attack-type-out on KDDTrain+")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt (auto-downloaded if blank)")
    ap.add_argument("--out", default="results/leave_one_out.json")
    ap.add_argument("--contamination", type=float, default=0.1)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--models", nargs="+", choices=list(MODELS), default=list(MODELS))
    ap.add_argument("--holdouts", nargs="+", help="only these types or categories (default: all)")
    args = ap.parse_args(argv)

    train_path = Path(args.train) if args.train else Path("data") / "nslkdd" / "KDDTrain+.txt"
    print("getting the dataset")
    download_if_missing(TRAIN_URL, train_path)

    out_path = Path(args.out)
    results = run_leave_one_out(args.models, train_path, args.seeds, args.contamination,
                                args.holdouts, out_path)
    print(f"\nresults saved to {out_path}")
    print_table(results)


if __name__ == "__main__":
    main()
