#!/usr/bin/env python3
# hybrid evaluation: the random forest alerts, plus an anomaly detector's alerts on the flows the forest
# calls normal. the false-alarm budget on validation normals is fixed and shared between the two sources;
# the split is chosen on validation labels, so every row is at the same total false-alarm rate. this
# evaluates a combination, it is not a new detector.
#
# usage:
#   python models/hybrid.py
#   python models/hybrid.py --budget 0.05 --seeds 0 1 2 3 4

import argparse
import json
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from evaluate import (
    GRIDS,
    TEST_URL,
    TRAIN_URL,
    VAL_FRACTION,
    attack_groups,
    download_if_missing,
    engineer_features,
    fit_model,
    fpr_threshold,
    load_nslkdd,
    mean_std,
    score_samples,
)

ANOMALY = {"if_normal": ("iforest", True), "ocsvm_normal": ("ocsvm", True), "if_mixed": ("iforest", False)}
SPLIT_GRID = [0.0, 0.25, 0.5, 0.75, 1.0]  # share of the budget the forest may use; 1.0 is the forest alone


def thresholds(s_rf_val, s_an_val, y_val, budget, share):
    normal = y_val == 0
    k_total = int(np.floor(budget * normal.sum() + 1e-9))
    tau_rf = fpr_threshold(s_rf_val[normal], share * budget) if share > 0 else np.inf
    rf_alert = s_rf_val >= tau_rf
    k_extra = k_total - int((rf_alert & normal).sum())
    rest = normal & ~rf_alert
    if k_extra <= 0 or rest.sum() == 0:
        return tau_rf, np.inf
    return tau_rf, fpr_threshold(s_an_val[rest], k_extra / rest.sum())


def alerts(s_rf, s_an, tau_rf, tau_an):
    return (s_rf >= tau_rf) | (s_an >= tau_an)


def run(train_path, test_path, seeds, budget):
    df_tr, df_te = load_nslkdd(train_path), load_nslkdd(test_path)
    X_all, y_all = engineer_features(df_tr)
    X_te, y_te = engineer_features(df_te)
    groups = attack_groups(df_tr["label"], df_te["label"])
    per_seed = {name: [] for name in [*ANOMALY, "forest_alone"]}

    for seed in seeds:
        idx_tr, idx_val = train_test_split(np.arange(len(y_all)), test_size=VAL_FRACTION,
                                           stratify=y_all, random_state=seed)
        scaler = StandardScaler().fit(X_all[idx_tr])
        X_tr, y_tr = scaler.transform(X_all[idx_tr]), y_all[idx_tr]
        X_val, y_val = scaler.transform(X_all[idx_val]), y_all[idx_val]
        X_test = scaler.transform(X_te)

        rf = fit_model("rf", X_tr, y_tr, seed, 0.1, {"max_depth": None}, False)
        s_rf_val, s_rf_test = score_samples("rf", rf, X_val), score_samples("rf", rf, X_test)
        tau_alone = fpr_threshold(s_rf_val[y_val == 0], budget)
        per_seed["forest_alone"].append(_row(s_rf_test >= tau_alone, groups, y_te, 1.0))
        for name, (key, normal_only) in ANOMALY.items():
            clf = fit_model(key, X_tr, y_tr, seed, 0.1, GRIDS[key][0], normal_only)
            s_an_val, s_an_test = score_samples(key, clf, X_val), score_samples(key, clf, X_test)
            best = None
            for share in SPLIT_GRID:
                tau_rf, tau_an = thresholds(s_rf_val, s_an_val, y_val, budget, share)
                val_recall = alerts(s_rf_val, s_an_val, tau_rf, tau_an)[y_val == 1].mean()
                if best is None or val_recall > best[0]:
                    best = (val_recall, share, tau_rf, tau_an)
            _, share, tau_rf, tau_an = best
            a = alerts(s_rf_test, s_an_test, tau_rf, tau_an)
            per_seed[name].append(_row(a, groups, y_te, share))
    return per_seed


def _row(a, groups, y_te, share):
    return {
        "share_to_forest": share,
        "recall": {g: round(float(a[m].mean()), 4) for g, m in groups.items() if m.any()},
        "fpr": round(float(a[y_te == 0].mean()), 4),
    }


def summarize(per_seed: dict) -> dict:
    out = {}
    for name, runs in per_seed.items():
        recall = {g: mean_std([r["recall"][g] for r in runs]) for g in runs[0]["recall"]}
        out[name] = {
            "share_to_forest": [r["share_to_forest"] for r in runs],
            "fpr": mean_std([r["fpr"] for r in runs]),
            "recall": recall,
        }
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="forest plus anomaly detector at a fixed false-alarm budget")
    ap.add_argument("--train", default="")
    ap.add_argument("--test", default="")
    ap.add_argument("--budget", type=float, default=0.05, help="total false-alarm rate on validation normals")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--out", default="results/hybrid.json")
    args = ap.parse_args(argv)

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    per_seed = run(train_path, test_path, args.seeds, args.budget)
    results = {
        "budget": args.budget,
        "seeds": args.seeds,
        "protocol": "alerts = forest alerts OR anomaly alerts on flows the forest calls normal; the "
                    "false-alarm budget on validation normals is split between the two sources, and the split "
                    "is chosen by validation recall; test normals only measure the false-alarm rate",
        "share_grid": SPLIT_GRID,
        "summary": summarize(per_seed),
        "per_seed": per_seed,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print(f"results saved to {out}")
    for name, s in results["summary"].items():
        rec = {g: s["recall"][g]["mean"] if g in s["recall"] else float("nan")
               for g in ("seen", "unseen", "R2L")}
        print(f"{name:<14} fpr {s['fpr']['mean']:.4f}  seen {rec['seen']:.3f}  "
              f"unseen {rec['unseen']:.3f}  R2L {rec['R2L']:.3f}  share to forest {s['share_to_forest']}")


if __name__ == "__main__":
    main()
