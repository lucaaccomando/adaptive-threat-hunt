#!/usr/bin/env python3
# permutation importance on KDDTest+ for the forest and the normal-only Isolation Forest: the drop in
# ROC-AUC (normal vs attack) when one feature is shuffled, for attacks seen in training and for unseen ones
# models train on 80% of KDDTrain+ and nothing here picks a threshold or a model from test labels
#
# usage:
#   python models/feature_analysis.py
#   python models/feature_analysis.py --top 15 --seeds 0 1 2

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent))
from evaluate import (
    TEST_URL,
    TRAIN_URL,
    NUMERIC_COLS,
    VAL_FRACTION,
    attack_groups,
    download_if_missing,
    engineer_features,
    fit_model,
    load_nslkdd,
    mean_std,
    score_samples,
)

DETECTORS = {"rf": ("rf", False), "iforest_normal_only": ("iforest", True)}


def permutation_importance(key, clf, X, y, rng, repeats=3) -> np.ndarray:
    base = roc_auc_score(y, score_samples(key, clf, X))
    drops = np.zeros(X.shape[1])
    for j in range(X.shape[1]):
        for _ in range(repeats):
            Xp = X.copy()
            Xp[:, j] = rng.permutation(Xp[:, j])
            drops[j] += base - roc_auc_score(y, score_samples(key, clf, Xp))
    return drops / repeats


def importances_for_seed(df_train, df_test, seed, contamination=0.1):
    X_all, y_all = engineer_features(df_train)
    X_test, _ = engineer_features(df_test)
    idx_tr, _ = train_test_split(np.arange(len(y_all)), test_size=VAL_FRACTION,
                                 stratify=y_all, random_state=seed)
    scaler = StandardScaler().fit(X_all[idx_tr])
    X_tr, y_tr = scaler.transform(X_all[idx_tr]), y_all[idx_tr]
    X_test = scaler.transform(X_test)

    groups = attack_groups(df_train["label"], df_test["label"])
    normal = (df_test["label"] == "normal").to_numpy()
    rng = np.random.default_rng(seed)
    out = {}
    for name, (key, normal_only) in DETECTORS.items():
        clf = fit_model(key, X_tr, y_tr, seed, contamination, {}, normal_only)
        out[name] = {}
        for g in ("seen", "unseen"):
            mask = normal | groups[g]
            out[name][g] = permutation_importance(key, clf, X_test[mask], groups[g][mask].astype(int), rng)
    return out


def summarize(per_seed: list[dict], names: list[str]) -> dict:
    res = {}
    for det in per_seed[0]:
        res[det] = {}
        for g in per_seed[0][det]:
            vals = np.array([s[det][g] for s in per_seed])
            res[det][g] = {n: mean_std(list(vals[:, i])) for i, n in enumerate(names)}
    return res


def plot_importance(res: dict, out_path: Path, top_n: int) -> None:
    titles = {"rf": "Random Forest", "iforest_normal_only": "Isolation Forest, normal-only training"}
    fig, axes = plt.subplots(1, len(res), figsize=(13, 6), sharex=True)
    for ax, (det, groups) in zip(axes, res.items()):
        order = sorted(groups["unseen"], key=lambda n: groups["seen"][n]["mean"] + groups["unseen"][n]["mean"],
                       reverse=True)[:top_n][::-1]
        pos = np.arange(len(order))
        for off, g, color in ((-0.2, "seen", "steelblue"), (0.2, "unseen", "darkorange")):
            ax.barh(pos + off, [groups[g][n]["mean"] for n in order], height=0.4, color=color,
                    xerr=[groups[g][n]["std"] for n in order], label=f"{g} attacks")
        ax.set_yticks(pos)
        ax.set_yticklabels(order, fontsize=8)
        ax.set_title(titles[det], fontsize=11)
        ax.set_xlabel("drop in ROC-AUC when the feature is shuffled")
        ax.grid(axis="x", alpha=0.3)
    axes[0].legend()
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"feature importance plot saved to {out_path}")


def plot_correlation_heatmap(df_train: pd.DataFrame, names: list[str], out_path: Path) -> pd.DataFrame:
    corr = df_train[names].corr()
    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1, aspect="auto")
    fig.colorbar(im, ax=ax, shrink=0.8, label="Pearson r")
    ax.set_xticks(range(len(names)))
    ax.set_yticks(range(len(names)))
    ax.set_xticklabels(names, rotation=90, fontsize=7)
    ax.set_yticklabels(names, fontsize=7)
    ax.set_title("Feature correlation, KDDTrain+ numeric features with nonzero variance", fontsize=12)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"correlation heatmap saved to {out_path}")
    return corr


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="permutation importance and correlation on NSL-KDD")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt")
    ap.add_argument("--test", default="", help="path to KDDTest+.txt")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--top", type=int, default=12, help="features per panel (default: 12)")
    ap.add_argument("--out-dir", default="results", help="folder for the plots and JSON (default: results/)")
    args = ap.parse_args(argv)

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"
    out_dir = Path(args.out_dir)

    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)
    df_train, df_test = load_nslkdd(train_path), load_nslkdd(test_path)

    constant = [c for c in NUMERIC_COLS if df_train[c].std() == 0]
    names = [c for c in NUMERIC_COLS if c not in constant]
    print(f"dropping constant columns: {constant}")
    keep = [NUMERIC_COLS.index(c) for c in names]

    per_seed = []
    for seed in args.seeds:
        print(f"seed {seed}")
        per_seed.append({det: {g: v[keep] for g, v in groups.items()}
                         for det, groups in importances_for_seed(df_train, df_test, seed).items()})
    res = summarize(per_seed, names)

    plot_importance(res, out_dir / "feature_importance.png", args.top)
    corr = plot_correlation_heatmap(df_train, names, out_dir / "correlation_heatmap.png")

    pairs = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool)).stack()
    strong = pairs[pairs.abs() > 0.9].sort_values(key=abs, ascending=False)
    out = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "seeds": args.seeds,
        "dropped_constant_columns": constant,
        "method": "mean drop in test ROC-AUC (normal vs seen or unseen attacks) over 3 shuffles per feature; "
                  "models trained on 80% of KDDTrain+, raw features, scaler fit on the training split; "
                  "analysis only, no threshold or model choice uses test labels",
        "permutation_importance": res,
        "correlated_pairs_over_0.9": [{"a": a, "b": b, "r": round(float(r), 3)} for (a, b), r in strong.items()],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "feature_importance.json").write_text(json.dumps(out, indent=2))
    print(f"results saved to {out_dir / 'feature_importance.json'}")

    for det, groups in res.items():
        print(f"\n{det}: top features by drop in ROC-AUC (seen / unseen)")
        for n in sorted(names, key=lambda n: groups["unseen"][n]["mean"], reverse=True)[:5]:
            print(f"  {n:<28} {groups['seen'][n]['mean']:.4f} / {groups['unseen'][n]['mean']:.4f}")


if __name__ == "__main__":
    main()
