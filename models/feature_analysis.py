#!/usr/bin/env python3
# analyzes which features matter most for detecting attacks in NSL-KDD
# uses a random forest to get feature importances and plots a correlation heatmap
#
# outputs:
#   results/feature_importance.png  - bar chart of top N features
#   results/correlation_heatmap.png - pearson correlation matrix
#
# usage:
#   python models/feature_analysis.py
#   python models/feature_analysis.py --top 20

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent))
from evaluate import (
    TEST_URL,
    TRAIN_URL,
    NUMERIC_COLS,
    download_if_missing,
    engineer_features,
    load_nslkdd,
)


def train_rf(X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
    # same setup as supervised_baseline.py
    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)
    return clf


def plot_feature_importance(
    importances: np.ndarray,
    feature_names: list[str],
    out_path: Path,
    top_n: int = 15,
) -> list[tuple[str, float]]:
    # sort by importance and grab the top N
    indices = np.argsort(importances)[::-1]
    top_idx = indices[:top_n]
    top_names = [feature_names[i] for i in top_idx]
    top_vals = importances[top_idx]

    # reverse so the most important feature is at the top of the chart
    top_names_r = top_names[::-1]
    top_vals_r = top_vals[::-1]

    fig, ax = plt.subplots(figsize=(8, 6))
    bars = ax.barh(top_names_r, top_vals_r, color="steelblue", alpha=0.85)
    ax.bar_label(bars, fmt="%.4f", padding=3, fontsize=8)
    ax.set_xlabel("Feature Importance (mean decrease in impurity)", fontsize=11)
    ax.set_title(f"Top {top_n} Feature Importances - Random Forest on NSL-KDD", fontsize=12)
    ax.set_xlim(0, top_vals_r.max() * 1.18)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"feature importance plot saved to {out_path}")

    return list(zip(top_names, top_vals))


def plot_correlation_heatmap(
    df_train: pd.DataFrame,
    feature_names: list[str],
    out_path: Path,
) -> pd.DataFrame:
    corr = df_train[feature_names].corr()

    n = len(feature_names)
    fig, ax = plt.subplots(figsize=(14, 12))
    im = ax.imshow(corr.values, cmap="RdBu_r", vmin=-1, vmax=1, aspect="auto")
    fig.colorbar(im, ax=ax, shrink=0.8, label="Pearson r")

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(feature_names, rotation=90, fontsize=7)
    ax.set_yticklabels(feature_names, fontsize=7)
    ax.set_title("Feature Correlation Heatmap - NSL-KDD Numeric Features", fontsize=12)

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"correlation heatmap saved to {out_path}")

    return corr


def generate_report(
    top_features: list[tuple[str, float]],
    corr: pd.DataFrame,
    top_n_corr: int = 5,
) -> None:
    # print a markdown summary of what we found
    print("\n" + "=" * 60)
    print("## Feature Analysis Report - NSL-KDD\n")

    print("### Top Features by Importance\n")
    for i, (name, val) in enumerate(top_features, 1):
        print(f"{i:>2}. `{name}` - {val:.4f}")

    top3 = [name for name, _ in top_features[:3]]
    print(f"\nTop 3: {', '.join(top3)} — volume and service-concentration features dominate.")

    # find the strongest correlations (ignoring the diagonal)
    print("\n### Strongest Feature Correlations\n")
    corr_vals = (
        corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
        .stack()
        .abs()
        .sort_values(ascending=False)
    )
    print("| Feature A | Feature B | Pearson r |")
    print("|---|---|---|")
    for (fa, fb), val in corr_vals.head(top_n_corr).items():
        raw = corr.loc[fa, fb]
        print(f"| `{fa}` | `{fb}` | {raw:+.3f} |")

    # flag anything with |r| > 0.9 as potentially redundant
    high_corr = corr_vals[corr_vals > 0.9]
    if not high_corr.empty:
        print(f"\n{len(high_corr)} pairs with |r| > 0.90 — likely redundant, candidates for pruning.")

    print("\n" + "=" * 60)


def main() -> None:
    ap = argparse.ArgumentParser(description="feature importance and correlation analysis on NSL-KDD")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt")
    ap.add_argument("--top", type=int, default=15, help="how many top features to plot (default: 15)")
    ap.add_argument("--out-dir", default="results", help="folder to save plots (default: results/)")
    args = ap.parse_args()

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = data_dir / "KDDTest+.txt"
    out_dir = Path(args.out_dir)

    print("=== Feature Analysis ===\n")

    print("step 1: getting the dataset")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    print("\nstep 2: loading features")
    df_train = load_nslkdd(train_path)
    X_train_raw, y_train = engineer_features(df_train)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)

    print("step 3: training random forest to get feature importances")
    clf = train_rf(X_train, y_train)

    print("\nstep 4: plotting feature importance")
    top_features = plot_feature_importance(
        clf.feature_importances_,
        NUMERIC_COLS,
        out_dir / "feature_importance.png",
        top_n=args.top,
    )

    print("\nstep 5: plotting correlation heatmap")
    corr = plot_correlation_heatmap(
        df_train,
        NUMERIC_COLS,
        out_dir / "correlation_heatmap.png",
    )

    generate_report(top_features, corr)


if __name__ == "__main__":
    main()
