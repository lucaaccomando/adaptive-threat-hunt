#!/usr/bin/env python3
# detection map: each attack type as a point. x = distance from normal flows, y = distance from the
# other attack types, in the scaled feature space. distance = mean to the k nearest reference flows,
# median over the type's flows. reference flows come from KDDTrain+ only; KDDTest+ rows of unseen
# types are query points, never reference points.
#
# usage:
#   python models/detection_map.py
#   python models/detection_map.py --ks 1 5 20 --primary-k 5

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import spearmanr
from sklearn.linear_model import LinearRegression
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from evaluate import (
    NUMERIC_COLS,
    TEST_URL,
    TRAIN_URL,
    category_levels,
    check_categories,
    download_if_missing,
    engineer_features,
    load_nslkdd,
)
from leave_one_out import holdout_sets

# detector -> (name in leave_one_out.json, benchmark file, name in that benchmark file)
DETECTORS = {
    "rf": ("Random Forest", "benchmark.json", "Random Forest"),
    "if_normal": ("Isolation Forest (normal-only)", "benchmark_normal_only.json", "Isolation Forest"),
    "if_mixed": ("Isolation Forest (mixed)", "benchmark.json", "Isolation Forest"),
    "lof_normal": ("Local Outlier Factor (normal-only)", "benchmark_normal_only.json", "Local Outlier Factor"),
    "ocsvm_normal": ("One-Class SVM (normal-only)", "benchmark_normal_only.json", "One-Class SVM"),
}
BEST_OTHER = ["if_mixed", "lof_normal", "ocsvm_normal"]
OPERATING_POINT = "fpr_5pct"
N_BOOT = 2000


def feature_matrices(df_tr, df_te, levels):
    X_tr, _ = engineer_features(df_tr, levels)
    X_te, _ = engineer_features(df_te, levels)
    scaler = StandardScaler().fit(X_tr)
    return scaler.transform(X_tr), scaler.transform(X_te)


def knn_distance(query, ref, kmax):
    nn = NearestNeighbors(n_neighbors=kmax, algorithm="brute", n_jobs=-1).fit(ref)
    return nn.kneighbors(query, return_distance=True)[0]


def positions(df_tr, df_te, X_tr, X_te, ks):
    labels_tr, labels_te = df_tr["label"].values, df_te["label"].values
    attack_tr = labels_tr != "normal"
    normal_ref = X_tr[~attack_tr]

    jobs = []
    sets, _ = holdout_sets(labels_tr)
    for t, names in sets.items():
        if names == [t]:
            jobs.append((t, "held_out", X_tr[labels_tr == t], X_tr[attack_tr & (labels_tr != t)]))
    seen = set(labels_tr[attack_tr])
    for t in sorted(set(labels_te[labels_te != "normal"]) - seen):
        jobs.append((t, "unseen_test", X_te[labels_te == t], X_tr[attack_tr]))

    kmax = max(ks)
    out = {k: {} for k in ks}
    for t, group, query, others in jobs:
        dn = knn_distance(query, normal_ref, kmax)
        da = knn_distance(query, others, kmax)
        for k in ks:
            out[k][t] = {
                "group": group,
                "rows": len(query),
                "x": round(float(np.median(dn[:, :k].mean(axis=1))), 4),
                "y": round(float(np.median(da[:, :k].mean(axis=1))), 4),
            }
    return out


def exact_duplicates(df_tr, df_te):
    # unseen test attacks whose raw numeric values match a KDDTrain+ normal flow exactly
    seen = set(df_tr.loc[df_tr["label"] != "normal", "label"])
    unseen = df_te[(df_te["binary_label"] == 1) & ~df_te["label"].isin(seen)]
    normal = df_tr.loc[df_tr["label"] == "normal", NUMERIC_COLS].drop_duplicates()
    matched = unseen[NUMERIC_COLS + ["label"]].merge(normal, on=NUMERIC_COLS)
    return {
        "unseen_attack_rows": int(len(unseen)),
        "matching_normal_rows": int(len(matched)),
        "by_type": {t: int(n) for t, n in matched["label"].value_counts().items()},
    }


def load_recall(results_dir: Path, loo: dict | None, groups: dict[str, str]) -> dict:
    recall = {t: {} for t in groups}
    if loo is not None:
        for t, group in groups.items():
            if group != "held_out":
                continue
            for det, (loo_name, _, _) in DETECTORS.items():
                row = loo["summary"].get(t, {}).get(loo_name)
                if row:
                    recall[t][det] = row[OPERATING_POINT]["recall"]["mean"]
    for det, (_, fname, bname) in DETECTORS.items():
        path = results_dir / fname
        if not path.exists():
            continue
        summary = json.loads(path.read_text())["summary"].get(bname)
        if summary is None or OPERATING_POINT not in summary:
            print(f"  {fname} has no {OPERATING_POINT} numbers, re-run the benchmark")
            continue
        by_type = summary[OPERATING_POINT]["recall_by_group"]
        for t, group in groups.items():
            if group == "unseen_test" and t in by_type:
                recall[t][det] = by_type[t]["mean"]
    for r in recall.values():
        vals = [r[d] for d in BEST_OTHER if d in r]
        if vals:
            r["best_other"] = max(vals)
    return recall


def spearman_ci(a, b, rng) -> dict:
    n = len(a)
    rho = spearmanr(a, b).statistic
    if n < 5 or not np.isfinite(rho):
        return {"rho": None, "n": n}
    boots = []
    for _ in range(N_BOOT):
        i = rng.integers(0, n, n)
        r = spearmanr(a[i], b[i]).statistic
        if np.isfinite(r):
            boots.append(r)
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {"rho": round(float(rho), 3), "ci95": [round(float(lo), 3), round(float(hi), 3)], "n": n}


def leave_one_type_out(x, y, r) -> dict:
    # predict each type's recall from the other types: linear in (x, y) against the mean of the others
    err_model, err_mean = [], []
    for i in range(len(r)):
        keep = np.arange(len(r)) != i
        reg = LinearRegression().fit(np.c_[x[keep], y[keep]], r[keep])
        pred = float(np.clip(reg.predict([[x[i], y[i]]])[0], 0, 1))
        err_model.append(abs(pred - r[i]))
        err_mean.append(abs(r[keep].mean() - r[i]))
    return {"mae_model": round(float(np.mean(err_model)), 3),
            "mae_mean_baseline": round(float(np.mean(err_mean)), 3)}


def analyse(points: dict, rng) -> dict:
    # held_out and unseen_test recall come from different operating points (see protocol), so they are
    # analysed separately as well as pooled
    out = {}
    for name, group in (("all", None), ("held_out", "held_out"), ("unseen_test", "unseen_test")):
        sub = {t: p for t, p in points.items() if group is None or p["group"] == group}
        out[name] = {}
        for det in ("if_normal", "rf", "best_other"):
            rows = [(p["x"], p["y"], p["recall"][det]) for p in sub.values() if det in p["recall"]]
            if len(rows) < 5:
                out[name][det] = {"n": len(rows)}
                continue
            x, y, r = (np.array(c, dtype=float) for c in zip(*rows))
            out[name][det] = {
                "n": len(rows),
                "x_vs_recall": spearman_ci(x, r, rng),
                "y_vs_recall": spearman_ci(y, r, rng),
                "leave_one_type_out": leave_one_type_out(x, y, r),
            }
    return out


def rank_stability(points: dict, primary: str) -> dict:
    base = points[primary]
    out = {}
    for name, pts in points.items():
        if name == primary:
            continue
        common = sorted(set(base) & set(pts))
        bx = [base[t]["x"] for t in common]
        by = [base[t]["y"] for t in common]
        px = [pts[t]["x"] for t in common]
        py = [pts[t]["y"] for t in common]
        out[name] = {
            "x_rank_rho_vs_primary": round(float(spearmanr(bx, px).statistic), 3),
            "y_rank_rho_vs_primary": round(float(spearmanr(by, py).statistic), 3),
            "n": len(common),
        }
    return out


def plot_map(points: dict, out_path: Path) -> None:
    panels = [
        ("rf", "Random Forest"),
        ("if_normal", "Isolation Forest (normal-only)"),
        ("best_other", "best other (IF mixed, LOF and OC-SVM normal-only)"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.5), sharex=True, sharey=True)
    sc = None
    for ax, (det, title) in zip(axes, panels):
        for group, marker in (("held_out", "o"), ("unseen_test", "^")):
            items = [(t, p) for t, p in points.items() if p["group"] == group]
            x = np.array([p["x"] for _, p in items])
            y = np.array([p["y"] for _, p in items])
            r = np.array([p["recall"].get(det, np.nan) for _, p in items], dtype=float)
            known = np.isfinite(r)
            ax.scatter(x[~known], y[~known], facecolor="none", edgecolor="grey", marker=marker, s=50)
            sc = ax.scatter(x[known], y[known], c=r[known], cmap="viridis", vmin=0, vmax=1,
                            marker=marker, s=60, edgecolor="black", linewidth=0.5)
            for (t, p), xi, yi in zip(items, x, y):
                if p["rows"] >= 100:
                    ax.annotate(t, (xi, yi), fontsize=7, xytext=(3, 3), textcoords="offset points")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(title, fontsize=10)
        ax.set_xlabel("x: distance from normal flows (log)")
        ax.grid(True, alpha=0.3)
    axes[0].set_ylabel("y: distance from the other attack types")
    axes[0].scatter([], [], marker="o", color="grey", label="KDDTrain+ type (held out)")
    axes[0].scatter([], [], marker="^", color="grey", label="KDDTest+ unseen type")
    axes[0].legend(loc="upper left", fontsize=8)
    if sc is not None:
        fig.colorbar(sc, ax=axes, label="recall at 5% false alarms (hollow: no recall)")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"map saved to {out_path}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="detection map of NSL-KDD attack types")
    ap.add_argument("--train", default="", help="path to KDDTrain+.txt (auto-downloaded if blank)")
    ap.add_argument("--test", default="", help="path to KDDTest+.txt (auto-downloaded if blank)")
    ap.add_argument("--ks", type=int, nargs="+", default=[1, 5, 20], help="neighbour counts")
    ap.add_argument("--primary-k", type=int, default=5, help="k used for the figure and the tests")
    ap.add_argument("--results", default="results", help="folder with leave_one_out.json and benchmarks")
    ap.add_argument("--out", default="results/detection_map.json")
    args = ap.parse_args(argv)
    if args.primary_k not in args.ks:
        ap.error("--primary-k must be one of --ks")

    data_dir = Path("data") / "nslkdd"
    train_path = Path(args.train) if args.train else data_dir / "KDDTrain+.txt"
    test_path = Path(args.test) if args.test else data_dir / "KDDTest+.txt"
    print("getting the dataset")
    download_if_missing(TRAIN_URL, train_path)
    download_if_missing(TEST_URL, test_path)

    df_tr, df_te = load_nslkdd(train_path), load_nslkdd(test_path)
    check_categories(df_tr["label"])
    check_categories(df_te["label"])

    points = {}
    for space, levels in (("drop", None), ("onehot", category_levels(df_tr))):
        print(f"feature space: {space}")
        X_tr, X_te = feature_matrices(df_tr, df_te, levels)
        for k, pos in positions(df_tr, df_te, X_tr, X_te, args.ks).items():
            points[f"{space}_k{k}"] = pos

    primary = f"drop_k{args.primary_k}"
    groups = {t: p["group"] for t, p in points[primary].items()}
    results_dir = Path(args.results)
    loo_path = results_dir / "leave_one_out.json"
    loo = json.loads(loo_path.read_text()) if loo_path.exists() else None
    recall = load_recall(results_dir, loo, groups)
    for setting in points.values():
        for t, p in setting.items():
            p["recall"] = recall[t]

    rng = np.random.default_rng(0)
    results = {
        "dataset": "NSL-KDD (KDDTrain+ / KDDTest+)",
        "protocol": {
            "x": "median over the type's flows of the mean distance to the k nearest normal KDDTrain+ flows",
            "y": "same, to the k nearest KDDTrain+ flows of the other attack types (the type itself excluded)",
            "groups": "held_out: KDDTrain+ types with >= 20 rows (recall from leave_one_out.json, test false-alarm "
                      "rate about 5% because test normals come from the same file); unseen_test: KDDTest+ types "
                      "absent from KDDTrain+ (query rows from KDDTest+, recall from the benchmark JSONs at the 5% "
                      "validation target, where the test false-alarm rate drifts: RF 12.6%, IF normal-only 2.2%)",
            "scaler": "fit on all KDDTrain+ rows; the drop space is the 38 numeric columns, onehot adds the "
                      "3 categorical columns as one-hot",
            "analysis_only": "grouping KDDTest+ rows by type is for this analysis only; no model sees the test labels",
            "pre_registered": "x vs if_normal recall and y vs rf recall; the other pairs are reported for contrast",
            "primary": primary,
        },
        "ks": args.ks,
        "points": points,
        "duplicates": exact_duplicates(df_tr, df_te),
        "analysis": analyse(points[primary], rng),
        "rank_stability": rank_stability(points, primary),
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\nresults saved to {out_path}")

    plot_map(points[primary], out_path.with_suffix(".png"))

    print(f"\n{'type':<18}{'group':<13}{'rows':>8}{'x':>9}{'y':>9}")
    for t, p in sorted(points[primary].items(), key=lambda kv: kv[1]["x"]):
        print(f"{t:<18}{p['group']:<13}{p['rows']:>8,}{p['x']:>9.3f}{p['y']:>9.3f}")
    print(f"\nduplicates: {results['duplicates']}")
    print(f"rank stability: {results['rank_stability']}")


if __name__ == "__main__":
    main()
