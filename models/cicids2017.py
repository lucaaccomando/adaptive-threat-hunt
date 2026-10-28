#!/usr/bin/env python3
# second dataset: the improved CIC-IDS2017 flows. train and validate on Monday-Wednesday, test on Thursday-Friday,
# where every attack type is new. same models, thresholds and helpers as evaluate.py, leave_one_out.py, detection_map.py
#
# usage:
#   python models/cicids2017.py benchmark
#   python models/cicids2017.py benchmark --train-on normal
#   python models/cicids2017.py leave-one-out
#   python models/cicids2017.py map

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

import cicids_data
from cicids_data import CATEGORIES, TRAIN_DAYS
from detection_map import analyse, load_recall, plot_map, positions, rank_stability
from evaluate import MODELS, VAL_FRACTION, evaluate_model, plot_pr_curves
from evaluate import summarize as summarize_benchmark
from leave_one_out import MIN_ROWS, TEST_NORMAL_FRACTION, compact, holdout_sets, leave_out_split
from leave_one_out import summarize as summarize_leave_one_out

# per seed, rows are sampled so that LOF and RF stay fast: every attack type is capped, normal flows too
POOL_CAPS = {"normal": 80_000, "attack": 8_000}
TEST_CAPS = {"normal": 40_000, "attack": 10_000}
RESULTS = Path("results")
SPACES = ("none", "slog1p")


def transform(X: np.ndarray, name: str) -> np.ndarray:
    X = X.astype(float)
    return X if name == "none" else np.sign(X) * np.log1p(np.abs(X))


def sample_rows(labels, rows, caps, rng) -> np.ndarray:
    picked = []
    for lab in np.unique(labels[rows]):
        r = rows[labels[rows] == lab]
        cap = caps["normal"] if lab == "normal" else caps["attack"]
        picked.append(rng.choice(r, cap, replace=False) if len(r) > cap else r)
    return np.sort(np.concatenate(picked))


def block_roles(blocks, rng, test_frac: float) -> np.ndarray:
    # whole 10-minute blocks go to one role, so near-identical flows of one burst do not straddle train and validation
    order = rng.permutation(np.unique(blocks))
    n_test = int(round(test_frac * len(order)))
    rest = order[n_test:]
    role = np.zeros(len(blocks), dtype=np.int8)
    role[np.isin(blocks, rest[:int(round(VAL_FRACTION * len(rest)))])] = 1
    role[np.isin(blocks, order[:n_test])] = 2
    return role


def type_groups(labels) -> dict[str, np.ndarray]:
    groups = {}
    for t in np.unique(labels[labels != "normal"]):
        groups[str(t)] = labels == t
    for cat, names in CATEGORIES.items():
        mask = np.isin(labels, list(names))
        if mask.any():
            groups[cat] = mask
    return groups


def draw(data: dict, seed: int):
    rng = np.random.default_rng(seed)
    labels = data["label"]
    pool = sample_rows(labels, np.flatnonzero(data["day"] < TRAIN_DAYS), POOL_CAPS, rng)
    test = sample_rows(labels, np.flatnonzero(data["day"] >= TRAIN_DAYS), TEST_CAPS, rng)
    return pool, test, rng


def run_benchmark(data, keys, seeds, contamination, train_on="mixed", tfm="none"):
    labels, X_all = data["label"], data["X"]
    per_seed, first_scores, first_y, first_groups = {}, {}, None, None
    for seed in seeds:
        print(f"\nseed {seed}")
        pool, test, rng = draw(data, seed)
        role = block_roles(data["block"][pool], rng, 0.0)
        idx_tr, idx_val = pool[role == 0], pool[role == 1]
        scaler = StandardScaler().fit(transform(X_all[idx_tr], tfm))
        X_tr, X_val, X_test = (scaler.transform(transform(X_all[i], tfm)) for i in (idx_tr, idx_val, test))
        y_tr, y_val, y_test = ((labels[i] != "normal").astype(int) for i in (idx_tr, idx_val, test))
        groups = type_groups(labels[test])
        if first_y is None:
            first_y, first_groups = y_test, groups
            print(f"  train {len(y_tr):,} ({int(y_tr.sum()):,} attacks), validation {len(y_val):,} "
                  f"({int(y_val.sum()):,}), test {len(y_test):,} ({int(y_test.sum()):,})")
        per_seed[str(seed)] = {}
        for key in keys:
            res, s_test = evaluate_model(key, X_tr, y_tr, X_val, y_val, X_test, y_test, groups, seed,
                                         contamination, normal_only=train_on == "normal")
            per_seed[str(seed)][MODELS[key]] = res
            if seed == seeds[0]:
                first_scores[MODELS[key]] = s_test
            lo, hi, v = res["fpr_1pct"], res["fpr_5pct"], res["val_threshold"]
            print(f"  {MODELS[key]:<22} roc_auc={res['roc_auc']:.4f}  recall@1%={lo['recall']:.4f} "
                  f"(fpr {lo['fpr']:.4f})  recall@5%={hi['recall']:.4f} (fpr {hi['fpr']:.4f})  "
                  f"max-F1={v['f1']:.4f}  val_pr_auc={res['val_pr_auc']:.4f}", flush=True)

    results = {
        "dataset": "CIC-IDS2017, improved release (Engelen et al.), train Monday-Wednesday, test Thursday-Friday",
        "n_features": int(X_all.shape[1]),
        "ablation": {"train_on": train_on, "transform": tfm,
                     "note": "train_on=normal only changes the unsupervised models; rf always sees both classes"},
        "protocol": {
            "sample": f"per seed, normal flows capped at {POOL_CAPS['normal']:,} (train and validation pool) and "
                      f"{TEST_CAPS['normal']:,} (test), every attack type at {POOL_CAPS['attack']:,} / "
                      f"{TEST_CAPS['attack']:,}; sampling is part of the seed",
            "split": f"10-minute blocks of Monday-Wednesday go {1 - VAL_FRACTION:.0%} / {VAL_FRACTION:.0%} to train / "
                     "validation, new assignment per seed; Thursday-Friday is the test set",
            "novelty": "every attack type in the test set is absent from Monday-Wednesday",
            "labels": "'... - Attempted' flows are relabelled benign, as the authors recommend",
            "features": "82 numeric CICFlowMeter columns; identifiers, ports, time stamp and label columns dropped",
            "transform": "none, or sign(x) * log1p(|x|) on every column (slog1p), applied before scaling",
            "thresholds": "as in evaluate.py: max F1, 1% / 5% false alarms on validation normals, quantiles, oracle",
            "scaler": "fit on the training split only",
            "std": "sample std over seeds (ddof=1)",
        },
        "test_groups": {"flows_per_group_seed0": {g: int(m.sum()) for g, m in first_groups.items()}},
        "seeds": list(seeds),
        "summary": summarize_benchmark(per_seed),
        "per_seed": per_seed,
    }
    return results, first_scores, first_y


def run_leave_one_out(data, keys, seeds, contamination, tfm, holdouts=None, out_path=None):
    labels, X_all = data["label"], data["X"]
    per_seed, sets, skipped, rows = {}, None, None, None
    for seed in seeds:
        pool, _, rng = draw(data, seed)
        lp, Xp, yp = labels[pool], transform(X_all[pool], tfm), (labels[pool] != "normal").astype(int)
        if sets is None:
            sets, skipped = holdout_sets(lp, CATEGORIES)
            if holdouts:
                sets = {h: sets[h] for h in holdouts}
            rows = {h: int(np.isin(lp, names).sum()) for h, names in sets.items()}
            print(f"  {len(sets)} held-out sets, skipped (under {MIN_ROWS} rows): {skipped}")
        role = block_roles(data["block"][pool], rng, TEST_NORMAL_FRACTION)
        test_normal = np.flatnonzero((role == 2) & (yp == 0))
        idx_tr, idx_val = np.flatnonzero(role == 0), np.flatnonzero(role == 1)
        per_seed[str(seed)] = {}
        for hold, names in sets.items():
            tr, val, test_idx, held = leave_out_split(lp, test_normal, idx_tr, idx_val, names)
            scaler = StandardScaler().fit(Xp[tr])
            X_tr, X_val, X_test = (scaler.transform(Xp[i]) for i in (tr, val, test_idx))
            out = per_seed[str(seed)][hold] = {}
            for key in keys:
                for normal_only in ([False, True] if key != "rf" else [False]):
                    name = MODELS[key] + ("" if key == "rf" else " (normal-only)" if normal_only else " (mixed)")
                    res, _ = evaluate_model(key, X_tr, yp[tr], X_val, yp[val], X_test, yp[test_idx],
                                            {"held_out": held}, seed, contamination, normal_only=normal_only)
                    out[name] = compact(res)
            print(f"  seed {seed}  {hold:<26} " + "  ".join(
                f"{n.replace('Random Forest', 'RF').replace('Isolation Forest', 'IF')}={m['fpr_5pct']['recall']:.2f}"
                for n, m in out.items()), flush=True)
        results = {
            "dataset": "CIC-IDS2017 improved, Monday-Wednesday only",
            "protocol": {
                "sample": "per seed, the same capped sample of Monday-Wednesday as the benchmark",
                "split": f"10-minute blocks: {TEST_NORMAL_FRACTION:.0%} of blocks are test blocks (their normal flows "
                         f"are the test normals), the rest goes {1 - VAL_FRACTION:.0%} / {VAL_FRACTION:.0%} to train / validation",
                "held_out": "all rows of the held-out type or category go to the test set and are removed "
                            "from train and validation; scaler and thresholds never see them",
                "thresholds": "max F1, and 1% / 5% false alarms on validation normals, as in evaluate.py",
                "transform": tfm,
            },
            "min_rows": MIN_ROWS,
            "skipped_types": skipped,
            "holdouts": {h: {"types": names, "rows": rows[h]} for h, names in sets.items()},
            "seeds": [int(s) for s in per_seed],
            "summary": summarize_leave_one_out(per_seed),
            "per_seed": per_seed,
        }
        if out_path:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(results, indent=2))
    return results


def row_hashes(X: np.ndarray) -> np.ndarray:
    return pd.util.hash_pandas_object(pd.DataFrame(X), index=False).to_numpy()


def exact_duplicates(data: dict) -> dict:
    labels, day = data["label"], data["day"]
    normal = row_hashes(data["X"][(day < TRAIN_DAYS) & (labels == "normal")])
    test = (day >= TRAIN_DAYS) & (labels != "normal")
    hit = np.isin(row_hashes(data["X"][test]), normal)
    return {"test_attack_rows": int(test.sum()), "matching_normal_rows": int(hit.sum()),
            "by_type": {t: int(n) for t, n in pd.Series(labels[test][hit]).value_counts().items()}}


def run_map(data, ks, primary_k, tfm, results_dir, prefix, seed=0):
    pool, test, _ = draw(data, seed)
    labels = data["label"]
    df_tr, df_te = pd.DataFrame({"label": labels[pool]}), pd.DataFrame({"label": labels[test]})
    points = {}
    for space in SPACES:
        print(f"feature space: {space}")
        Xp, Xt = transform(data["X"][pool], space), transform(data["X"][test], space)
        scaler = StandardScaler().fit(Xp)
        for k, pos in positions(df_tr, df_te, scaler.transform(Xp), scaler.transform(Xt), ks, CATEGORIES).items():
            points[f"{space}_k{k}"] = pos

    primary = f"{tfm}_k{primary_k}"
    groups = {t: p["group"] for t, p in points[primary].items()}
    loo_path = results_dir / f"{prefix}leave_one_out.json"
    loo = json.loads(loo_path.read_text()) if loo_path.exists() else None
    recall = load_recall(results_dir, loo, groups, prefix)
    for setting in points.values():
        for t, p in setting.items():
            p["recall"] = recall[t]
    return {
        "dataset": "CIC-IDS2017 improved, seed-0 sample",
        "protocol": {
            "x": "median over the type's flows of the mean distance to the k nearest normal Monday-Wednesday flows",
            "y": "same, to the k nearest Monday-Wednesday flows of the other attack types (the type itself excluded)",
            "groups": f"held_out: Monday-Wednesday types with >= {MIN_ROWS} rows (recall from the leave-one-out run); "
                      "unseen_test: Thursday-Friday types (query rows from the test sample, recall from the "
                      "benchmark JSONs at the 5% validation target)",
            "scaler": "fit on the sampled Monday-Wednesday pool",
            "spaces": "none = raw features, slog1p = sign(x) * log1p(|x|); the primary space is the benchmark transform",
            "analysis_only": "grouping test rows by type is for this analysis only; no model sees the test labels",
            "primary": primary,
        },
        "ks": ks,
        "points": points,
        "duplicates": exact_duplicates(data),
        "analysis": analyse(points[primary], np.random.default_rng(0)),
        "rank_stability": rank_stability(points, primary),
    }


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="CIC-IDS2017 study: benchmark, leave-one-out or detection map")
    ap.add_argument("study", choices=["benchmark", "leave-one-out", "map"])
    ap.add_argument("--train-on", choices=["mixed", "normal"], default="mixed")
    ap.add_argument("--transform", choices=SPACES, default="none")
    ap.add_argument("--contamination", type=float, default=0.1)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--models", nargs="+", choices=list(MODELS), default=list(MODELS))
    ap.add_argument("--holdouts", nargs="+", help="leave-one-out: only these types or categories")
    ap.add_argument("--ks", type=int, nargs="+", default=[1, 5, 20], help="map: neighbour counts")
    ap.add_argument("--primary-k", type=int, default=5)
    ap.add_argument("--results", default="results", help="folder for the JSON files")
    ap.add_argument("--out", default="", help="output JSON path (default depends on the study)")
    args = ap.parse_args(argv)
    if args.study == "map" and args.primary_k not in args.ks:
        ap.error("--primary-k must be one of --ks")

    # the slog1p runs get their own file names, so both feature spaces sit side by side in results/
    results_dir = Path(args.results)
    prefix = "cicids2017_" + ("slog1p_" if args.transform == "slog1p" else "")
    print("loading the dataset")
    data = cicids_data.load()
    print(f"  {len(data['label']):,} flows, {data['X'].shape[1]} features")

    if args.study == "benchmark":
        suffix = "_normal_only" if args.train_on == "normal" else ""
        out_path = Path(args.out or results_dir / f"{prefix}benchmark{suffix}.json")
        results, scores, y_test = run_benchmark(data, args.models, args.seeds, args.contamination,
                                                args.train_on, args.transform)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2))
        print(f"\nresults saved to {out_path}")
        plot_pr_curves(y_test, scores, results["per_seed"][str(args.seeds[0])],
                       out_path.with_name(out_path.stem + "_pr_curves.png"), dataset="CIC-IDS2017 Thu-Fri")
    elif args.study == "leave-one-out":
        out_path = Path(args.out or results_dir / f"{prefix}leave_one_out.json")
        run_leave_one_out(data, args.models, args.seeds, args.contamination, args.transform,
                          args.holdouts, out_path)
        print(f"\nresults saved to {out_path}")
    else:
        out_path = Path(args.out or results_dir / f"{prefix}detection_map.json")
        results = run_map(data, args.ks, args.primary_k, args.transform, results_dir, prefix)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2))
        print(f"\nresults saved to {out_path}")
        plot_map(results["points"][results["protocol"]["primary"]], out_path.with_suffix(".png"),
                 ("Mon-Wed type (held out)", "Thu-Fri new type"))
        for t, p in sorted(results["points"][results["protocol"]["primary"]].items(), key=lambda kv: kv[1]["x"]):
            print(f"{t:<30}{p['group']:<13}{p['rows']:>8,}{p['x']:>9.3f}{p['y']:>9.3f}")


if __name__ == "__main__":
    main()
