#!/usr/bin/env python3
# how far each common evaluation mistake moves the headline number. reads results/*.json only;
# the one formula (flag-all F1 at the test base rate) uses the prevalence stored in the JSON
#
# usage:
#   python models/pitfalls.py
#   python models/pitfalls.py --results results --out results/pitfalls.json

import argparse
import json
from pathlib import Path

MODELS = ["Isolation Forest", "Local Outlier Factor", "One-Class SVM", "Random Forest"]
FILES = {
    "default": "benchmark.json",
    "normal_only": "benchmark_normal_only.json",
    "onehot": "benchmark_onehot.json",
}
FPR_TARGET = 0.05


def load(results: Path, name: str) -> dict:
    return json.loads((results / name).read_text())


def mean(run: dict, model: str, *path: str) -> float:
    node = run["summary"][model]
    for key in path:
        node = node[key]
    return float(node["mean"])


def flag_all_f1(prevalence: float) -> float:
    # alert on every flow: precision = p, recall = 1, so F1 = 2p / (1 + p)
    return 2 * prevalence / (1 + prevalence)


def rows(runs: dict, prevalence: float) -> list[dict]:
    d, n, o = runs["default"], runs["normal_only"], runs["onehot"]
    out = []

    def add(pitfall, model, metric, with_mistake, without_mistake, source):
        out.append({
            "pitfall": pitfall, "model": model, "metric": metric,
            "with_mistake": round(with_mistake, 4), "without_mistake": round(without_mistake, 4),
            "shift": round(with_mistake - without_mistake, 4), "source": source,
        })

    for m in MODELS:
        add("threshold chosen on test labels", m, "F1",
            mean(d, m, "oracle_test_max_f1", "f1"), mean(d, m, "val_threshold", "f1"), FILES["default"])
    for m in MODELS:
        add("max-F1 threshold reported as the operating point", m, "test FPR",
            mean(d, m, "val_threshold", "fpr"), mean(d, m, "fpr_5pct", "fpr"), FILES["default"])
    for m in MODELS:
        add("F1 at the test base rate instead of a 1% base rate", m, "precision",
            mean(d, m, "val_threshold", "precision"), mean(d, m, "val_threshold", "precision_prev1"),
            FILES["default"])
    for m in MODELS:
        add("default threshold instead of a validation-chosen one", m, "F1",
            mean(d, m, "default", "f1"), mean(d, m, "val_threshold", "f1"), FILES["default"])
    for m in ["Isolation Forest", "Local Outlier Factor", "One-Class SVM"]:
        add("training on all flows instead of normal flows (unsupervised)", m, "unseen recall at max F1",
            mean(d, m, "val_threshold", "recall_by_group", "unseen"),
            mean(n, m, "val_threshold", "recall_by_group", "unseen"), FILES["default"])
    for m in MODELS:
        add("fixed false-alarm target drifts under the shift", m, "test FPR at 5% target",
            mean(d, m, "fpr_5pct", "fpr"), FPR_TARGET, FILES["default"])
    for m in MODELS:
        add("one-hot instead of dropped categorical columns (sensitivity)", m, "F1 at max F1",
            mean(o, m, "val_threshold", "f1"), mean(d, m, "val_threshold", "f1"), FILES["onehot"])
    add("a flag-all detector reported as a result", "Local Outlier Factor", "F1 at max F1",
        mean(d, "Local Outlier Factor", "val_threshold", "f1"), flag_all_f1(prevalence), FILES["default"])
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="evaluation pitfalls, read from the benchmark JSON files")
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="results/pitfalls.json")
    args = ap.parse_args(argv)

    results = Path(args.results)
    runs = {k: load(results, f) for k, f in FILES.items()}
    prevalence = runs["default"]["attack_prevalence"]["test"]
    table = rows(runs, prevalence)

    out = {
        "test_attack_prevalence": prevalence,
        "source_files": FILES,
        "rows": table,
        "not_yet": ["one dataset vs two (P0-10, needs a second dataset)"],
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))
    print(f"pitfalls saved to {out_path}")
    for r in table:
        print(f"{r['pitfall'][:52]:<52} {r['model'][:22]:<22} {r['metric'][:20]:<20} "
              f"{r['with_mistake']:>8.4f} {r['without_mistake']:>8.4f} {r['shift']:>+9.4f}")


if __name__ == "__main__":
    main()
