import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
sys.path.insert(0, str(Path(__file__).parent))
from evaluate import NSL_KDD_COLUMNS
from leave_one_out import (
    MIN_ROWS,
    holdout_sets,
    leave_out_split,
    run_leave_one_out,
    seed_split,
)
from test_evaluate import _write_nslkdd


def _labels(counts: dict[str, int]) -> np.ndarray:
    return np.array([t for t, n in counts.items() for _ in range(n)])


def _write_multi_attack(path, n, seed):
    _write_nslkdd(path, n, seed)
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    rng = np.random.default_rng(seed)
    attacks = df["label"] != "normal"
    df.loc[attacks, "label"] = rng.choice(["neptune", "smurf", "satan", "guess_passwd"], attacks.sum())
    df.to_csv(path, header=False, index=False)


def test_holdout_sets_skip_rare_types_and_add_categories():
    labels = _labels({"normal": 500, "neptune": 400, "smurf": 50, "satan": MIN_ROWS,
                      "perl": MIN_ROWS - 1, "ftp_write": 4})
    sets, skipped = holdout_sets(labels)
    assert sets["neptune"] == ["neptune"] and "perl" not in sets
    assert sets["DoS"] == ["neptune", "smurf"]
    assert sets["Probe"] == ["satan"]
    assert "R2L" not in sets and "U2R" not in sets
    assert skipped == {"ftp_write": 4, "perl": MIN_ROWS - 1}


def test_held_out_rows_never_reach_train_or_validation():
    labels = _labels({"normal": 600, "neptune": 200, "satan": 100})
    y = (labels != "normal").astype(int)
    test_normal, idx_tr, idx_val = seed_split(y, seed=3)
    assert not set(test_normal) & (set(idx_tr) | set(idx_val))

    tr, val, test_idx, held = leave_out_split(labels, test_normal, idx_tr, idx_val, ["satan"])
    assert "satan" not in set(labels[tr]) | set(labels[val])
    assert (labels[test_idx][held] == "satan").all() and held.sum() == 100
    assert set(labels[test_idx][~held]) == {"normal"}
    assert set(test_idx[held]) == set(np.flatnonzero(labels == "satan"))


def test_split_is_stable_per_seed_and_changes_across_seeds():
    y = np.array([0] * 300 + [1] * 200)
    a, b = seed_split(y, 0), seed_split(y, 0)
    assert all((x == z).all() for x, z in zip(a, b))
    assert not (seed_split(y, 1)[0] == a[0]).all()


def test_leave_one_out_output_shape_and_fpr_targets(tmp_path):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 1500, seed=1)
    out = tmp_path / "loo.json"

    res = run_leave_one_out(["iforest", "rf"], train, [0, 1], 0.1, ["neptune", "DoS"], out)

    assert out.exists() and res["seeds"] == [0, 1]
    assert set(res["holdouts"]) == {"neptune", "DoS"}
    assert res["holdouts"]["DoS"]["types"] == ["neptune", "smurf"]
    models = set(res["summary"]["neptune"])
    assert models == {"Isolation Forest (mixed)", "Isolation Forest (normal-only)", "Random Forest"}
    for run in res["per_seed"].values():
        for hold in run.values():
            for m in hold.values():
                assert m["fpr_1pct"]["val_fpr"] <= 0.01 and m["fpr_5pct"]["val_fpr"] <= 0.05
                assert m["fpr_1pct"]["recall"] <= m["fpr_5pct"]["recall"]


def test_compact_keeps_only_reported_fields():
    from leave_one_out import SETTINGS, compact
    res = {"roc_auc": 0.9, "extra": 1}
    res.update({s: {"recall": 0.5, "fpr": 0.04, "val_fpr": 0.05, "extra": 1} for s in SETTINGS})
    out = compact(res)
    assert set(out) == {"roc_auc", *SETTINGS}
    assert out["fpr_1pct"] == {"recall": 0.5, "fpr": 0.04, "val_fpr": 0.05}


def test_summarize_means_over_seeds():
    from leave_one_out import SETTINGS, summarize
    def run(auc):
        m = {"roc_auc": auc}
        m.update({s: {"recall": 0.5, "fpr": 0.04, "val_fpr": 0.05} for s in SETTINGS})
        return {"neptune": {"rf": m}}
    out = summarize({0: run(0.9), 1: run(0.7)})
    assert out["neptune"]["rf"]["roc_auc"]["mean"] == 0.8
    assert out["neptune"]["rf"]["val_threshold"]["recall"] == {"mean": 0.5, "std": 0.0}
