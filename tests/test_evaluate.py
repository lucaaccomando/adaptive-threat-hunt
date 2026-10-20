import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from evaluate import NSL_KDD_COLUMNS, NUMERIC_COLS, mean_std, pick_threshold, run_benchmark


def _write_nslkdd(path, n, seed, flip_labels=False):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(rng.random((n, len(NSL_KDD_COLUMNS))), columns=NSL_KDD_COLUMNS)
    is_attack = rng.random(n) < 0.5
    # attacks get shifted numeric features so the models have something to find
    df.loc[is_attack, NUMERIC_COLS] += 2.0
    if flip_labels:
        is_attack = ~is_attack
    df["protocol_type"] = "tcp"
    df["service"] = "http"
    df["flag"] = "SF"
    df["label"] = np.where(is_attack, "neptune", "normal")
    df["difficulty"] = 10
    df.to_csv(path, header=False, index=False)


def test_pick_threshold_uses_only_given_scores():
    y = np.array([0, 0, 0, 1, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
    assert pick_threshold(y, s) == 0.7


def test_mean_std():
    assert mean_std([1.0, 3.0]) == {"mean": 2.0, "std": 1.4142}
    assert mean_std([5.0]) == {"mean": 5.0, "std": 0.0}


def test_threshold_ignores_test_labels(tmp_path):
    train = tmp_path / "train.txt"
    _write_nslkdd(train, 400, seed=1)
    test_a, test_b = tmp_path / "test_a.txt", tmp_path / "test_b.txt"
    _write_nslkdd(test_a, 200, seed=2)
    _write_nslkdd(test_b, 200, seed=2, flip_labels=True)

    res_a, _, _ = run_benchmark(["iforest", "rf"], train, test_a, [0], 0.1)
    res_b, _, _ = run_benchmark(["iforest", "rf"], train, test_b, [0], 0.1)

    for name in ("Isolation Forest", "Random Forest"):
        a = res_a["per_seed"]["0"][name]["val_threshold"]
        b = res_b["per_seed"]["0"][name]["val_threshold"]
        assert a["threshold"] == b["threshold"]
        assert a["val_f1"] == b["val_f1"]


def test_benchmark_output_shape(tmp_path):
    train, test = tmp_path / "train.txt", tmp_path / "test.txt"
    _write_nslkdd(train, 400, seed=1)
    _write_nslkdd(test, 200, seed=2)

    res, scores, y_test = run_benchmark(["iforest"], train, test, [0, 1], 0.1)

    assert res["seeds"] == [0, 1]
    assert set(res["per_seed"]) == {"0", "1"}
    summ = res["summary"]["Isolation Forest"]
    assert set(summ) == {"roc_auc", "pr_auc", "default", "val_threshold"}
    assert 0.0 <= summ["val_threshold"]["f1"]["mean"] <= 1.0
    assert len(scores["Isolation Forest"]) == len(y_test) == 200
