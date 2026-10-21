import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from evaluate import (
    ATTACK_CATEGORIES,
    CATEGORY_OF,
    NSL_KDD_COLUMNS,
    NUMERIC_COLS,
    attack_groups,
    check_categories,
    engineer_features,
    mean_std,
    pick_threshold,
    run_benchmark,
)

DATA = Path(__file__).parent.parent / "data" / "nslkdd"


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


def test_onehot_uses_training_levels():
    df = pd.DataFrame({**{c: [0.0, 0.0] for c in NUMERIC_COLS},
                       "protocol_type": ["tcp", "icmp"], "service": ["http", "http"],
                       "flag": ["SF", "SF"], "binary_label": [0, 1]})
    levels = {"protocol_type": ["tcp", "udp"], "service": ["http"], "flag": ["REJ", "SF"]}
    X, _ = engineer_features(df, levels)
    assert X.shape == (2, len(NUMERIC_COLS) + 5)
    assert X[0, len(NUMERIC_COLS):].tolist() == [1, 0, 1, 0, 1]
    # icmp was not in the training levels, so the protocol block is all zeros
    assert X[1, len(NUMERIC_COLS):len(NUMERIC_COLS) + 2].tolist() == [0, 0]
    assert engineer_features(df)[0].shape == (2, len(NUMERIC_COLS))


def test_ablation_flags(tmp_path):
    train, test = tmp_path / "train.txt", tmp_path / "test.txt"
    _write_nslkdd(train, 400, seed=1)
    _write_nslkdd(test, 200, seed=2)
    models = ["iforest", "rf"]

    base, _, _ = run_benchmark(models, train, test, [0], 0.1)
    normal, _, _ = run_benchmark(models, train, test, [0], 0.1, train_on="normal")
    onehot, _, _ = run_benchmark(models, train, test, [0], 0.1, categorical="onehot")

    assert normal["ablation"] == {**base["ablation"], "train_on": "normal"}
    assert onehot["n_features"] == base["n_features"] + 3
    # rf sees both classes whatever the flag says, so only the unsupervised model moves
    rf = lambda r: r["per_seed"]["0"]["Random Forest"]["val_threshold"]
    iforest = lambda r: r["per_seed"]["0"]["Isolation Forest"]["val_threshold"]
    assert rf(normal) == rf(base)
    assert iforest(normal)["threshold"] != iforest(base)["threshold"]


def test_attack_groups_seen_and_unseen():
    train = ["normal", "neptune", "neptune", "satan"]
    test = ["normal", "neptune", "apache2", "satan", "mscan", "normal"]
    g = attack_groups(train, test)
    assert g["seen"].tolist() == [False, True, False, True, False, False]
    assert g["unseen"].tolist() == [False, False, True, False, True, False]
    assert g["DoS"].tolist() == [False, True, True, False, False, False]
    assert g["Probe"].tolist() == [False, False, False, True, True, False]


def test_check_categories_rejects_unknown_label():
    check_categories(["normal", "neptune", "worm"])
    with pytest.raises(ValueError, match="made_up_attack"):
        check_categories(["normal", "made_up_attack"])


def test_categories_do_not_overlap():
    assert sum(len(s) for s in ATTACK_CATEGORIES.values()) == len(CATEGORY_OF)


@pytest.mark.skipif(not (DATA / "KDDTest+.txt").exists(), reason="dataset not present")
def test_every_nslkdd_label_has_a_category():
    for name in ("KDDTrain+.txt", "KDDTest+.txt"):
        labels = pd.read_csv(DATA / name, header=None, names=NSL_KDD_COLUMNS)["label"]
        check_categories(labels)
        attacks = labels[labels != "normal"]
        assert attacks.map(CATEGORY_OF).notna().all()
