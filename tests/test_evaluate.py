import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from evaluate import (
    ATTACK_CATEGORIES,
    CATEGORY_OF,
    GRIDS,
    HEAVY_TAILED_COLS,
    NSL_KDD_COLUMNS,
    MODELS,
    NUMERIC_COLS,
    OP_SETTINGS,
    apply_transform,
    attack_groups,
    check_categories,
    engineer_features,
    fpr_threshold,
    mean_std,
    operating_point,
    pick_threshold,
    precision_at_prevalence,
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


def test_fpr_threshold_caps_false_alarms():
    s = np.arange(100, dtype=float)
    assert (s >= fpr_threshold(s, 0.05)).sum() == 5
    assert (s >= fpr_threshold(s, 0.01)).sum() == 1


def test_fpr_threshold_with_ties_stays_under_target():
    # ten normal rows share the top score, so allowing 5 alerts would mean splitting the tie
    s = np.array([0.0] * 90 + [1.0] * 10)
    assert (s >= fpr_threshold(s, 0.05)).sum() == 0


def test_fpr_threshold_rejects_bad_target():
    for bad in (0.0, 1.0, -0.1):
        with pytest.raises(ValueError):
            fpr_threshold(np.arange(10.0), bad)


def test_precision_at_prevalence():
    assert precision_at_prevalence(0.9, 0.1, 0.5) == pytest.approx(0.9)
    assert precision_at_prevalence(0.5, 0.01, 0.01) == pytest.approx(0.005 / 0.0149)
    assert precision_at_prevalence(0.0, 0.0, 0.1) == 0.0


def test_operating_point_by_hand():
    y_test = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    s_test = np.array([0.1, 0.2, 0.6, 0.3, 0.7, 0.4, 0.8, 0.9])
    y_val = np.array([0, 0, 1, 1])
    s_val = np.array([0.1, 0.6, 0.7, 0.9])
    op = operating_point(0.5, s_val, y_val, s_test, y_test, {"attacks": y_test == 1})
    assert (op["tp"], op["fn"], op["fp"], op["tn"]) == (3, 1, 1, 3)
    assert op["recall"] == 0.75 and op["fpr"] == 0.25
    assert op["val_f1"] == 0.8 and op["val_fpr"] == 0.5
    assert op["f1_gap"] == -0.05 and op["fpr_gap"] == -0.25
    assert op["alerts_per_10k_normal"] == 2500.0
    assert op["precision_prev10"] == 0.25
    assert op["recall_by_group"] == {"attacks": 0.75}


def test_threshold_ignores_test_labels(tmp_path):
    train = tmp_path / "train.txt"
    _write_nslkdd(train, 400, seed=1)
    test_a, test_b = tmp_path / "test_a.txt", tmp_path / "test_b.txt"
    _write_nslkdd(test_a, 200, seed=2)
    _write_nslkdd(test_b, 200, seed=2, flip_labels=True)

    res_a, _, _ = run_benchmark(["iforest", "rf"], train, test_a, [0], 0.1)
    res_b, _, _ = run_benchmark(["iforest", "rf"], train, test_b, [0], 0.1)

    for name in ("Isolation Forest", "Random Forest"):
        for setting in OP_SETTINGS:
            a = res_a["per_seed"]["0"][name][setting]
            b = res_b["per_seed"]["0"][name][setting]
            assert a["threshold"] == b["threshold"]
            assert a["val_f1"] == b["val_f1"]
            assert a["val_fpr"] == b["val_fpr"]


def test_benchmark_output_shape(tmp_path):
    train, test = tmp_path / "train.txt", tmp_path / "test.txt"
    _write_nslkdd(train, 400, seed=1)
    _write_nslkdd(test, 200, seed=2)

    res, scores, y_test = run_benchmark(["iforest"], train, test, [0, 1], 0.1)

    assert res["seeds"] == [0, 1]
    assert set(res["per_seed"]) == {"0", "1"}
    summ = res["summary"]["Isolation Forest"]
    assert set(summ) == {"roc_auc", "pr_auc", "val_pr_auc", "default", *OP_SETTINGS}
    assert 0.0 <= summ["val_threshold"]["f1"]["mean"] <= 1.0
    assert len(scores["Isolation Forest"]) == len(y_test) == 200
    assert res["attack_prevalence"]["test"] == round(float(y_test.mean()), 4)


def test_fixed_fpr_points_respect_validation_target(tmp_path):
    train, test = tmp_path / "train.txt", tmp_path / "test.txt"
    _write_nslkdd(train, 400, seed=1)
    _write_nslkdd(test, 200, seed=2)

    res, _, _ = run_benchmark(["iforest", "lof", "ocsvm", "rf"], train, test, [0], 0.1)

    for r in res["per_seed"]["0"].values():
        assert r["fpr_1pct"]["val_fpr"] <= 0.01
        assert r["fpr_5pct"]["val_fpr"] <= 0.05
        assert r["fpr_1pct"]["threshold"] >= r["fpr_5pct"]["threshold"]
        assert r["fpr_1pct"]["recall"] <= r["fpr_5pct"]["recall"]


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


def test_log1p_only_touches_heavy_tailed_columns():
    X = np.full((2, len(NUMERIC_COLS)), 3.0)
    out = apply_transform(X, "log1p")
    changed = [NUMERIC_COLS[i] for i in np.flatnonzero(out[0] != 3.0)]
    assert sorted(changed) == sorted(HEAVY_TAILED_COLS)
    assert np.allclose(out[0, NUMERIC_COLS.index("src_bytes")], np.log1p(3.0))
    assert (X == 3.0).all()
    assert apply_transform(X, "none") is X


def test_grids_cover_every_model_without_duplicates():
    assert set(GRIDS) == set(MODELS)
    for key, grid in GRIDS.items():
        assert len(grid) > 1
        assert len({tuple(sorted(g.items(), key=str)) for g in grid}) == len(grid)


def test_tuning_picks_on_validation_only(tmp_path):
    train = tmp_path / "train.txt"
    _write_nslkdd(train, 400, seed=1)
    test_a, test_b = tmp_path / "test_a.txt", tmp_path / "test_b.txt"
    _write_nslkdd(test_a, 200, seed=2)
    _write_nslkdd(test_b, 200, seed=2, flip_labels=True)

    res_a, _, _ = run_benchmark(["lof", "rf"], train, test_a, [0], 0.1, transform="log1p", tune=True)
    res_b, _, _ = run_benchmark(["lof", "rf"], train, test_b, [0], 0.1, transform="log1p", tune=True)

    assert res_a["ablation"]["tuned"] and res_a["ablation"]["transform"] == "log1p"
    for name, key in (("Local Outlier Factor", "lof"), ("Random Forest", "rf")):
        a, b = res_a["per_seed"]["0"][name], res_b["per_seed"]["0"][name]
        assert a["params"] == b["params"] and a["val_pr_auc"] == b["val_pr_auc"]
        assert a["params"] in GRIDS[key]
    untuned, _, _ = run_benchmark(["lof"], train, test_a, [0], 0.1)
    assert untuned["per_seed"]["0"]["Local Outlier Factor"]["params"] == GRIDS["lof"][0]
