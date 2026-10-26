import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
sys.path.insert(0, str(Path(__file__).parent))
from detection_map import (
    exact_duplicates,
    feature_matrices,
    knn_distance,
    leave_one_type_out,
    load_recall,
    main,
    positions,
    spearman_ci,
)
from evaluate import NSL_KDD_COLUMNS, NUMERIC_COLS, load_nslkdd
from test_leave_one_out import _write_multi_attack


def test_knn_distance_is_exact():
    ref = np.array([[3.0, 4.0], [0.0, 1.0], [10.0, 0.0]])
    d = knn_distance(np.array([[0.0, 0.0]]), ref, kmax=2)
    assert np.allclose(d, [[1.0, 5.0]])


def test_positions_match_brute_force_and_exclude_own_type(tmp_path):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 1500, seed=2)
    df_tr = load_nslkdd(train)
    df_te = df_tr.copy()
    df_te.loc[df_te["label"] == "satan", "label"] = "apache2"
    X_tr, X_te = feature_matrices(df_tr, df_te, levels=None)

    pos = positions(df_tr, df_te, X_tr, X_te, ks=[3])[3]
    assert pos["neptune"]["group"] == "held_out"
    assert pos["apache2"]["group"] == "unseen_test"
    assert "normal" not in pos

    labels = df_tr["label"].values
    q = X_tr[labels == "neptune"]
    normal = X_tr[labels == "normal"]
    others = X_tr[(labels != "normal") & (labels != "neptune")]
    dn = np.sort(np.linalg.norm(q[:, None, :] - normal[None], axis=2), axis=1)[:, :3].mean(axis=1)
    da = np.sort(np.linalg.norm(q[:, None, :] - others[None], axis=2), axis=1)[:, :3].mean(axis=1)
    assert abs(pos["neptune"]["x"] - round(float(np.median(dn)), 4)) < 1e-3
    assert abs(pos["neptune"]["y"] - round(float(np.median(da)), 4)) < 1e-3


def test_exact_duplicates_counts_only_matching_normal_rows(tmp_path):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 800, seed=3)
    df_tr = load_nslkdd(train)
    normal_row = df_tr[df_tr["label"] == "normal"].iloc[[0]].copy()
    attack_row = df_tr[df_tr["label"] != "normal"].iloc[[0]].copy()
    attack_row[NUMERIC_COLS] = attack_row[NUMERIC_COLS].values + 0.5
    df_te = pd.concat([normal_row, attack_row]).reset_index(drop=True)
    df_te["label"] = "apache2"
    df_te["binary_label"] = 1
    dup = exact_duplicates(df_tr, df_te)
    assert dup == {"unseen_attack_rows": 2, "matching_normal_rows": 1, "by_type": {"apache2": 1}}


def test_spearman_ci_and_leave_one_type_out_on_a_linear_map():
    rng = np.random.default_rng(0)
    x = rng.random(15)
    y = rng.random(15)
    r = np.clip(0.6 * x + 0.2 * y, 0, 1)
    ci = spearman_ci(r, r, np.random.default_rng(1))
    assert ci["rho"] == 1.0 and ci["ci95"] == [1.0, 1.0] and ci["n"] == 15
    assert 0.5 < spearman_ci(x, r, np.random.default_rng(1))["rho"] < 1.0
    loto = leave_one_type_out(x, y, r)
    assert loto["mae_model"] < 1e-6 and loto["mae_mean_baseline"] > 0.05


def test_spearman_ci_refuses_too_few_types():
    ci = spearman_ci(np.array([1.0, 2.0]), np.array([1.0, 2.0]), np.random.default_rng(0))
    assert ci == {"rho": None, "n": 2}


def test_load_recall_reads_loo_and_benchmark(tmp_path):
    loo = {"summary": {"neptune": {"Random Forest": {"fpr_5pct": {"recall": {"mean": 0.4}}}}}}
    bench = {"summary": {"Random Forest": {"fpr_5pct": {"recall_by_group": {"apache2": {"mean": 0.3}}}}}}
    (tmp_path / "benchmark.json").write_text(json.dumps(bench))
    groups = {"neptune": "held_out", "apache2": "unseen_test"}
    recall = load_recall(tmp_path, loo, groups)
    assert recall["neptune"] == {"rf": 0.4}
    assert recall["apache2"] == {"rf": 0.3}


def test_main_runs_end_to_end_on_small_data(tmp_path):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 1200, seed=4)
    raw = pd.read_csv(train, header=None, names=NSL_KDD_COLUMNS).iloc[:400]
    raw.loc[raw["label"] == "satan", "label"] = "apache2"
    test = tmp_path / "test.txt"
    raw.to_csv(test, header=False, index=False)

    out = tmp_path / "map.json"
    main(["--train", str(train), "--test", str(test), "--results", str(tmp_path),
          "--ks", "1", "5", "--primary-k", "5", "--out", str(out)])

    res = json.loads(out.read_text())
    assert set(res["points"]) == {"drop_k1", "drop_k5", "onehot_k1", "onehot_k5"}
    assert res["points"]["drop_k5"]["apache2"]["group"] == "unseen_test"
    assert out.with_suffix(".png").exists()
    assert set(res["robustness"]) == {"drop_k1", "onehot_k1", "onehot_k5"}
