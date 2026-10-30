import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
sys.path.insert(0, str(Path(__file__).parent))
import evaluate
from evaluate import NSL_KDD_COLUMNS
from feature_analysis import main, permutation_importance, summarize
from test_leave_one_out import _write_multi_attack


def test_permutation_importance_finds_the_informative_column():
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 600)
    X = np.column_stack([y + 0.1 * rng.normal(size=600), rng.normal(size=600)])
    clf = RandomForestClassifier(n_estimators=30, random_state=0).fit(X, y)
    drops = permutation_importance("rf", clf, X, y, np.random.default_rng(1), repeats=3)
    assert drops[0] > 0.3
    assert abs(drops[1]) < 0.05


def test_summarize_averages_over_seeds():
    per_seed = [{"rf": {"seen": np.array([0.2, 0.0]), "unseen": np.array([0.1, 0.1])}},
                {"rf": {"seen": np.array([0.4, 0.0]), "unseen": np.array([0.3, 0.1])}}]
    res = summarize(per_seed, ["a", "b"])
    assert res["rf"]["seen"]["a"]["mean"] == 0.3
    assert res["rf"]["unseen"]["b"]["std"] == 0.0


def test_main_runs_end_to_end_on_small_data(tmp_path, monkeypatch):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 1200, seed=6)
    raw = pd.read_csv(train, header=None, names=NSL_KDD_COLUMNS).iloc[:500]
    raw.loc[raw["label"] == "satan", "label"] = "apache2"
    test = tmp_path / "test.txt"
    raw.to_csv(test, header=False, index=False)
    monkeypatch.setitem(evaluate.SHA256, evaluate.TRAIN_URL, evaluate.sha256_of(train))
    monkeypatch.setitem(evaluate.SHA256, evaluate.TEST_URL, evaluate.sha256_of(test))

    main(["--train", str(train), "--test", str(test), "--seeds", "0", "--out-dir", str(tmp_path)])

    res = json.loads((tmp_path / "feature_importance.json").read_text())
    assert set(res["permutation_importance"]) == {"rf", "iforest_normal_only"}
    kept = set(res["permutation_importance"]["rf"]["seen"])
    assert kept.isdisjoint(res["dropped_constant_columns"])
    assert len(kept) + len(res["dropped_constant_columns"]) == len(evaluate.NUMERIC_COLS)
    assert (tmp_path / "feature_importance.png").exists()
    assert (tmp_path / "correlation_heatmap.png").exists()
