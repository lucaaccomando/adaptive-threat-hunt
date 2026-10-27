import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
sys.path.insert(0, str(Path(__file__).parent))
from hybrid import SPLIT_GRID, alerts, main, thresholds
from test_leave_one_out import _write_multi_attack


def _scores(seed, n=2000):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.3).astype(int)
    s_rf = rng.random(n) + 0.5 * y
    s_an = rng.random(n) + 0.3 * y
    return s_rf, s_an, y


def test_union_stays_within_validation_budget():
    budget = 0.05
    s_rf, s_an, y = _scores(0)
    k_total = int(np.floor(budget * (y == 0).sum() + 1e-9))
    for share in SPLIT_GRID:
        tau_rf, tau_an = thresholds(s_rf, s_an, y, budget, share)
        normal_alerts = alerts(s_rf, s_an, tau_rf, tau_an)[y == 0].sum()
        assert normal_alerts <= k_total, share


def test_share_one_is_the_forest_alone():
    budget = 0.05
    s_rf, s_an, y = _scores(1)
    tau_rf, tau_an = thresholds(s_rf, s_an, y, budget, 1.0)
    assert tau_an == np.inf
    assert (alerts(s_rf, s_an, tau_rf, tau_an) == (s_rf >= tau_rf)).all()


def test_main_runs_end_to_end(tmp_path):
    train = tmp_path / "train.txt"
    _write_multi_attack(train, 1200, seed=5)
    test = tmp_path / "test.txt"
    test.write_text(train.read_text())
    out = tmp_path / "hybrid.json"

    main(["--train", str(train), "--test", str(test), "--seeds", "0", "--out", str(out)])

    res = json.loads(out.read_text())
    assert set(res["summary"]) == {"if_normal", "ocsvm_normal", "if_mixed", "forest_alone"}
    assert all(len(v["share_to_forest"]) == 1 for v in res["summary"].values())
