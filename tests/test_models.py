import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

sys.path.insert(0, str(Path(__file__).parent.parent))
from models import score, train
from models.train import MODEL_BUILDERS, NUMERIC, build_isolation_forest, build_lof, build_ocsvm
from models.score import FEATURE_COLS


def _make_df(n=200):
    rng = np.random.default_rng(0)
    return pd.DataFrame({
        "src": ["10.0.0.1"] * n,
        "dst": ["10.0.0.2"] * n,
        "sport": rng.integers(1024, 65535, n),
        "dport": rng.integers(1, 1024, n),
        "proto_tcp": rng.integers(0, 2, n),
        "proto_udp": rng.integers(0, 2, n),
        "pkt_count": rng.integers(1, 50, n).astype(float),
        "bytes": rng.integers(64, 9000, n).astype(float),
        "duration_ms": rng.uniform(0, 500, n),
        "avg_pkt_size": rng.uniform(64, 1500, n),
        "iat_mean_ms": rng.uniform(0, 100, n),
        "iat_std_ms": rng.uniform(0, 50, n),
        "payload_entropy": rng.uniform(0, 8, n),
    })


def _train_cli(tmp_path, monkeypatch, model_type="isolation_forest", extra=()):
    csv = tmp_path / "features.csv"
    _make_df().to_csv(csv, index=False)
    model = tmp_path / "model.pkl"
    argv = ["train.py", "--csv", str(csv), "--model", str(model),
            "--model-type", model_type, *extra]
    monkeypatch.setattr(sys, "argv", argv)
    train.main()
    return model


def _score_cli(tmp_path, monkeypatch, model, extra=()):
    csv = tmp_path / "features.csv"
    if not csv.exists():
        _make_df().to_csv(csv, index=False)
    out = tmp_path / "scored.csv"
    argv = ["score.py", "--csv", str(csv), "--model", str(model), "--out", str(out), *extra]
    monkeypatch.setattr(sys, "argv", argv)
    score.main()
    return pd.read_csv(out)


def _sorted_frame(scores, flags):
    # score.py writes rows sorted by anomaly_score, highest first
    return (pd.DataFrame({"anomaly_score": scores, "is_anomaly": flags})
            .sort_values("anomaly_score", ascending=False)
            .reset_index(drop=True))


def test_feature_columns_in_sync():
    assert NUMERIC == FEATURE_COLS, (
        "NUMERIC in train.py and FEATURE_COLS in score.py are out of sync"
    )


def test_builders_set_contamination():
    assert isinstance(build_isolation_forest(0.05), IsolationForest)
    assert build_isolation_forest(0.05).contamination == 0.05
    assert build_lof(0.05).contamination == 0.05
    assert build_ocsvm(0.05).nu == 0.05


def test_lof_is_novelty_detector():
    # predict() on unseen rows needs novelty=True
    assert isinstance(build_lof(0.1), LocalOutlierFactor)
    assert build_lof(0.1).novelty is True


def test_model_builders_cover_cli_choices():
    assert set(MODEL_BUILDERS) == {"isolation_forest", "lof", "ocsvm"}


def test_train_writes_bundle_and_meta(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch)
    bundle = joblib.load(model)
    assert set(bundle) == {"model", "scaler", "features"}
    assert bundle["scaler"] is None
    assert bundle["features"] == NUMERIC
    assert isinstance(bundle["model"], IsolationForest)

    meta = pd.read_json(model.with_suffix(".meta.json"), typ="series")
    assert meta["model_type"] == "isolation_forest"
    assert meta["train_rows"] == 200
    assert meta["scaled"] is False


def test_train_ocsvm_is_scaled(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch, model_type="ocsvm")
    bundle = joblib.load(model)
    assert bundle["scaler"] is not None
    assert isinstance(bundle["model"], OneClassSVM)


def test_train_missing_column_exits(tmp_path, monkeypatch):
    csv = tmp_path / "features.csv"
    _make_df().drop(columns=["proto_tcp"]).to_csv(csv, index=False)
    monkeypatch.setattr(sys, "argv", ["train.py", "--csv", str(csv),
                                      "--model", str(tmp_path / "m.pkl")])
    with pytest.raises(SystemExit, match="proto_tcp"):
        train.main()


def test_train_missing_csv_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["train.py", "--csv", str(tmp_path / "nope.csv"),
                                      "--model", str(tmp_path / "m.pkl")])
    with pytest.raises(SystemExit):
        train.main()


def test_score_matches_model_predictions(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch)
    out = _score_cli(tmp_path, monkeypatch, model)
    X = _make_df()[NUMERIC].fillna(0.0).values.astype(float)
    clf = joblib.load(model)["model"]

    X = _make_df()[NUMERIC].fillna(0.0).values.astype(float)
    expected = _sorted_frame(-clf.decision_function(X), (clf.predict(X) == -1).astype(int))
    pd.testing.assert_frame_equal(out[["anomaly_score", "is_anomaly"]], expected, check_dtype=False)


def test_score_scaled_bundle_applies_scaler(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch, model_type="ocsvm")
    bundle = joblib.load(model)
    out = _score_cli(tmp_path, monkeypatch, model)
    X = bundle["scaler"].transform(_make_df()[NUMERIC].values.astype(float))
    expected = _sorted_frame(-bundle["model"].decision_function(X), (bundle["model"].predict(X) == -1).astype(int))
    pd.testing.assert_frame_equal(out[["anomaly_score", "is_anomaly"]], expected, check_dtype=False)


def test_score_threshold_override(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch)
    everything = _score_cli(tmp_path, monkeypatch, model, extra=["--threshold", "-1000000000"])
    nothing = _score_cli(tmp_path, monkeypatch, model, extra=["--threshold", "1000000000"])
    assert everything["is_anomaly"].sum() == 200
    assert nothing["is_anomaly"].sum() == 0


def test_score_bare_model_pickle(tmp_path, monkeypatch):
    # old-format pickles hold the model alone, with no scaler and no threshold
    csv = tmp_path / "features.csv"
    df = _make_df()
    df.to_csv(csv, index=False)
    clf = build_isolation_forest(0.1)
    clf.fit(df[NUMERIC].values.astype(float))
    bare = tmp_path / "bare.pkl"
    joblib.dump(clf, bare)

    out = _score_cli(tmp_path, monkeypatch, bare)
    X = df[NUMERIC].values.astype(float)
    expected = _sorted_frame(-clf.decision_function(X), (clf.predict(X) == -1).astype(int))
    pd.testing.assert_frame_equal(out[["anomaly_score", "is_anomaly"]], expected, check_dtype=False)


def test_score_missing_column_exits(tmp_path, monkeypatch):
    model = _train_cli(tmp_path, monkeypatch)
    csv = tmp_path / "short.csv"
    _make_df().drop(columns=["bytes"]).to_csv(csv, index=False)
    monkeypatch.setattr(sys, "argv", ["score.py", "--csv", str(csv), "--model", str(model),
                                      "--out", str(tmp_path / "o.csv")])
    with pytest.raises(SystemExit, match="bytes"):
        score.main()


def test_score_missing_model_exits(tmp_path, monkeypatch):
    csv = tmp_path / "features.csv"
    _make_df().to_csv(csv, index=False)
    monkeypatch.setattr(sys, "argv", ["score.py", "--csv", str(csv),
                                      "--model", str(tmp_path / "nope.pkl"),
                                      "--out", str(tmp_path / "o.csv")])
    with pytest.raises(SystemExit):
        score.main()
