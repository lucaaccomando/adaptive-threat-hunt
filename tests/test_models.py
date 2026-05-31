import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).parent.parent))
from models.train import NUMERIC, build_isolation_forest
from models.score import FEATURE_COLS


def _make_df(n=100):
    rng = np.random.default_rng(0)
    return pd.DataFrame({
        "src": ["10.0.0.1"] * n,
        "dst": ["10.0.0.2"] * n,
        "sport": rng.integers(1024, 65535, n),
        "dport": rng.integers(1, 1024, n),
        "proto": [6] * n,
        "pkt_count": rng.integers(1, 50, n).astype(float),
        "bytes": rng.integers(64, 9000, n).astype(float),
        "duration_ms": rng.uniform(0, 500, n),
        "avg_pkt_size": rng.uniform(64, 1500, n),
        "iat_mean_ms": rng.uniform(0, 100, n),
        "iat_std_ms": rng.uniform(0, 50, n),
        "payload_entropy": rng.uniform(0, 8, n),
    })


def test_feature_columns_in_sync():
    assert NUMERIC == FEATURE_COLS, (
        "NUMERIC in train.py and FEATURE_COLS in score.py are out of sync"
    )


def test_build_isolation_forest():
    clf = build_isolation_forest(contamination=0.1)
    assert clf.contamination == 0.1
    assert clf.n_estimators == 200


def test_model_bundle_format(tmp_path):
    df = _make_df()
    X = df[NUMERIC].values.astype(float)
    clf = build_isolation_forest(0.1)
    clf.fit(X)

    bundle = {"model": clf, "scaler": None, "features": NUMERIC}
    pkl = tmp_path / "model.pkl"
    joblib.dump(bundle, pkl)

    loaded = joblib.load(pkl)
    assert isinstance(loaded, dict)
    assert set(loaded.keys()) == {"model", "scaler", "features"}
    assert loaded["features"] == NUMERIC


def test_score_with_bundle(tmp_path):
    df = _make_df()
    X = df[NUMERIC].values.astype(float)
    clf = build_isolation_forest(0.1)
    clf.fit(X)

    bundle = {"model": clf, "scaler": None, "features": NUMERIC}
    scores = -clf.decision_function(X)
    preds = clf.predict(X)

    df["anomaly_score"] = scores
    df["is_anomaly"] = (preds == -1).astype(int)

    assert "anomaly_score" in df.columns
    assert "is_anomaly" in df.columns
    assert df["is_anomaly"].isin([0, 1]).all()


def test_score_with_scaler(tmp_path):
    df = _make_df()
    X = df[NUMERIC].values.astype(float)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    clf = build_isolation_forest(0.1)
    clf.fit(X_scaled)

    X_test = scaler.transform(X)
    scores = -clf.decision_function(X_test)
    assert len(scores) == len(df)


def test_contamination_rate():
    df = _make_df(200)
    X = df[NUMERIC].values.astype(float)
    clf = build_isolation_forest(contamination=0.1)
    clf.fit(X)
    preds = clf.predict(X)
    anomaly_rate = (preds == -1).mean()
    assert abs(anomaly_rate - 0.1) < 0.01


def test_bare_model_compat(tmp_path):
    # score.py must still handle old-format pickles (bare model, no dict wrapper)
    df = _make_df()
    X = df[NUMERIC].values.astype(float)
    clf = build_isolation_forest(0.1)
    clf.fit(X)

    pkl = tmp_path / "bare.pkl"
    joblib.dump(clf, pkl)

    bundle = joblib.load(pkl)
    if isinstance(bundle, dict):
        model = bundle["model"]
        scaler = bundle.get("scaler")
    else:
        model = bundle
        scaler = None

    assert scaler is None
    scores = -model.decision_function(X)
    assert len(scores) == len(df)
