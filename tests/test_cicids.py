import hashlib
import sys
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
import cicids_data
from cicids2017 import (
    block_roles,
    exact_duplicates,
    run_benchmark,
    run_leave_one_out,
    run_map,
    sample_rows,
    transform,
    type_groups,
)
from cicids_data import DAYS, clean_labels, fetch, load, prepare

DAY_LABELS = {
    "monday": ["BENIGN"],
    "tuesday": ["BENIGN", "FTP-Patator", "FTP-Patator - Attempted"],
    "wednesday": ["BENIGN", "DoS Hulk"],
    "thursday": ["BENIGN", "Web Attack - XSS"],
    "friday": ["BENIGN", "DDoS"],
}


def _write_zip(path, n=30):
    rng = np.random.default_rng(0)
    with zipfile.ZipFile(path, "w") as zf:
        for i, day in enumerate(DAYS):
            labels = [DAY_LABELS[day][j % len(DAY_LABELS[day])] for j in range(n)]
            df = pd.DataFrame({
                "id": range(n), "Flow ID": "a", "Src IP": "1.1.1.1", "Src Port": 5, "Dst IP": "2.2.2.2",
                "Dst Port": 80,
                "Timestamp": pd.date_range(f"2017-07-0{3 + i} 09:00", periods=n, freq="5min").astype(str),
                "f1": rng.normal(size=n), "f2": rng.normal(size=n),
                "Label": labels, "Attempted Category": -1,
            })
            df.loc[0, "f2"] = np.inf
            zf.writestr(f"{day}.csv", df.to_csv(index=False))


def _data(seed=0):
    # three train days with FTP-Patator and DoS Hulk, two test days with new types
    rng = np.random.default_rng(seed)
    parts = [("normal", 0, 600, 0.0), ("FTP-Patator", 1, 100, 4.0), ("DoS Hulk", 2, 100, -4.0),
             ("normal", 3, 300, 0.0), ("Web Attack - XSS", 3, 60, 6.0), ("DDoS", 4, 60, -6.0)]
    X, label, day = [], [], []
    for lab, d, n, shift in parts:
        X.append(rng.normal(size=(n, 5)) + shift * (np.arange(5) == (d % 5)))
        label += [lab] * n
        day += [d] * n
    X = np.vstack(X).astype(np.float32)
    return {"X": X, "label": np.array(label), "day": np.array(day, dtype=np.int8),
            "block": rng.integers(0, 40, len(label))}


def test_clean_labels_maps_benign_and_attempted_to_normal():
    s = pd.Series(["BENIGN", "DoS Hulk", "DoS Hulk - Attempted", " FTP-Patator ", "Infiltration - Portscan"])
    assert clean_labels(s).tolist() == ["normal", "DoS Hulk", "normal", "FTP-Patator", "Infiltration - Portscan"]


def test_prepare_keeps_only_features_and_cleans_values(tmp_path):
    _write_zip(tmp_path / "x.zip")
    prepare(tmp_path / "x.zip", tmp_path / "prepared.npz")
    with np.load(tmp_path / "prepared.npz") as z:
        assert z["features"].tolist() == ["f1", "f2"]
        assert z["X"].shape == (150, 2) and z["X"].dtype == np.float32
        assert np.isfinite(z["X"]).all()
        labels = z["label"]
        assert "BENIGN" not in labels and "FTP-Patator - Attempted" not in labels
        assert (labels == "FTP-Patator").sum() == 10
        assert z["day"].tolist() == [i for i in range(5) for _ in range(30)]
        first = [z["block"][z["day"] == i].min() for i in range(5)]
        assert first == sorted(first)


def test_load_prepares_once_from_the_zip(tmp_path, monkeypatch):
    _write_zip(tmp_path / "CICIDS2017_improved.zip")
    monkeypatch.setattr(cicids_data, "fetch", lambda dest: dest)
    assert load(tmp_path)["X"].shape == (150, 2)
    assert (tmp_path / "prepared.npz").exists()


def test_fetch_accepts_a_matching_download_and_rejects_a_bad_one(tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"flows")
    good = hashlib.sha256(b"flows").hexdigest()
    dest = fetch(tmp_path / "out" / "a.bin", src.as_uri(), good)
    assert dest.read_bytes() == b"flows"
    assert fetch(dest, src.as_uri(), good) == dest

    with pytest.raises(SystemExit, match="sha256"):
        fetch(tmp_path / "out" / "b.bin", src.as_uri(), "0" * 64)
    assert not (tmp_path / "out" / "b.bin").exists()
    assert not (tmp_path / "out" / "b.bin.part").exists()

    dest.write_bytes(b"tampered")
    with pytest.raises(SystemExit, match="sha256"):
        fetch(dest, src.as_uri(), good)


def test_sample_rows_caps_each_label_and_keeps_small_ones():
    labels = np.array(["normal"] * 100 + ["a"] * 50 + ["b"] * 5)
    rows = sample_rows(labels, np.arange(len(labels)), {"normal": 20, "attack": 10}, np.random.default_rng(0))
    counts = pd.Series(labels[rows]).value_counts().to_dict()
    assert counts == {"normal": 20, "a": 10, "b": 5}
    assert (np.diff(rows) > 0).all()


def test_block_roles_give_whole_blocks_one_role():
    blocks = np.repeat(np.arange(20), 5)
    role = block_roles(blocks, np.random.default_rng(0), 0.2)
    for b in range(20):
        assert len(set(role[blocks == b])) == 1
    per_block = [role[blocks == b][0] for b in range(20)]
    assert per_block.count(2) == 4
    assert per_block.count(1) == 3
    assert per_block.count(0) == 13
    assert set(block_roles(blocks, np.random.default_rng(0), 0.0)) == {0, 1}


def test_type_groups_has_types_and_categories():
    labels = np.array(["normal", "FTP-Patator", "SSH-Patator", "DDoS"])
    g = type_groups(labels)
    assert set(g) == {"FTP-Patator", "SSH-Patator", "DDoS", "Brute force"}
    assert g["Brute force"].tolist() == [False, True, True, False]


def test_transform_is_signed_log1p_or_identity():
    X = np.array([[-3.0, 0.0, 7.0]], dtype=np.float32)
    assert transform(X, "none").tolist() == [[-3.0, 0.0, 7.0]]
    np.testing.assert_allclose(transform(X, "slog1p"), [[-np.log(4), 0.0, np.log(8)]])


def test_exact_duplicates_counts_test_attacks_equal_to_a_normal_flow():
    data = _data()
    normal_row = data["X"][np.flatnonzero((data["day"] == 0))[0]]
    victim = np.flatnonzero(data["label"] == "DDoS")[0]
    data["X"][victim] = normal_row
    assert exact_duplicates(data)["by_type"] == {"DDoS": 1}


def test_benchmark_reports_recall_on_every_new_type():
    res, scores, y = run_benchmark(_data(), ["iforest", "rf"], [0], 0.1)
    rg = res["summary"]["Random Forest"]["fpr_5pct"]["recall_by_group"]
    assert {"Web Attack - XSS", "DDoS", "Web attack"} <= set(rg)
    assert set(res["summary"]) == {"Isolation Forest", "Random Forest"}
    assert len(scores["Random Forest"]) == len(y)
    assert res["test_groups"]["flows_per_group_seed0"]["DDoS"] == 60


def test_benchmark_threshold_ignores_test_days():
    a, _, _ = run_benchmark(_data(), ["rf"], [0], 0.1)
    data = _data()
    data["X"][data["day"] >= 3] += 50
    b, _, _ = run_benchmark(data, ["rf"], [0], 0.1)
    thr = lambda r: r["per_seed"]["0"]["Random Forest"]["fpr_5pct"]["threshold"]
    assert thr(a) == thr(b)


def test_leave_one_out_holds_the_type_out(tmp_path):
    out = tmp_path / "loo.json"
    res = run_leave_one_out(_data(), ["iforest", "rf"], [0], 0.1, "none", ["FTP-Patator"], out)
    assert out.exists()
    assert list(res["summary"]) == ["FTP-Patator"]
    assert set(res["summary"]["FTP-Patator"]) == {
        "Isolation Forest (mixed)", "Isolation Forest (normal-only)", "Random Forest"}
    assert res["skipped_types"] == {}


def test_map_places_train_and_new_types(tmp_path):
    res = run_map(_data(), [1, 5], 5, "none", tmp_path, "cicids2017_")
    pts = res["points"]["none_k5"]
    assert {t: p["group"] for t, p in pts.items()} == {
        "FTP-Patator": "held_out", "DoS Hulk": "held_out",
        "Web Attack - XSS": "unseen_test", "DDoS": "unseen_test"}
    assert set(res["points"]) == {"none_k1", "none_k5", "slog1p_k1", "slog1p_k5"}
    assert res["duplicates"]["matching_normal_rows"] == 0
