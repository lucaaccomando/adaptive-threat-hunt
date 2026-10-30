import math
import sys
from pathlib import Path

import pandas as pd
import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

sys.path.insert(0, str(Path(__file__).parent.parent))
from feature_extractor.extract import (
    _PCAPNG_MAGIC,
    demo_features,
    entropy_bytes,
)


def test_entropy_empty():
    assert entropy_bytes(b"") == 0.0


def test_entropy_single_symbol():
    # all same bytes - no randomness, entropy = 0
    assert entropy_bytes(b"\xff\xff\xff\xff") == 0.0


def test_entropy_uniform():
    # 4 equally likely symbols -> entropy = log2(4) = 2.0
    result = entropy_bytes(bytes(range(4)) * 100)
    assert abs(result - 2.0) < 0.01


def test_entropy_high_for_random():
    import os
    result = entropy_bytes(os.urandom(1024))
    assert result > 6.0  # random bytes should be close to 8 bits of entropy


def test_demo_features_shape():
    df = demo_features()
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 2


def test_demo_features_columns():
    expected = {"src", "dst", "sport", "dport", "proto_tcp", "proto_udp",
                "pkt_count", "bytes", "duration_ms",
                "avg_pkt_size", "iat_mean_ms", "iat_std_ms", "payload_entropy"}
    assert expected.issubset(set(demo_features().columns))


def test_demo_features_numeric_values():
    df = demo_features()
    for col in ["pkt_count", "bytes", "duration_ms", "payload_entropy"]:
        assert (df[col] > 0).all()


def test_pcapng_magic_constant():
    assert _PCAPNG_MAGIC == b"\x0a\x0d\x0d\x0a"


def _tcp(src, dst, sport, dport, t, payload=b""):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(payload)
    p.time = t
    return p


def test_extract_raises_on_missing_file(tmp_path):
    from feature_extractor.extract import extract_from_pcap
    with pytest.raises(FileNotFoundError):
        extract_from_pcap(tmp_path / "nonexistent.pcap")


def test_both_directions_form_one_flow(tmp_path):
    from feature_extractor.extract import extract_from_pcap
    path = tmp_path / "two_way.pcap"
    wrpcap(str(path), [
        _tcp("10.0.0.1", "10.0.0.2", 1234, 80, 100.0, b"aaaa"),
        _tcp("10.0.0.2", "10.0.0.1", 80, 1234, 100.5, b"bb"),
        _tcp("10.0.0.1", "10.0.0.2", 1234, 80, 101.0),
    ])
    df = extract_from_pcap(path)
    assert len(df) == 1
    assert df.loc[0, "pkt_count"] == 3
    assert abs(df.loc[0, "duration_ms"] - 1000.0) < 1e-6
    assert df.loc[0, "payload_entropy"] > 0


def test_idle_gap_starts_a_new_flow(tmp_path):
    from feature_extractor.extract import extract_from_pcap, IDLE_TIMEOUT_S
    path = tmp_path / "reused_port.pcap"
    wrpcap(str(path), [
        _tcp("10.0.0.1", "10.0.0.2", 1234, 80, 100.0),
        _tcp("10.0.0.1", "10.0.0.2", 1234, 80, 100.0 + IDLE_TIMEOUT_S + 80.0),
    ])
    df = extract_from_pcap(path)
    assert len(df) == 2
    assert (df["pkt_count"] == 1).all()


def test_capture_without_ip_is_an_error(tmp_path):
    from feature_extractor.extract import extract_from_pcap
    path = tmp_path / "no_ip.pcap"
    pkt = Ether() / Raw(b"not ip")
    pkt.time = 1.0
    wrpcap(str(path), [pkt])
    with pytest.raises(ValueError):
        extract_from_pcap(path)


def test_demo_flag_writes_fake_rows(tmp_path, monkeypatch):
    from feature_extractor.extract import main
    out = tmp_path / "features.csv"
    monkeypatch.setattr(sys, "argv", ["extract.py", "--demo", "--out", str(out)])
    main()
    assert len(pd.read_csv(out)) == 2


def test_no_pcap_and_no_demo_is_a_usage_error(monkeypatch):
    from feature_extractor.extract import main
    monkeypatch.setattr(sys, "argv", ["extract.py"])
    with pytest.raises(SystemExit):
        main()


def test_flow_row_features_by_hand():
    from feature_extractor.extract import _flow_row
    flow = {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 1234, "dport": 80, "proto": 6,
            "times": [0.0, 1.5, 0.5], "bytes": 300, "payloads": [b"ab", b"cd"]}
    row = _flow_row(flow)
    assert row["pkt_count"] == 3
    assert row["duration_ms"] == 1500.0
    assert row["avg_pkt_size"] == 100.0
    assert row["iat_mean_ms"] == pytest.approx(750.0)
    assert row["iat_std_ms"] == pytest.approx(250.0)
    assert row["payload_entropy"] == pytest.approx(2.0)


def test_flow_row_single_packet_has_zero_timing():
    from feature_extractor.extract import _flow_row
    flow = {"src": "a", "dst": "b", "sport": 1, "dport": 2, "proto": 17,
            "times": [3.0], "bytes": 64, "payloads": [b""]}
    row = _flow_row(flow)
    assert row["duration_ms"] == 0.0
    assert row["iat_mean_ms"] == 0.0 and row["iat_std_ms"] == 0.0
    assert row["payload_entropy"] == 0.0
