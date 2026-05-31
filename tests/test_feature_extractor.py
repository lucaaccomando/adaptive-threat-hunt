import math
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from feature_extractor.extract import (
    _PCAPNG_MAGIC,
    demo_features,
    entropy_bytes,
)


def test_entropy_empty():
    assert entropy_bytes(b"") == 0.0


def test_entropy_single_symbol():
    # all same bytes — no randomness, entropy = 0
    assert entropy_bytes(b"\xff\xff\xff\xff") == 0.0


def test_entropy_uniform():
    # 4 equally likely symbols → entropy = log2(4) = 2.0
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
    expected = {"src", "dst", "sport", "dport", "proto",
                "pkt_count", "bytes", "duration_ms",
                "avg_pkt_size", "iat_mean_ms", "iat_std_ms", "payload_entropy"}
    assert expected.issubset(set(demo_features().columns))


def test_demo_features_numeric_values():
    df = demo_features()
    for col in ["pkt_count", "bytes", "duration_ms", "payload_entropy"]:
        assert (df[col] > 0).all()


def test_pcapng_magic_constant():
    assert _PCAPNG_MAGIC == b"\x0a\x0d\x0d\x0a"


def test_extract_falls_back_on_missing_file(tmp_path):
    from feature_extractor.extract import extract_from_pcap
    missing = tmp_path / "nonexistent.pcap"
    df = extract_from_pcap(missing)
    # should fall back to demo data rather than crash
    assert isinstance(df, pd.DataFrame)
    assert len(df) >= 2
