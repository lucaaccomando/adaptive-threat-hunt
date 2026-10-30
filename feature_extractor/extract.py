#!/usr/bin/env python3
# extracts flow-level features from a pcap file using scapy. a flow is both directions of one
# 5-tuple; it ends after 120 s without packets, so a reused port starts a new flow.
# fails with an error on a missing, unreadable or empty capture; --demo writes two fake rows.
#
# usage:
#   python feature_extractor/extract.py --pcap data/capture.pcap --out data/features.csv
#   python feature_extractor/extract.py --demo --out data/features.csv

import argparse
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, PcapReader
from scapy.utils import PcapNgReader

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
IDLE_TIMEOUT_S = 120.0


def entropy_bytes(b: bytes) -> float:
    # Shannon entropy of a byte string - higher means more random payload
    if not b:
        return 0.0
    counts = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    probs = [c / len(b) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def demo_features():
    return pd.DataFrame([
        {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 1234, "dport": 80,
         "proto_tcp": 1, "proto_udp": 0, "pkt_count": 10, "bytes": 1500, "duration_ms": 120, "avg_pkt_size": 150,
         "iat_mean_ms": 13, "iat_std_ms": 3, "payload_entropy": 3.2},
        {"src": "10.0.0.2", "dst": "10.0.0.1", "sport": 80, "dport": 1234,
         "proto_tcp": 1, "proto_udp": 0, "pkt_count": 8, "bytes": 900, "duration_ms": 95, "avg_pkt_size": 112.5,
         "iat_mean_ms": 12, "iat_std_ms": 2.5, "payload_entropy": 2.8},
    ])


def read_packets(pcap_path: Path):
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
    reader_cls = PcapNgReader if magic == _PCAPNG_MAGIC else PcapReader
    with reader_cls(str(pcap_path)) as reader:
        yield from reader


def _flow_row(f: dict) -> dict:
    times = sorted(f["times"])
    n = len(times)
    duration_ms = (times[-1] - times[0]) * 1000 if n > 1 else 0.0
    iats = np.diff(times) * 1000 if n > 1 else np.array([0.0])
    return {
        "src": f["src"], "dst": f["dst"], "sport": f["sport"], "dport": f["dport"],
        "proto_tcp": int(f["proto"] == 6), "proto_udp": int(f["proto"] == 17), "pkt_count": n, "bytes": f["bytes"], "duration_ms": duration_ms,
        "avg_pkt_size": f["bytes"] / n, "iat_mean_ms": float(iats.mean()),
        "iat_std_ms": float(iats.std()), "payload_entropy": entropy_bytes(b"".join(f["payloads"])),
    }


def stream_flows(packets):
    # yields a flow when it goes idle or when the capture ends
    active = {}
    for p in packets:
        if IP not in p:
            continue
        ts = float(p.time)
        ip = p[IP]
        proto = 6 if TCP in p else (17 if UDP in p else 0)
        sport = p.sport if hasattr(p, "sport") else 0
        dport = p.dport if hasattr(p, "dport") else 0
        key = (min((ip.src, sport), (ip.dst, dport)), max((ip.src, sport), (ip.dst, dport)), proto)
        flow = active.get(key)
        if flow is not None and ts - flow["last"] > IDLE_TIMEOUT_S:
            yield _flow_row(flow)
            flow = None
        if flow is None:
            flow = active[key] = {"src": ip.src, "dst": ip.dst, "sport": sport, "dport": dport,
                                  "proto": proto, "times": [], "bytes": 0, "payloads": [], "last": ts}
        flow["times"].append(ts)
        flow["last"] = ts
        flow["bytes"] += len(p)
        if Raw in p:
            flow["payloads"].append(bytes(p[Raw].load))
    for flow in active.values():
        yield _flow_row(flow)


def extract_from_pcap(pcap_path: Path) -> pd.DataFrame:
    if not pcap_path.is_file():
        raise FileNotFoundError(f"no capture at {pcap_path}")
    rows = list(stream_flows(read_packets(pcap_path)))
    if not rows:
        raise ValueError(f"no IPv4 flows found in {pcap_path}")
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser(description="extract flow features from a pcap file")
    ap.add_argument("--pcap", type=str, default="", help="path to pcap/pcapng file")
    ap.add_argument("--out", type=str, default="data/features.csv", help="output CSV path")
    ap.add_argument("--demo", action="store_true", help="write two fake flows (pipeline test only)")
    args = ap.parse_args()
    if not args.pcap and not args.demo:
        ap.error("give --pcap FILE, or --demo for two fake flows")

    try:
        df = demo_features() if args.demo else extract_from_pcap(Path(args.pcap))
    except (OSError, ValueError) as e:
        sys.exit(f"error: {e}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"wrote {len(df)} rows to {out}")


if __name__ == "__main__":
    main()
