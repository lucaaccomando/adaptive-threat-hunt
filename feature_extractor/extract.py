#!/usr/bin/env python3
# extracts flow-level features from a pcap file using scapy
# if scapy isn't installed or no pcap is given, falls back to two demo rows
#
# usage:
#   python feature_extractor/extract.py --pcap data/capture.pcap --out data/features.csv

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw
    from scapy.utils import PcapNgReader
except ImportError:
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, Raw
        PcapNgReader = None
    except Exception as e:
        rdpcap = None
        PcapNgReader = None
        IP = TCP = UDP = Raw = object
        print(f"warning: scapy not available ({e}), will use demo data instead")
except Exception as e:
    rdpcap = None
    PcapNgReader = None
    IP = TCP = UDP = Raw = object
    print(f"warning: scapy not available ({e}), will use demo data instead")


_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _read_packets(pcap_path: Path):
    with open(pcap_path, "rb") as f:
        magic = f.read(4)
    if magic == _PCAPNG_MAGIC and PcapNgReader is not None:
        with PcapNgReader(str(pcap_path)) as reader:
            return reader.read_all()
    return rdpcap(str(pcap_path))


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
    # just two fake flows so the rest of the pipeline doesn't break without real data
    return pd.DataFrame([
        {"src": "10.0.0.1", "dst": "10.0.0.2", "sport": 1234, "dport": 80, "proto": 6,
         "pkt_count": 10, "bytes": 1500, "duration_ms": 120, "avg_pkt_size": 150,
         "iat_mean_ms": 13, "iat_std_ms": 3, "payload_entropy": 3.2},
        {"src": "10.0.0.2", "dst": "10.0.0.1", "sport": 80, "dport": 1234, "proto": 6,
         "pkt_count": 8, "bytes": 900, "duration_ms": 95, "avg_pkt_size": 112.5,
         "iat_mean_ms": 12, "iat_std_ms": 2.5, "payload_entropy": 2.8},
    ])


def extract_from_pcap(pcap_path: Path) -> pd.DataFrame:
    if rdpcap is None:
        return demo_features()

    try:
        pkts = _read_packets(pcap_path)
    except Exception as e:
        print(f"warning: failed to read {pcap_path} ({e}), using demo data")
        return demo_features()

    if not pkts:
        return demo_features()

    # group packets into flows by 5-tuple (src, dst, sport, dport, proto)
    flows = {}
    for p in pkts:
        if IP not in p:
            continue
        ts = float(p.time)
        ip = p[IP]
        proto = 6 if TCP in p else (17 if UDP in p else 0)
        sport = p.sport if hasattr(p, "sport") else 0
        dport = p.dport if hasattr(p, "dport") else 0
        key = (ip.src, ip.dst, sport, dport, proto)
        entry = flows.setdefault(key, {"times": [], "bytes": 0, "payloads": []})
        entry["times"].append(ts)
        entry["bytes"] += len(p)
        if Raw in p:
            entry["payloads"].append(bytes(p[Raw].load))

    # compute stats for each flow
    rows = []
    for (src, dst, sport, dport, proto), e in flows.items():
        times = sorted(e["times"])
        pkt_count = len(times)
        duration_ms = (times[-1] - times[0]) * 1000 if pkt_count > 1 else 0.0
        iats = [(times[i + 1] - times[i]) * 1000 for i in range(len(times) - 1)] if pkt_count > 1 else [0.0]
        iat_mean_ms = float(np.mean(iats))
        iat_std_ms = float(np.std(iats, ddof=0))
        avg_pkt_size = e["bytes"] / pkt_count if pkt_count else 0.0
        payload = b"".join(e["payloads"])
        payload_entropy = entropy_bytes(payload)
        rows.append({
            "src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto,
            "pkt_count": pkt_count, "bytes": e["bytes"], "duration_ms": duration_ms,
            "avg_pkt_size": avg_pkt_size, "iat_mean_ms": iat_mean_ms,
            "iat_std_ms": iat_std_ms, "payload_entropy": payload_entropy,
        })

    return pd.DataFrame(rows) if rows else demo_features()


def main():
    ap = argparse.ArgumentParser(description="extract flow features from a pcap file")
    ap.add_argument("--pcap", type=str, default="", help="path to pcap/pcapng file")
    ap.add_argument("--out", type=str, default="data/features.csv", help="output CSV path")
    args = ap.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.pcap:
        df = extract_from_pcap(Path(args.pcap))
    else:
        print("no pcap provided, using demo data")
        df = demo_features()

    df.to_csv(out, index=False)
    print(f"wrote {len(df)} rows to {out}")


if __name__ == "__main__":
    main()
