#!/usr/bin/env bash
# captures traffic to a pcap with tcpdump, for the feature extractor. needs root. use it on your own lab network only.
#
# usage:
#   sudo bash sensors/capture.sh -i eth0 -d 60 -o data/capture.pcap
#   sudo bash sensors/capture.sh -i eth0 -d 60 -f "host 10.0.0.5"
set -euo pipefail

iface=""
seconds=60
out="data/capture.pcap"
filter=""
while getopts "i:d:o:f:" opt; do
  case "$opt" in
    i) iface="$OPTARG" ;;
    d) seconds="$OPTARG" ;;
    o) out="$OPTARG" ;;
    f) filter="$OPTARG" ;;
    *) echo "usage: capture.sh -i interface [-d seconds] [-o file.pcap] [-f 'bpf filter']" >&2; exit 2 ;;
  esac
done

if [ -z "$iface" ]; then
  echo "capture.sh: -i interface is required (list them with: tcpdump -D)" >&2
  exit 2
fi
if ! [[ "$seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "capture.sh: -d must be a whole number of seconds" >&2
  exit 2
fi
if ! command -v tcpdump >/dev/null 2>&1; then
  echo "capture.sh: tcpdump is not installed" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
echo "capturing on $iface for ${seconds}s to $out"

# -G with -W 1 stops after one file of that many seconds
# shellcheck disable=SC2086
tcpdump -i "$iface" -n -G "$seconds" -W 1 -w "$out" $filter

echo "saved $out"
echo "next: python feature_extractor/extract.py --pcap $out --out data/features.csv"
