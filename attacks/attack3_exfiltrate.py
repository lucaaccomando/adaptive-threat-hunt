#!/usr/bin/env python3
"""HTTP exfiltration simulation — sends bursts of encoded data to a target URL.

Generates high-bytes, high-entropy outbound traffic detectable by the ML pipeline.
Run against a local listener (e.g. netcat: nc -l -p 8080) or a lab VM only.
"""
import argparse
import base64
import os
import urllib.error
import urllib.request


def main():
    ap = argparse.ArgumentParser(description="simulate HTTP data exfiltration")
    ap.add_argument("--target", default="http://127.0.0.1:8080", help="target URL")
    ap.add_argument("--size", type=int, default=1024, help="payload size in bytes per request")
    ap.add_argument("--count", type=int, default=20, help="number of requests to send")
    args = ap.parse_args()

    print(f"[attack3] exfiltrating {args.count} chunks of {args.size}B to {args.target}")
    success = 0
    for i in range(args.count):
        payload = base64.b64encode(os.urandom(args.size))
        try:
            req = urllib.request.Request(args.target, data=payload, method="POST")
            req.add_header("Content-Type", "application/octet-stream")
            urllib.request.urlopen(req, timeout=2)
            success += 1
        except (urllib.error.URLError, OSError):
            pass  # target may not be listening — traffic is still generated on the wire
    print(f"[attack3] done — {success}/{args.count} requests acknowledged")


if __name__ == "__main__":
    main()
