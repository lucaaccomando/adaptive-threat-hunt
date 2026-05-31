#!/usr/bin/env bash
# Port scan simulation — run against a lab VM or localhost only, not public hosts
TARGET="${1:-127.0.0.1}"
echo "[attack1] scanning $TARGET"
if command -v nmap &>/dev/null; then
    nmap -sS -T4 -p 1-1024 "$TARGET"
else
    for port in 22 23 25 80 443 3389 8080; do
        (echo >/dev/tcp/"$TARGET"/$port) 2>/dev/null && echo "open: $port" || echo "closed: $port"
    done
fi
echo "[attack1] done"
