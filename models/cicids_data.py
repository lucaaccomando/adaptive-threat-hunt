#!/usr/bin/env python3
# downloads, verifies and prepares the improved CIC-IDS2017 flows (Engelen, Rimmer, Joosen; labels corrected, flows
# regenerated with a fixed CICFlowMeter). writes data/cicids2017/prepared.npz: float32 features, labels, day, 10-minute block
#
# usage:
#   python models/cicids_data.py

import argparse
import hashlib
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

URL = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
SHA256 = "97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883"
SIZE_BYTES = 343_549_013
DATA_DIR = Path("data") / "cicids2017"
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
TRAIN_DAYS = 3
BLOCK_SECONDS = 600
# identifiers, ports, the time stamp and the label columns are not features; the ports are dropped for the same
# reason NSL-KDD's service column is (a service name is not a number)
EXCLUDE = {"id", "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp", "Label",
           "Attempted Category"}

CATEGORIES = {
    "Brute force": {"FTP-Patator", "SSH-Patator"},
    "DoS": {"DoS Hulk", "DoS GoldenEye", "DoS Slowloris", "DoS Slowhttptest", "Heartbleed"},
    "Web attack": {"Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL Injection"},
    "Probe": {"Portscan", "Infiltration - Portscan"},
    "Infiltration": {"Infiltration"},
    "DDoS": {"DDoS"},
    "Botnet": {"Botnet"},
}
CATEGORY_OF = {t: c for c, names in CATEGORIES.items() for t in names}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(dest: Path, url: str = URL, sha256: str = SHA256) -> Path:
    if dest.exists():
        if sha256_of(dest) != sha256:
            raise SystemExit(f"{dest} does not match the pinned sha256, delete it and run again")
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    print(f"  downloading {url}")
    h = hashlib.sha256()
    with urllib.request.urlopen(url) as r, open(part, "wb") as f:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk)
            f.write(chunk)
    if h.hexdigest() != sha256:
        part.unlink()
        raise SystemExit("download does not match the pinned sha256, not saved")
    part.rename(dest)
    print(f"  saved to {dest} ({dest.stat().st_size / 1e6:.1f} MB)")
    return dest


def clean_labels(labels: pd.Series) -> pd.Series:
    # the authors say flows of an attack that did nothing ("... - Attempted") are benign, not a class
    out = labels.str.strip()
    out = out.mask(out.str.endswith(" - Attempted"), "normal")
    return out.mask(out == "BENIGN", "normal")


def read_day(zf: zipfile.ZipFile, day: str) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    with zf.open(f"{day}.csv") as f:
        df = pd.read_csv(f, low_memory=False)
    features = df.drop(columns=[c for c in EXCLUDE if c in df.columns])
    X = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    seconds = pd.to_datetime(df["Timestamp"]).astype("int64") // 10**9
    return X, clean_labels(df["Label"]).to_numpy(str), (seconds // BLOCK_SECONDS).to_numpy()


def prepare(zip_path: Path, out_path: Path) -> None:
    parts, names = [], None
    with zipfile.ZipFile(zip_path) as zf:
        for i, day in enumerate(DAYS):
            print(f"  reading {day}")
            X, labels, blocks = read_day(zf, day)
            if names is None:
                names = list(X.columns)
            elif list(X.columns) != names:
                raise SystemExit(f"{day}.csv has different feature columns than monday.csv")
            parts.append((X.to_numpy(np.float32), labels, np.full(len(labels), i, np.int8), blocks))
    X, labels, day, block = (np.concatenate(c) for c in zip(*parts))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(out_path, X=X, label=labels, day=day, block=block, features=np.array(names))
    print(f"  saved {len(labels):,} flows x {len(names)} features to {out_path}")


def load(data_dir: Path = DATA_DIR) -> dict:
    prepared = data_dir / "prepared.npz"
    if not prepared.exists():
        prepare(fetch(data_dir / "CICIDS2017_improved.zip"), prepared)
    with np.load(prepared, allow_pickle=False) as z:
        return {k: z[k] for k in z.files}


def main() -> None:
    argparse.ArgumentParser(description="download, verify and prepare the improved CIC-IDS2017 flows").parse_args()
    data = load()
    labels = pd.Series(data["label"])
    print(f"{len(labels):,} flows, {data['X'].shape[1]} features")
    print(labels.groupby(data["day"]).value_counts().to_string())


if __name__ == "__main__":
    main()
