#!/usr/bin/env python3
import base64
import io
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-GUI backend, must be set before pyplot
import matplotlib.pyplot as plt

import pandas as pd
from flask import Flask, render_template, redirect, url_for, request, send_file, session
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
MODELS_DIR = ROOT / "models"

for p in (DATA_DIR, MODELS_DIR):
    p.mkdir(parents=True, exist_ok=True)

CAPTURE_PID_FILE = DATA_DIR / "tcpdump.pid"


def _csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

app.jinja_env.globals["csrf_token"] = _csrf_token


def _check_csrf():
    token = request.form.get("_csrf", "")
    if not token or token != session.get("_csrf"):
        return "invalid or missing csrf token", 403
    return None


def capture_running() -> bool:
    if not CAPTURE_PID_FILE.exists():
        return False
    try:
        pid = int(CAPTURE_PID_FILE.read_text().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        try:
            CAPTURE_PID_FILE.unlink()
        except FileNotFoundError:
            pass
        return False


@app.route("/")
def index():
    return render_template(
        "index.html",
        data_dir=str(DATA_DIR),
        have_features=(DATA_DIR / "features.csv").exists(),
        have_model=(MODELS_DIR / "model.pkl").exists(),
        have_scored=(DATA_DIR / "scored.csv").exists(),
        have_capture_running=capture_running(),
    )


@app.route("/generate", methods=["POST"])
def generate():
    err = _check_csrf()
    if err:
        return err
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "feature_extractor" / "extract.py")],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Feature generation failed (exit {e.returncode})."
            f"<pre>{escape(e.stderr)}</pre>",
            500,
        )
    return redirect(url_for("index"))


@app.route("/train", methods=["POST"])
def train():
    err = _check_csrf()
    if err:
        return err
    csv_path = DATA_DIR / "features.csv"
    if not csv_path.exists():
        return "data/features.csv not found. Generate features first.", 404
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "models" / "train.py"),
             "--csv", str(csv_path), "--model", str(MODELS_DIR / "model.pkl")],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Model training failed (exit {e.returncode})."
            f"<pre>{escape(e.stderr)}</pre>",
            500,
        )
    return redirect(url_for("index"))


@app.route("/score", methods=["POST"])
def score():
    err = _check_csrf()
    if err:
        return err
    csv_path = DATA_DIR / "features.csv"
    model_path = MODELS_DIR / "model.pkl"
    if not csv_path.exists():
        return "data/features.csv not found. Generate features first.", 404
    if not model_path.exists():
        return "models/model.pkl not found. Train the model first.", 404
    try:
        subprocess.run(
            [sys.executable, str(ROOT / "models" / "score.py"),
             "--csv", str(csv_path), "--model", str(model_path),
             "--out", str(DATA_DIR / "scored.csv")],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Scoring failed (exit {e.returncode})."
            f"<pre>{escape(e.stderr)}</pre>",
            500,
        )
    return redirect(url_for("anomalies"))


@app.route("/anomalies")
def anomalies():
    scored_path = DATA_DIR / "scored.csv"
    if not scored_path.exists():
        return "No data/scored.csv found. Click 'Score flows' on the home page first.", 404
    try:
        df = pd.read_csv(scored_path)
    except Exception as e:
        return f"Failed to read data/scored.csv: {escape(str(e))}", 500

    total = len(df)
    num_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0
    percent = (num_anom / total * 100.0) if total else 0.0

    view_mode = request.args.get("view", "anom")
    df_view = df

    if "anomaly_score" in df.columns:
        df_view = df_view.sort_values("anomaly_score", ascending=False)

    if view_mode == "anom" and "is_anomaly" in df_view.columns:
        df_view = df_view[df_view["is_anomaly"] == 1]

    df_view = df_view.head(100)
    rows_shown = len(df_view)

    if "is_anomaly" in df_view.columns:
        df_view = df_view.copy()
        df_view["is_anomaly"] = df_view["is_anomaly"].map(
            lambda v: "ANOMALY" if v == 1 else "normal"
        )

    table_html = df_view.to_html(classes="table", index=False)

    return render_template(
        "anomalies.html",
        total_flows=total,
        num_anomalies=num_anom,
        percent_anomalies=f"{percent:.2f}",
        rows_shown=rows_shown,
        table_html=table_html,
        view_mode=view_mode,
    )


@app.route("/download_anomalies")
def download_anomalies():
    scored_path = DATA_DIR / "scored.csv"
    if not scored_path.exists():
        return "No data/scored.csv found. Click 'Score flows' on the home page first.", 404
    try:
        df = pd.read_csv(scored_path)
    except Exception as e:
        return f"Failed to read data/scored.csv: {escape(str(e))}", 500

    if "is_anomaly" in df.columns:
        df = df[df["is_anomaly"] == 1]

    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)

    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="anomalies.csv",
    )


@app.route("/stats")
def stats():
    scored_path = DATA_DIR / "scored.csv"
    if not scored_path.exists():
        return "No data/scored.csv found. Click 'Score flows' on the home page first.", 404
    try:
        df = pd.read_csv(scored_path)
    except Exception as e:
        return f"Failed to read data/scored.csv: {escape(str(e))}", 500

    total = len(df)
    num_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0

    hist_img = None
    score_mean = score_min = score_max = "N/A"
    if "anomaly_score" in df.columns and total > 0:
        scores = df["anomaly_score"].dropna()
        score_mean = f"{scores.mean():.4f}"
        score_min = f"{scores.min():.4f}"
        score_max = f"{scores.max():.4f}"

        fig1 = plt.figure(figsize=(6, 3))
        plt.hist(scores, bins=30)
        plt.xlabel("anomaly_score")
        plt.ylabel("Count")
        plt.title("Anomaly score distribution")
        buf1 = io.BytesIO()
        fig1.savefig(buf1, format="png", bbox_inches="tight")
        plt.close(fig1)
        buf1.seek(0)
        hist_img = base64.b64encode(buf1.getvalue()).decode("ascii")

    bar_img = None
    if "src" in df.columns and total > 0:
        counts = df["src"].value_counts().head(10)
        fig2 = plt.figure(figsize=(6, 3))
        plt.bar(counts.index.astype(str), counts.values)
        plt.xticks(rotation=45, ha="right")
        plt.xlabel("src")
        plt.ylabel("Flow count")
        plt.title("Top 10 source IPs")
        fig2.tight_layout()
        buf2 = io.BytesIO()
        fig2.savefig(buf2, format="png", bbox_inches="tight")
        plt.close(fig2)
        buf2.seek(0)
        bar_img = base64.b64encode(buf2.getvalue()).decode("ascii")

    return render_template(
        "stats.html",
        total_flows=total,
        num_anomalies=num_anom,
        score_mean=score_mean,
        score_min=score_min,
        score_max=score_max,
        hist_img=hist_img,
        bar_img=bar_img,
    )


@app.route("/live-capture", methods=["POST"])
def live_capture():
    err = _check_csrf()
    if err:
        return err
    iface = os.environ.get("CAPTURE_IFACE", "ens33")
    pcap_path = DATA_DIR / "live_capture.pcap"

    if capture_running():
        return "A live capture is already running. <a href='/'>Back to dashboard</a>"

    capture_cmd = ["sudo", "tcpdump", "-i", iface, "-w", str(pcap_path)]
    try:
        proc = subprocess.Popen(capture_cmd)
    except OSError as e:
        return f"Failed to start tcpdump: {escape(str(e))}", 500

    CAPTURE_PID_FILE.write_text(str(proc.pid))
    return "Live capture started. Generate some traffic, then click 'Stop live capture'. <a href='/'>Back to dashboard</a>"


@app.route("/stop-capture", methods=["POST"])
def stop_capture():
    err = _check_csrf()
    if err:
        return err
    if not CAPTURE_PID_FILE.exists():
        return "No live capture in progress. <a href='/'>Back to dashboard</a>"

    try:
        pid = int(CAPTURE_PID_FILE.read_text().strip())
    except ValueError:
        pid = None

    if pid is not None:
        try:
            os.kill(pid, signal.SIGINT)
        except ProcessLookupError:
            pass

    time.sleep(1)

    try:
        CAPTURE_PID_FILE.unlink()
    except FileNotFoundError:
        pass

    pcap_path = DATA_DIR / "live_capture.pcap"
    csv_path = DATA_DIR / "features.csv"
    model_path = MODELS_DIR / "model.pkl"

    if not pcap_path.exists():
        return "No live_capture.pcap found after stopping capture.", 404

    extract_cmd = [
        sys.executable, str(ROOT / "feature_extractor" / "extract.py"),
        "--pcap", str(pcap_path), "--out", str(csv_path),
    ]
    train_cmd = [
        sys.executable, str(ROOT / "models" / "train.py"),
        "--csv", str(csv_path), "--model", str(model_path),
    ]

    try:
        subprocess.run(extract_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return (
            f"Feature extraction failed (exit {e.returncode})."
            f"<pre>{escape(e.stderr)}</pre>",
            500,
        )

    try:
        subprocess.run(train_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return (
            f"Model training on live capture features failed (exit {e.returncode})."
            f"<pre>{escape(e.stderr)}</pre>",
            500,
        )

    return "Capture stopped, features extracted, and model retrained. <a href='/'>Back to dashboard</a>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
