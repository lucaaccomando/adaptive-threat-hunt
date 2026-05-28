#!/usr/bin/env python3
from flask import Flask, render_template, redirect, url_for, request, send_file
from pathlib import Path
import os
import pandas as pd
import io
import subprocess
import signal
import time
import base64

import matplotlib
matplotlib.use("Agg")  # non-GUI backend for server
import matplotlib.pyplot as plt

app = Flask(__name__)

# directories

DATA_DIR = Path("data")
MODELS_DIR = Path("models")

for p in (DATA_DIR, MODELS_DIR):
    p.mkdir(parents=True, exist_ok=True)

CAPTURE_PID_FILE = DATA_DIR / "tcpdump.pid"

# helpers

def capture_running() -> bool:
    if not CAPTURE_PID_FILE.exists():
        return False
    try:
        pid = int(CAPTURE_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # test signal
        return True
    except Exception:
        try:
            CAPTURE_PID_FILE.unlink()
        except FileNotFoundError:
            pass
        return False

# routes

@app.route("/")
def index():
    data_dir = str(DATA_DIR.resolve())
    have_features = (DATA_DIR / "features.csv").exists()
    have_model = (MODELS_DIR / "model.pkl").exists()
    have_scored = (DATA_DIR / "scored.csv").exists()
    have_capture_running = capture_running()

    return render_template(
        "index.html",
        data_dir=data_dir,
        have_features=have_features,
        have_model=have_model,
        have_scored=have_scored,
        have_capture_running=have_capture_running,
    )


@app.route("/generate")
def generate():
    try:
        subprocess.run(
            ["python", "feature_extractor/extract.py"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Feature generation failed (exit {e.returncode})."
            f"<pre>{e.stderr}</pre>",
            500,
        )
    return redirect(url_for("index"))


@app.route("/train")
def train():
    csv_path = DATA_DIR / "features.csv"
    if not csv_path.exists():
        return "data/features.csv not found. Generate features first.", 404

    try:
        subprocess.run(
            ["python", "models/train.py", "--csv", str(csv_path), "--model", str(MODELS_DIR / "model.pkl")],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Model training failed (exit {e.returncode})."
            f"<pre>{e.stderr}</pre>",
            500,
        )
    return redirect(url_for("index"))


@app.route("/score")
def score():
    csv_path = DATA_DIR / "features.csv"
    model_path = MODELS_DIR / "model.pkl"
    if not csv_path.exists():
        return "data/features.csv not found. Generate features first.", 404
    if not model_path.exists():
        return "models/model.pkl not found. Train the model first.", 404

    try:
        subprocess.run(
            [
                "python",
                "models/score.py",
                "--csv", str(csv_path),
                "--model", str(model_path),
                "--out", str(DATA_DIR / "scored.csv"),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        return (
            f"Scoring failed (exit {e.returncode})."
            f"<pre>{e.stderr}</pre>",
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
        return f"Failed to read data/scored.csv: {e}", 500

    total = len(df)
    num_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0
    percent = (num_anom / total * 100.0) if total else 0.0

    view_mode = request.args.get("view", "anom")
    df_view = df

    if "anomaly_score" in df.columns:
        df_view = df_view.sort_values("anomaly_score", ascending=True)

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
        return f"Failed to read data/scored.csv: {e}", 500

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
        return f"Failed to read data/scored.csv: {e}", 500

    total = len(df)
    num_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0

    if "anomaly_score" in df.columns and total > 0:
        scores = df["anomaly_score"].dropna()
        score_mean = f"{scores.mean():.4f}"
        score_min = f"{scores.min():.4f}"
        score_max = f"{scores.max():.4f}"

        # Histogram
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
    else:
        score_mean = score_min = score_max = "N/A"
        hist_img = None

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


@app.route("/live-capture")
def live_capture():
    iface = "ens33"  # change to your actual interface if needed
    pcap_path = DATA_DIR / "live_capture.pcap"

    if capture_running():
        return "A live capture is already running. <a href='/'>Back to dashboard</a>"

    capture_cmd = [
        "sudo",
        "tcpdump",
        "-i", iface,
        "-w", str(pcap_path),
    ]

    try:
        proc = subprocess.Popen(capture_cmd)
    except OSError as e:
        return f"Failed to start tcpdump: {e}", 500

    CAPTURE_PID_FILE.write_text(str(proc.pid))

    return "Live capture started. Generate some traffic, then click 'Stop live capture' on the dashboard. <a href='/'>Back to dashboard</a>"


@app.route("/stop-capture")
def stop_capture():
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
        "python",
        "feature_extractor/extract.py",
        "--pcap", str(pcap_path),
        "--out", str(csv_path),
    ]
    train_cmd = [
        "python",
        "models/train.py",
        "--csv", str(csv_path),
        "--model", str(model_path),
    ]

    try:
        subprocess.run(extract_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return (
            f"Feature extraction from live_capture.pcap failed (exit {e.returncode})."
            f"<pre>{e.stderr}</pre>",
            500,
        )

    try:
        subprocess.run(train_cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        return (
            f"Model training on live capture features failed (exit {e.returncode})."
            f"<pre>{e.stderr}</pre>",
            500,
        )

    return "Capture stopped, features extracted, and model retrained. <a href='/'>Back to dashboard</a>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
