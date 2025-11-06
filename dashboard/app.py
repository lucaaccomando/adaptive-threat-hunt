#!/usr/bin/env python3
from flask import Flask, render_template_string, redirect, url_for, request, send_file
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

# --- Directories & basic setup -------------------------------------------------

DATA_DIR = Path("data")
MODELS_DIR = Path("models")

for p in (DATA_DIR, MODELS_DIR):
    p.mkdir(parents=True, exist_ok=True)

CAPTURE_PID_FILE = DATA_DIR / "tcpdump.pid"

# --- HTML templates ------------------------------------------------------------

INDEX_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Adaptive Threat Hunt — Dashboard</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0b1120;
      color: #e5e7eb;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 960px;
      margin: 2rem auto;
      padding: 1.5rem;
      background: #020617;
      border-radius: 12px;
      border: 1px solid #1f2933;
      box-shadow: 0 20px 30px rgba(0,0,0,0.4);
    }
    h1 {
      margin-top: 0;
      font-size: 1.8rem;
    }
    p {
      color: #9ca3af;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin: 1.5rem 0;
    }
    .btn {
      display: inline-block;
      padding: 0.6rem 1.2rem;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.95rem;
      transition: transform 0.08s ease, box-shadow 0.08s ease, background 0.15s ease;
    }
    .btn-primary {
      background: #2563eb;
      color: white;
      box-shadow: 0 10px 20px rgba(37,99,235,0.4);
    }
    .btn-primary:hover {
      background: #1d4ed8;
      transform: translateY(-1px);
      box-shadow: 0 16px 30px rgba(37,99,235,0.55);
    }
    .btn-secondary {
      background: #111827;
      color: #e5e7eb;
      border: 1px solid #374151;
    }
    .btn-secondary:hover {
      background: #1f2937;
      transform: translateY(-1px);
    }
    .btn-live {
      background: #059669;
      color: white;
      box-shadow: 0 10px 20px rgba(5,150,105,0.4);
    }
    .btn-live:hover {
      background: #047857;
      transform: translateY(-1px);
      box-shadow: 0 16px 30px rgba(5,150,105,0.55);
    }
    .btn-stop {
      background: #b91c1c;
      color: #fee2e2;
      border: 1px solid #ef4444;
    }
    .btn-stop:hover {
      background: #991b1b;
      transform: translateY(-1px);
    }
    .status {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .status-card {
      padding: 0.75rem 1rem;
      border-radius: 10px;
      background: #020617;
      border: 1px solid #1f2937;
      font-size: 0.9rem;
    }
    .status-label {
      color: #9ca3af;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .status-value-ok {
      color: #4ade80;
      font-weight: 600;
    }
    .status-value-missing {
      color: #f97373;
      font-weight: 600;
    }
    .link-muted {
      color: #9ca3af;
      font-size: 0.85rem;
    }
    a.link-muted {
      text-decoration: none;
    }
    a.link-muted:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Adaptive Threat Hunt — Starter Dashboard</h1>
    <p>Use this page to generate demo features, train an Isolation Forest model, score flows, and inspect anomalies.</p>

    <div class="actions">
      <a class="btn btn-primary" href="{{ url_for('generate') }}">Generate demo features</a>
      <a class="btn btn-primary" href="{{ url_for('train') }}">Train model</a>
      <a class="btn btn-primary" href="{{ url_for('score') }}">Score flows</a>
      {% if have_scored %}
        <a class="btn btn-secondary" href="{{ url_for('anomalies') }}">View anomalies</a>
        <a class="btn btn-secondary" href="{{ url_for('stats') }}">View stats</a>
      {% endif %}
      <a class="btn btn-live" href="{{ url_for('live_capture') }}">Live capture + retrain</a>
      {% if have_capture_running %}
        <a class="btn btn-stop" href="{{ url_for('stop_capture') }}">Stop live capture</a>
      {% endif %}
    </div>

    <div class="status">
      <div class="status-card">
        <div class="status-label">Data directory</div>
        <div>{{ data_dir }}</div>
      </div>
      <div class="status-card">
        <div class="status-label">Features CSV</div>
        <div class="{{ 'status-value-ok' if have_features else 'status-value-missing' }}">
          {{ 'present (data/features.csv)' if have_features else 'missing' }}
        </div>
      </div>
      <div class="status-card">
        <div class="status-label">Model</div>
        <div class="{{ 'status-value-ok' if have_model else 'status-value-missing' }}">
          {{ 'present (models/model.pkl)' if have_model else 'missing' }}
        </div>
      </div>
      <div class="status-card">
        <div class="status-label">Scored flows</div>
        <div class="{{ 'status-value-ok' if have_scored else 'status-value-missing' }}">
          {{ 'present (data/scored.csv)' if have_scored else 'missing' }}
        </div>
      </div>
    </div>

    <p style="margin-top:1.5rem;" class="link-muted">
      Tip: run the buttons above in order — Generate → Train → Score → View anomalies.
      <br>
      For real traffic, start a <strong>Live capture</strong>, generate some traffic, then hit <strong>Stop live capture</strong> to extract features and retrain.
    </p>
  </div>
</body>
</html>
"""

ANOMALIES_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Anomaly View — Adaptive Threat Hunt</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #020617;
      color: #e5e7eb;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 1100px;
      margin: 2rem auto;
      padding: 1.5rem;
      background: #020617;
      border-radius: 12px;
      border: 1px solid #1f2937;
      box-shadow: 0 20px 30px rgba(0,0,0,0.5);
    }
    h1 {
      margin-top: 0;
      font-size: 1.7rem;
    }
    .btn {
      display: inline-block;
      padding: 0.5rem 1rem;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.9rem;
      background: #111827;
      color: #e5e7eb;
      border: 1px solid #374151;
      margin-bottom: 0.75rem;
      margin-right: 0.5rem;
    }
    .btn:hover {
      background: #1f2937;
    }
    .btn-active {
      background: #2563eb;
      border-color: #2563eb;
    }
    .summary {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      margin: 1rem 0 1.5rem 0;
    }
    .summary-card {
      min-width: 160px;
      padding: 0.75rem 1rem;
      border-radius: 10px;
      background: #020617;
      border: 1px solid #1f2937;
      font-size: 0.9rem;
    }
    .summary-label {
      color: #9ca3af;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .summary-value {
      font-size: 1.1rem;
      font-weight: 600;
      margin-top: 0.15rem;
    }
    .table-wrapper {
      overflow-x: auto;
      border-radius: 10px;
      border: 1px solid #1f2937;
      background: #020617;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.83rem;
    }
    thead {
      background: #0f172a;
    }
    th, td {
      padding: 0.35rem 0.5rem;
      border-bottom: 1px solid #1f2937;
      text-align: left;
      white-space: nowrap;
    }
    tbody tr:nth-child(even) {
      background: #020617;
    }
    tbody tr:nth-child(odd) {
      background: #030712;
    }
    tbody tr td:last-child {
      font-weight: 600;
    }
    .tag-anom {
      color: #fecaca;
    }
    .tag-normal {
      color: #6ee7b7;
    }
  </style>
</head>
<body>
  <div class="container">
    <a href="{{ url_for('index') }}" class="btn">← Back to dashboard</a>
    <h1>Top Anomalous Flows</h1>

    <div>
      <a href="{{ url_for('anomalies', view='anom') }}"
         class="btn {% if view_mode == 'anom' %}btn-active{% endif %}">
        Only anomalies
      </a>
      <a href="{{ url_for('anomalies', view='all') }}"
         class="btn {% if view_mode == 'all' %}btn-active{% endif %}">
        All flows
      </a>
      <a href="{{ url_for('download_anomalies') }}" class="btn">
        Download anomalies CSV
      </a>
    </div>

    <div class="summary">
      <div class="summary-card">
        <div class="summary-label">Total flows</div>
        <div class="summary-value">{{ total_flows }}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Anomalies</div>
        <div class="summary-value">{{ num_anomalies }}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Anomaly rate</div>
        <div class="summary-value">{{ percent_anomalies }}%</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Rows shown</div>
        <div class="summary-value">{{ rows_shown }}</div>
      </div>
    </div>

    <div class="table-wrapper">
      {{ table_html|safe }}
    </div>
  </div>
</body>
</html>
"""

STATS_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Stats — Adaptive Threat Hunt</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #020617;
      color: #e5e7eb;
      margin: 0;
      padding: 0;
    }
    .container {
      max-width: 1100px;
      margin: 2rem auto;
      padding: 1.5rem;
      background: #020617;
      border-radius: 12px;
      border: 1px solid #1f2937;
      box-shadow: 0 20px 30px rgba(0,0,0,0.5);
    }
    h1 {
      margin-top: 0;
      font-size: 1.7rem;
    }
    .btn {
      display: inline-block;
      padding: 0.5rem 1rem;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.9rem;
      background: #111827;
      color: #e5e7eb;
      border: 1px solid #374151;
      margin-bottom: 0.75rem;
      margin-right: 0.5rem;
    }
    .btn:hover {
      background: #1f2937;
    }
    .summary {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      margin: 1rem 0 1.5rem 0;
    }
    .summary-card {
      min-width: 160px;
      padding: 0.75rem 1rem;
      border-radius: 10px;
      background: #020617;
      border: 1px solid #1f2937;
      font-size: 0.9rem;
    }
    .summary-label {
      color: #9ca3af;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .summary-value {
      font-size: 1.1rem;
      font-weight: 600;
      margin-top: 0.15rem;
    }
    .chart-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1.5rem;
      margin-top: 1rem;
    }
    .chart-card {
      padding: 1rem;
      border-radius: 10px;
      background: #020617;
      border: 1px solid #1f2937;
    }
    .chart-title {
      font-size: 0.95rem;
      margin-bottom: 0.5rem;
      color: #e5e7eb;
    }
    img {
      max-width: 100%;
      height: auto;
      display: block;
      border-radius: 8px;
      background: #0f172a;
    }
  </style>
</head>
<body>
  <div class="container">
    <a href="{{ url_for('index') }}" class="btn">← Back to dashboard</a>
    <h1>Flow & Anomaly Statistics</h1>

    <div class="summary">
      <div class="summary-card">
        <div class="summary-label">Total flows</div>
        <div class="summary-value">{{ total_flows }}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Anomalies</div>
        <div class="summary-value">{{ num_anomalies }}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Anomaly score mean</div>
        <div class="summary-value">{{ score_mean }}</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Anomaly score min / max</div>
        <div class="summary-value">{{ score_min }} / {{ score_max }}</div>
      </div>
    </div>

    <div class="chart-grid">
      <div class="chart-card">
        <div class="chart-title">Anomaly score distribution</div>
        {% if hist_img %}
          <img src="data:image/png;base64,{{ hist_img }}" alt="Histogram of anomaly scores">
        {% else %}
          <p>No anomaly_score column found in scored.csv.</p>
        {% endif %}
      </div>
      <div class="chart-card">
        <div class="chart-title">Top 10 source IPs by flow count</div>
        {% if bar_img %}
          <img src="data:image/png;base64,{{ bar_img }}" alt="Top source IPs bar chart">
        {% else %}
          <p>No src column found in scored.csv.</p>
        {% endif %}
      </div>
    </div>
  </div>
</body>
</html>
"""

# --- Helpers -------------------------------------------------------------------

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

# --- Routes --------------------------------------------------------------------

@app.route("/")
def index():
    data_dir = str(DATA_DIR.resolve())
    have_features = (DATA_DIR / "features.csv").exists()
    have_model = (MODELS_DIR / "model.pkl").exists()
    have_scored = (DATA_DIR / "scored.csv").exists()
    have_capture_running = capture_running()

    return render_template_string(
        INDEX_TEMPLATE,
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

    return render_template_string(
        ANOMALIES_TEMPLATE,
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

    return render_template_string(
        STATS_TEMPLATE,
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
    """
    Start a live tcpdump capture in the background.
    Stop it with /stop-capture, then extract features and retrain.

    NOTE: This uses 'sudo tcpdump'. Make sure your environment
    is configured so this does not hang on a password prompt
    (sudoers NOPASSWD or similar).
    """
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
    """
    Stop the running tcpdump (like Ctrl+C), then extract features and retrain.
    """
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
    # For anything beyond pure local dev, it's safer not to expose debug info
    app.run(host="0.0.0.0", port=5000, debug=False)
