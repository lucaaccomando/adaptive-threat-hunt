#!/usr/bin/env python3
from flask import Flask, render_template_string, redirect, url_for, request, send_file
from pathlib import Path
import os
import pandas as pd
import io
import subprocess


app = Flask(__name__)

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


@app.route("/")
def index():
    data_dir = os.path.abspath("data")
    have_features = Path("data/features.csv").exists()
    have_model = Path("models/model.pkl").exists()
    have_scored = Path("data/scored.csv").exists()

    return render_template_string(
        INDEX_TEMPLATE,
        data_dir=data_dir,
        have_features=have_features,
        have_model=have_model,
        have_scored=have_scored,
    )


@app.route("/generate")
def generate():
    os.system("python feature_extractor/extract.py")
    return redirect(url_for("index"))


@app.route("/train")
def train():
    os.system("python models/train.py --csv data/features.csv --model models/model.pkl")
    return redirect(url_for("index"))


@app.route("/score")
def score():
    os.system(
        "python models/score.py "
        "--csv data/features.csv "
        "--model models/model.pkl "
        "--out data/scored.csv"
    )
    return redirect(url_for("anomalies"))


@app.route("/anomalies")
def anomalies():
    scored_path = Path("data/scored.csv")
    if not scored_path.exists():
        return "No data/scored.csv found. Click 'Score flows' on the home page first.", 404

    df = pd.read_csv(scored_path)

    total = len(df)
    num_anom = int(df["is_anomaly"].sum()) if "is_anomaly" in df.columns else 0
    percent = (num_anom / total * 100.0) if total else 0.0

    # view mode: only anomalies (default) or all
    view_mode = request.args.get("view", "anom")
    df_view = df

    if "anomaly_score" in df.columns:
        # IsolationForest: more negative = more anomalous, so sort ascending
        df_view = df_view.sort_values("anomaly_score", ascending=True)

    if view_mode == "anom" and "is_anomaly" in df_view.columns:
        df_view = df_view[df_view["is_anomaly"] == 1]

    # cap number of rows for the table
    df_view = df_view.head(100)
    rows_shown = len(df_view)

    # prettier tag for is_anomaly
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
    scored_path = Path("data/scored.csv")
    if not scored_path.exists():
        return "No data/scored.csv found. Click 'Score flows' on the home page first.", 404

    df = pd.read_csv(scored_path)

    if "is_anomaly" in df.columns:
        df = df[df["is_anomaly"] == 1]

    # export to an in-memory CSV
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)

    return send_file(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name="anomalies.csv",
    )
@app.route("/live-capture")
def live_capture():
    """
    Capture a short PCAP from the VM, extract features, and retrain the model.
    """
    # TODO: change this to your actual interface if needed (e.g., "eth0", "ens33")
    iface = "ens33"

    data_dir = Path("data")
    data_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = data_dir / "live_capture.pcap"
    csv_path = data_dir / "features.csv"
    model_path = Path("models") / "model.pkl"

    # 1) Capture 2000 packets (or stop with Ctrl+C in the terminal)
    capture_cmd = [
        "sudo",
        "tcpdump",
        "-i", iface,
        "-w", str(pcap_path),
        "-c", "2000",
    ]
    subprocess.run(capture_cmd, check=True)

    # 2) Extract features from that PCAP
    extract_cmd = [
        "python",
        "feature_extractor/extract.py",
        "--pcap", str(pcap_path),
        "--out", str(csv_path),
    ]
    subprocess.run(extract_cmd, check=True)

    # 3) Retrain the model on the new CSV
    train_cmd = [
        "python",
        "models/train.py",
        "--csv", str(csv_path),
        "--model", str(model_path),
    ]
    subprocess.run(train_cmd, check=True)

    return "Live capture + training complete. <a href='/'>Back to dashboard</a>"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
