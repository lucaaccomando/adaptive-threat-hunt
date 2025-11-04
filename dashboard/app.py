from flask import Flask, render_template_string
import os

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Adaptive Threat Hunt</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
      .card { border: 1px solid #ddd; border-radius: 12px; padding: 1rem 1.2rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
      .muted { color: #666; }
      a.btn { display: inline-block; margin-right: 0.5rem; border: 1px solid #333; border-radius: 8px; padding: 0.5rem 0.75rem; text-decoration: none; color: #111; }
      code { background: #f6f8fa; padding: 2px 5px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <h1>Adaptive Threat Hunt — Starter Dashboard</h1>
    <p class="muted">Click below to generate features or train a model.</p>

    <div class="card">
      <h3>Actions</h3>
      <p>
        <a class="btn" href="/generate">Generate demo features</a>
        <a class="btn" href="/train">Train model</a>
      </p>
      <p class="muted">Data folder: {{ data_dir }}</p>
    </div>
  </body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE, data_dir=os.path.abspath("data"))

@app.route("/generate")
def generate():
    os.system("python feature_extractor/extract.py")
    return "Generated features at data/features.csv. <a href='/'>Back</a>"

@app.route("/train")
def train():
    os.system("python models/train.py --csv data/features.csv --model models/model.pkl")
    return "Trained model at models/model.pkl. <a href='/'>Back</a>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)