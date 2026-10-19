from pathlib import Path
import os
# --- Directories ---------------------------------------------------------------

BASE_DIR    = Path(__file__).parent.parent  # repo root
DATA_DIR    = BASE_DIR / "data"
MODELS_DIR  = BASE_DIR / "models"
RESULTS_DIR = BASE_DIR / "results"

for p in (DATA_DIR, MODELS_DIR, RESULTS_DIR):
    p.mkdir(parents=True, exist_ok=True)

# --- Live capture --------------------------------------------------------------

CAPTURE_PID_FILE = DATA_DIR / "tcpdump.pid"
CAPTURE_IFACE    = os.environ.get("CAPTURE_IFACE", "ens33")  # override with: export CAPTURE_IFACE=eth0

# --- Script paths (absolute, so subprocess calls work from any working dir) ---

EXTRACT_SCRIPT = BASE_DIR / "feature_extractor" / "extract.py"
TRAIN_SCRIPT   = BASE_DIR / "models" / "train.py"
SCORE_SCRIPT   = BASE_DIR / "models" / "score.py"

# --- Benchmark plots -----------------------------------------------------------

BENCHMARK_PLOTS = [
    ("01_class_distribution.png",     "Class Distribution"),
    ("02_feature_distributions.png",  "Feature Distributions"),
    ("03_correlation_heatmap.png",    "Correlation Heatmap"),
    ("04_anomaly_scores.png",         "Anomaly Score Distributions"),
    ("05_pca_visualization.png",      "PCA Visualization"),
    ("06_precision_recall_curves.png","Precision-Recall Curves"),
]