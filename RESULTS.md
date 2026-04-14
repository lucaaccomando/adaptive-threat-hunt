# Benchmark Results

All models evaluated on the **NSL-KDD** dataset (standard IDS benchmark, University of New Brunswick).  
Evaluation uses a fixed train/test split with `StandardScaler` fit on train only (no data leakage).  
Anomaly score thresholds are set at the dataset's known attack ratio (~46%).

## Model Comparison

| Model | F1 | Precision | Recall | Accuracy | ROC-AUC | Train Time |
|---|---|---|---|---|---|---|
| Isolation Forest | 0.4476 | **0.9535** | 0.2924 | 0.5891 | **0.8701** | 1.4s |
| Local Outlier Factor | **0.6245** | 0.7464 | **0.5369** | **0.6325** | 0.6834 | 16.7s |
| One-Class SVM | 0.4191 | 0.8276 | 0.2806 | 0.5572 | 0.7764 | 1.7s |

🏆 **Best F1:** Local Outlier Factor (0.6245)  
🎯 **Best ROC-AUC:** Isolation Forest (0.8701)

## Interpretation

- **Isolation Forest** achieves the highest ROC-AUC (0.87), meaning its anomaly scores are well-separated — the model *knows* what an attack looks like. The low recall is a threshold effect, not a model failure. With threshold tuning, this model has the highest upside.
- **Local Outlier Factor** is the most balanced performer. Best F1 and recall, but slowest to train (~17s) and lowest ROC-AUC — its score distribution is less separable.
- **One-Class SVM** was subsampled to 15,000 rows for speed and still underperforms both alternatives. Not recommended for this dataset at scale.

## Reproducing These Results

```bash
python models/evaluate.py
```

Results are saved to `results/benchmark.json` automatically.

## Dataset

- **NSL-KDD** — a cleaned version of the KDD Cup 1999 dataset, removing duplicate records that biased the original.
- Auto-downloaded by `evaluate.py` on first run (~1MB).
- Source: [University of New Brunswick](https://www.unb.ca/cic/datasets/nsl.html)
- Train split: `KDDTrain+.txt` | Test split: `KDDTest+.txt`
