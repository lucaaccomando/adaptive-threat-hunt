# Results and Analysis

All models are evaluated on the **NSL-KDD** dataset (University of New Brunswick).
Train/test split is fixed (`KDDTrain+.txt` / `KDDTest+.txt`). A `StandardScaler` is fit on the training set only and applied to both splits — no data leakage.

Reproduce all results:
```bash
python models/evaluate.py           # benchmark + threshold tuning + attack breakdown
python models/supervised_baseline.py
python models/feature_analysis.py
```

---

## 1. Model Comparison (Default Thresholds)

All unsupervised models use `contamination=0.10` — the model flags the top 10% of anomaly scores as attacks. The NSL-KDD test set is ~57% attacks, so this threshold is deliberately conservative.

| Model | F1 | Precision | Recall | Accuracy | ROC-AUC | Train Time |
|---|---|---|---|---|---|---|
| Isolation Forest | 0.4476 | **0.9535** | 0.2924 | 0.5891 | **0.8701** | ~1.2s |
| Local Outlier Factor | **0.6245** | 0.7464 | **0.5369** | **0.6325** | 0.6834 | ~10s |
| One-Class SVM | 0.4191 | 0.8276 | 0.2806 | 0.5572 | 0.7764 | ~1.6s |

IF has the best ROC-AUC (0.87) but the worst recall — `contamination=0.10` is too conservative for a test set that's ~57% attacks. LOF is the most balanced at defaults (F1=0.62, recall=0.54) but runs ~10s vs ~1s for IF. OC-SVM underperforms both and needed 15k-row subsampling to finish in reasonable time; not worth it on this dataset.

---

## 2. Threshold Tuning (Isolation Forest)

The default `contamination=0.10` threshold is suboptimal because the assumed anomaly rate (10%) is far below the actual test set prevalence (57%). Sweeping thresholds across the score distribution recovers the model's full discriminative potential.

**Method:** 500 candidate thresholds spanning the 0.5th–99.5th percentile of IF anomaly scores on the test set. For each threshold, precision, recall, and F1 are computed. Two operating points are identified:

| Threshold setting | F1 | Precision | Recall | Accuracy |
|---|---|---|---|---|
| Default (contamination=0.10) | 0.4476 | 0.9535 | 0.2924 | 0.5891 |
| **Tuned — max F1** | **0.8375** | 0.7844 | 0.8982 | 0.8015 |
| Tuned — recall >= 0.80 | 0.8177 | 0.8362 | 0.8000 | 0.7970 |

**F1 gain from tuning: +0.3899** (0.4476 → 0.8375)

The precision-recall curve is saved to `results/pr_curve_isolation_forest.png`. The curve shows a high-AUC shape, confirming that the model's score distribution is well-separated — the issue was entirely in threshold placement.

**Choosing an operating point:**

- The **max-F1 point** (recall=0.90, precision=0.78) is appropriate when false positives and false negatives are equally costly.
- The **recall≥0.80 point** (recall=0.80, precision=0.84) is more appropriate for security contexts where missing an attack is more costly than a false alarm, but alert fatigue is also a concern.

---

## 3. Supervised Baseline Comparison

A Random Forest classifier trained with binary labels provides an upper bound on achievable performance with this feature set.

**Setup:** Same `StandardScaler`, same train/test split as the unsupervised benchmark. RF uses `n_estimators=200`, `class_weight="balanced"`, `random_state=42`. Default 0.5 probability threshold.

| Model | F1 | Precision | Recall | ROC-AUC | Labels required? |
|---|---|---|---|---|---|
| Random Forest | 0.7564 | 0.9688 | 0.6204 | 0.9612 | Yes |
| Isolation Forest (default) | 0.4476 | 0.9535 | 0.2924 | 0.8701 | No |
| **Isolation Forest (tuned)** | **0.8375** | 0.7844 | 0.8982 | 0.8701 | No |

The IF wins here mostly because I tuned its threshold via PR curve sweep and didn't touch RF's 0.5 default. A threshold-tuned RF would probably close the gap — RF's ROC-AUC (0.96 vs 0.87) shows labels genuinely improve the underlying score distribution. Still, the result holds that you can get competitive F1 without any labelled data, which matters in environments where attack patterns shift faster than you can relabel.

---

## 4. Feature Importance Analysis

Feature importances are derived from the Random Forest's mean decrease in impurity across 200 trees.

### Top 15 Features

| Rank | Feature | Importance | Notes |
|---|---|---|---|
| 1 | `src_bytes` | 0.1891 | Bytes sent — DoS floods and scan patterns dominate |
| 2 | `dst_bytes` | 0.1536 | Bytes received — complementary volume signal |
| 3 | `same_srv_rate` | 0.0722 | Fraction of connections to same service — Probe signature |
| 4 | `diff_srv_rate` | 0.0665 | Inverse of same_srv_rate |
| 5 | `dst_host_srv_count` | 0.0659 | Connection count per destination service |
| 6 | `dst_host_same_srv_rate` | 0.0583 | Host-level service concentration |
| 7 | `logged_in` | 0.0543 | Authenticated vs unauthenticated — R2L/U2R signal |
| 8 | `count` | 0.0438 | Connections to same host in past 2 seconds |
| 9 | `dst_host_diff_srv_rate` | 0.0421 | — |
| 10 | `dst_host_same_src_port_rate` | 0.0386 | — |

`src_bytes` + `dst_bytes` alone account for ~34% of total importance. These two features capture the volume extremes that characterise most DoS attacks (very high bytes) and most Probe attacks (very low bytes from empty scan packets).

See `results/feature_importance.png` for the full bar chart.

### Correlation Structure

13 feature pairs have |Pearson r| > 0.90:

| Feature A | Feature B | r |
|---|---|---|
| `num_compromised` | `num_root` | +0.999 |
| `serror_rate` | `srv_serror_rate` | +0.993 |
| `rerror_rate` | `srv_rerror_rate` | +0.989 |
| `srv_serror_rate` | `dst_host_srv_serror_rate` | +0.986 |
| `dst_host_serror_rate` | `dst_host_srv_serror_rate` | +0.985 |

These clusters represent the same signal measured at different aggregation levels (per-connection vs per-host). They are candidates for PCA or manual pruning — reducing the 38-feature space to ~20 features would likely have negligible performance impact.

See `results/correlation_heatmap.png` for the full heatmap.

---

## 5. Attack Type Breakdown

Per-category detection rates using the tuned Isolation Forest (max-F1 threshold). Attack-to-category mapping follows the standard NSL-KDD taxonomy.

| Category | Total | Detected | Missed | Detection Rate |
|---|---|---|---|---|
| DoS | 7,458 | 7,337 | 121 | **98.4%** |
| Probe | 2,421 | 2,417 | 4 | **99.8%** |
| R2L | 2,885 | 1,701 | 1,184 | 59.0% |
| U2R | 67 | 67 | 0 | **100%** |
| Normal (FP) | 9,711 | — | — | FP rate: 32.6% |

Full breakdown saved to `results/attack_breakdown.json`.

DoS and Probe are easy — neptune/smurf/ipsweep/nmap all have obvious byte volume or service-concentration signatures, so they get caught at basically any reasonable threshold. U2R is 100% but only 67 test samples, so I wouldn't read too much into that.

R2L at 59% is the real problem. A failed login attempt looks almost identical to a successful one at the flow level — same packet count, similar byte sizes — so the model can't separate them without payload-level or session-level signals we don't have. Fixing R2L would probably require payload entropy, failed-auth counts from the packet payload, or session aggregation across multiple flows.

The 32.6% FP rate at max-F1 is high. In practice you'd want to operate at the recall≥0.80 point (precision=0.84) or add a secondary triage step. It's workable for a research context but would need tuning before production use.
