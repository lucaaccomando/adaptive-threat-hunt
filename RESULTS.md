# Results

These results come from the scripts in `models/`. Each number is read from a JSON file in `results/`, and
each section names its source. Dataset: NSL-KDD. KDDTrain+ is used for training and validation, KDDTest+
for testing. The README has the short version; this file has the details.

## Protocol

- Models train on 80% of KDDTrain+ (125,973 flows, 47% attacks). A stratified 20% validation split, drawn
  again for each seed, sets the alert thresholds. The thresholds are then applied unchanged to KDDTest+
  (22,544 flows, 57% attacks).
- Isolation Forest, LOF and One-Class SVM train without labels. The validation split uses labels, only to
  choose thresholds. Random Forest uses labels in training.
- The scaler is fit on the training split only. Seeds 0 to 4. Tables show means; the spread is in the JSON.
- Operating points: the max-F1 threshold on validation; a threshold that gives 1% or 5% false alarms on
  validation normal flows; and label-free thresholds at the 95th and 99th percentile of all validation
  scores.
- KDDTest+ contains 17 attack types that never appear in KDDTrain+ (3,750 flows, 29% of test attacks).
  Test rows are grouped by type only for the analysis in sections 4 and 5.

## 1. Ranking quality and fixed false-alarm operating points

Source: `results/benchmark.json`, `results/benchmark_normal_only.json`.

| Detector | Training | ROC-AUC | PR-AUC |
|---|---|---|---|
| Random Forest | labels | 0.961 | 0.963 |
| Isolation Forest | normal flows only | 0.927 | 0.949 |
| Isolation Forest | all training flows | 0.880 | 0.894 |
| One-Class SVM | normal flows only | 0.853 | 0.862 |
| One-Class SVM | all training flows | 0.785 | 0.819 |
| Local Outlier Factor | normal flows only | 0.835 | 0.815 |
| Local Outlier Factor | all training flows | 0.686 | 0.709 |

Recall at a validation-set false-alarm target. "Test FPR" is the false-alarm rate that the same threshold
produces on KDDTest+. "Precision at 1%" re-weights test recall and false-alarm rate to a 1% attack base rate
(Axelsson, 1999).

| Detector | Training | Target | Test FPR | Recall, all | Recall, seen | Recall, unseen | Precision at 1% |
|---|---|---|---|---|---|---|---|
| Isolation Forest | normal flows only | 1% | 0.007 | 0.540 | 0.595 | 0.407 | 0.42 |
| Isolation Forest | normal flows only | 5% | 0.022 | 0.638 | 0.644 | 0.622 | 0.22 |
| Isolation Forest | all training flows | 1% | 0.003 | 0.133 | 0.063 | 0.301 | 0.34 |
| Isolation Forest | all training flows | 5% | 0.014 | 0.258 | 0.137 | 0.552 | 0.17 |
| Random Forest | labels | 1% | 0.064 | 0.818 | 0.852 | 0.737 | 0.12 |
| Random Forest | labels | 5% | 0.126 | 0.960 | 0.979 | 0.913 | 0.07 |
| One-Class SVM | normal flows only | 5% | 0.079 | 0.661 | 0.783 | 0.366 | 0.08 |
| Local Outlier Factor | normal flows only | 5% | 0.102 | 0.474 | 0.554 | 0.281 | 0.05 |

Reading the table:

- The forest ranks flows best and has the highest recall at each target. Its validation thresholds do not
  transfer: a 1% target gives a 6.4% false-alarm rate on KDDTest+, and a 5% target gives 12.6%.
- Training Isolation Forest on normal flows only makes it much more selective. At max F1 its false-alarm rate
  falls from 36% to 6.5%, ROC-AUC rises from 0.88 to 0.93, and recall on unseen types at max F1 falls from
  0.87 to 0.75.
- LOF trained on all flows flags 99.7% of normal test flows at its best validation F1. Its F1 of 0.726 is
  the flag-all score at this base rate (2p / (1 + p) = 0.725). That row is not a result.
- The best-F1 comparison favours normal-only Isolation Forest (0.821 against 0.796 for the forest), but the
  two thresholds sit at different false-alarm rates (6.5% and 2.8%). It is not a like-for-like comparison.

## 2. Ablations: training data, encoding and tuning

Source: `results/benchmark_*.json`. ROC-AUC on KDDTest+, means over five seeds.

| Variant | Isolation Forest | One-Class SVM | LOF | Random Forest |
|---|---|---|---|---|
| default (all flows, categorical columns dropped) | 0.880 | 0.785 | 0.686 | 0.961 |
| normal flows only | 0.927 | 0.853 | 0.835 | 0.961 |
| one-hot categorical columns | 0.872 | 0.679 | 0.648 | 0.961 |
| normal flows only, one-hot | 0.940 | 0.931 | 0.869 | 0.961 |
| log1p on heavy-tailed columns | 0.899 | 0.827 | 0.719 | 0.961 |
| tuned hyperparameters | 0.882 | 0.742 | 0.695 | 0.964 |

- Encoding and training data interact. One-hot columns help the normal-only One-Class SVM (0.853 to 0.931)
  and hurt the One-Class SVM trained on all flows (0.785 to 0.679).
- Tuning on validation PR-AUC lowers One-Class SVM's test ROC-AUC (0.785 to 0.742). Validation is drawn from
  the same distribution as training, so it cannot see the shift to KDDTest+.
- log1p is chosen by no rule here. Validation PR-AUC favours no transform, while test ROC-AUC favours log1p
  for all three unsupervised models. The default stays "none", chosen on validation, and both are shown.
- The best unsupervised ROC-AUC is normal-only One-Class SVM with one-hot columns (0.931). At its max-F1
  threshold it reaches F1 0.882 at a 9.1% false-alarm rate, so it is not comparable to the forest's F1 at
  2.8%.

## 3. Label-free thresholds

Source: `results/benchmark.json`, `results/benchmark_normal_only.json`, fields `quantile_95` and
`quantile_99`. The threshold is the 95th or 99th percentile of the scores of all validation flows. No labels
are used to set it.

| Detector | Training | 95th: test FPR | 95th: recall | 99th: test FPR | 99th: recall |
|---|---|---|---|---|---|
| Isolation Forest | normal flows only | 0.000 | 0.048 | 0.000 | 0.022 |
| Isolation Forest | all training flows | 0.006 | 0.194 | 0.001 | 0.048 |
| One-Class SVM | normal flows only | 0.017 | 0.144 | 0.004 | 0.019 |
| Random Forest | labels | 0.006 | 0.419 | 0.006 | 0.419 |

Validation is 47% attacks, so the percentile lands where the attacks are, not where the false-alarm rate is.
The alert rate then depends on the unknown attack share. A threshold that targets a false-alarm rate needs a
validation set known to be benign. NSL-KDD does not have one, so these rules do not target a false-alarm rate,
and the fixed-false-alarm comparison on KDDTest+ remains open.

## 4. Leave-one-attack-type-out on KDDTrain+

Source: `results/leave_one_out.json`. Each held-out type (13 types with at least 20 flows, plus four
categories) is removed from training and validation. Its flows form the attack side of the test set, next to
20% of the normal flows. Test normals come from the same file as training, so the false-alarm rate stays
on target: 0.041 to 0.051 for every model and category below.

Recall at a 5% false-alarm target, five seeds:

| Held out | Random Forest | Isolation Forest, normal only | One-Class SVM, normal only | LOF, normal only |
|---|---|---|---|---|
| DoS (6 types) | 0.993 | 0.909 | 0.938 | 0.518 |
| Probe (4 types) | 0.966 | 0.542 | 0.761 | 0.733 |
| R2L (8 types) | 0.473 | 0.169 | 0.441 | 0.467 |
| U2R (4 types) | 0.931 | 0.235 | 0.669 | 0.550 |

Single types show the same split. The forest recalls teardrop, pod and warezmaster at 1.000, while normal-only
Isolation Forest recalls 0.105, 0.045 and 0.050. The forest's weakest single type is warezclient (0.475).

Normal-only models never see attacks, so their recall on a type reflects how far that type lies from normal
traffic (section 5). These are not strict zero-day tests: the other attack types in training can be close
relatives of a held-out type, which probably helps the forest most.

## 5. Detection map

Source: `results/detection_map.json`, feature space of 38 numeric columns, k = 5 nearest reference flows.
x is the distance of a type from normal training flows, y its distance from the other attack types, both
measured on KDDTrain+. Recall for held-out types comes from section 4. Recall for unseen KDDTest+ types comes
from the benchmark at the 5% validation target, where the test false-alarm rate drifts (12.6% for the forest,
2.2% for normal-only Isolation Forest). The groups are therefore analysed separately as well as pooled.

Spearman rank correlation between position and recall over types, with 95% bootstrap intervals:

| Group (types) | x vs forest recall | x vs Isolation Forest (normal) recall | y vs forest recall |
|---|---|---|---|
| All (30) | 0.74 [0.48, 0.89] | 0.62 [0.33, 0.84] | 0.41 [0.04, 0.70] |
| Held out (13) | 0.48 [-0.18, 0.87] | 0.37 [-0.25, 0.96] | 0.37 [-0.26, 0.83] |
| Unseen in KDDTest+ (17) | 0.76 [0.35, 0.94] | 0.68 [0.22, 0.91] | 0.31 [-0.20, 0.75] |

Leave-one-type-out prediction of recall from (x, y) does not beat the mean of the other types. Mean absolute
error over all 30 types is 0.17 for the forest against 0.17 for the mean, and 0.33 against 0.30 for normal-only
Isolation Forest.

- Distance from normal traffic goes with recall for both detectors, as the second hypothesis predicts for
  the anomaly detector.
- Distance from other attack types does not predict forest recall in the direction the first hypothesis
  predicts. The pooled sign is positive: types close to known attacks are not caught more. The interval barely
  excludes zero, and the held-out and unseen groups are not significant.
- The blind-spot hypothesis (types near normal traffic and far from other attacks) is not tested by these
  correlations.
- Position explains the ranking of types, not the recall of a single type.
- The x ranking is stable across neighbour counts (Spearman 0.97 at k=1, 0.99 at k=20). Encoding the
  categorical columns one-hot moves it more (0.88 to 0.92), so the map depends partly on that choice.

Positions: 27 of the 30 types lie at x below 12. xterm, sqlattack and xsnoop, all KDDTest+ types, lie at x
between 64 and 145. In KDDTest+, 30 unseen attack flows are exact copies of a KDDTrain+ normal flow: 28 are
snmpgetattack, one named and one snmpguess.

## 6. Forest plus an anomaly detector at a fixed false-alarm budget

Source: `results/hybrid.json`. The budget is 5% of validation normal flows, shared between the forest and an
anomaly detector: the forest alerts on flows above its threshold, the detector alerts on flows the forest calls
normal. The split is chosen on validation recall, and the forest's share of the budget varied by seed (25% to
100%). The forest-alone row uses the full budget. Test normals only measure the false-alarm rate.

| Alerts | Test FPR | Recall, seen | Recall, unseen | Recall, R2L |
|---|---|---|---|---|
| Forest alone | 0.126 | 0.979 | 0.913 | 0.825 |
| Forest + Isolation Forest (normal only) | 0.107 | 0.938 | 0.866 | 0.670 |
| Forest + One-Class SVM (normal only) | 0.121 | 0.961 | 0.891 | 0.751 |
| Forest + Isolation Forest (all flows) | 0.107 | 0.938 | 0.866 | 0.670 |

At the same validation budget, adding an anomaly detector does not beat the forest alone on this test set. The
forest's share of the budget shrinks, and the recall it loses is larger than what the detector adds. The test
false-alarm rates differ by about two points, so the comparison is matched on validation, not on test.

Per type, the gains are small. Normal-only Isolation Forest adds no type that the forest misses by more than
0.01 (buffer_overflow). Normal-only One-Class SVM adds sendmail (+0.17 recall) and loses recall on guess_passwd,
mailbomb, phf and snmpguess. sendmail sits near normal traffic (x = 1.08) and far from the other attack types
(y = 4.38) on the detection map.

## 7. Evaluation pitfalls

Source: `results/pitfalls.json`, computed from the benchmark JSON files. Each row changes one thing and
reports the headline with and without it.

| Mistake | Model | With | Without | Shift |
|---|---|---|---|---|
| threshold chosen on test labels (F1) | Random Forest | 0.936 | 0.796 | +0.139 |
| threshold chosen on test labels (F1) | Isolation Forest | 0.838 | 0.835 | +0.003 |
| max-F1 threshold reported as the operating point (test FPR, vs 5% target) | Isolation Forest | 0.360 | 0.0135 | +0.347 |
| max-F1 threshold reported as the operating point (test FPR, vs 5% target) | Random Forest | 0.028 | 0.126 | -0.098 |
| precision at the test base rate, vs 1% base rate | Random Forest | 0.970 | 0.196 | +0.773 |
| precision at the test base rate, vs 1% base rate | Isolation Forest | 0.770 | 0.025 | +0.745 |
| default threshold, vs validation threshold (F1) | Random Forest | 0.749 | 0.796 | -0.048 |
| default threshold, vs validation threshold (F1) | Isolation Forest | 0.458 | 0.835 | -0.377 |
| all training flows, vs normal only (unseen recall at max F1) | Isolation Forest | 0.868 | 0.749 | +0.119 |
| fixed 5% target, drifted test FPR vs target | Random Forest | 0.126 | 0.050 | +0.076 |
| flag-all detector reported as a result (F1) | LOF | 0.726 | 0.725 | +0.000 |

The first row is the one to read. The earlier headline that Isolation Forest beat Random Forest was a
comparison in which only one model was tuned on test labels. When both models get the same treatment, the
forest wins on test-label F1 (0.936 against 0.838). The other rows show that the reported number depends on
the threshold rule and the base rate, not only on the detector.

The second-dataset row ("one dataset vs two") waits for P0-10.

## 8. Limitations

- NSL-KDD is derived from 1998 DARPA traffic simulations. It is dated, and its attacks are simulated. These
  results describe this dataset, not current traffic.
- Alert thresholds use labels from a validation split (20% of KDDTrain+), except the label-free rows in
  section 3, which do not give a false-alarm rate.
- The matched false-alarm comparison on the test set is missing. Section 4 gives one inside KDDTrain+ only.
- Held-out types in section 4 still have relatives in training.
- The detection map has 13 to 30 types, so its intervals are wide. The pooled groups mix two operating points.
- The hybrid's test false-alarm rates differ from the forest's by about two points, and the budget split is
  chosen on validation. No gain was measured.
- The 38 numeric columns are the main feature set. The three categorical columns are dropped in the main
  results. The capture pipeline uses a different 8-feature set, so these results say nothing about it.
- One dataset.

## 9. Not done

- A second dataset with genuinely new attacks (CIC-IDS2017 with corrected labels is the proposal). It needs a
  download decision.
- A label-free threshold that targets a false-alarm rate. It needs a benign-only capture.
- The capture pipeline is checked on a synthetic capture only. It is not evaluated against labelled traffic.

## References

- Arp, Quiring, Pendlebury, Warnecke, Pierazzi, Wressnegger, Cavallaro, Rieck. Dos and Don'ts of Machine
  Learning in Computer Security. USENIX Security Symposium, 2022.
- Axelsson, S. The base-rate fallacy and its implications for the difficulty of intrusion detection. ACM
  Conference on Computer and Communications Security, 1999.
- Breunig, Kriegel, Ng, Sander. LOF: Identifying Density-Based Local Outliers. ACM SIGMOD, 2000, pp. 93-104.
- Engelen, Rimmer, Joosen. CICIDS2017 relabelling. IEEE Security and Privacy Workshops, 2021, pp. 7-12.
  DOI 10.1109/SPW53761.2021.00009.
- Liu, Ting, Zhou. Isolation Forest. IEEE International Conference on Data Mining, 2008, pp. 413-422.
- Schoelkopf, Platt, Shawe-Taylor, Smola, Williamson. Estimating the Support of a High-Dimensional
  Distribution. Neural Computation 13(7), 2001, pp. 1443-1471.
- Sommer, Paxson. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.
  IEEE Symposium on Security and Privacy, 2010. DOI 10.1109/SP.2010.25.
- Tavallaee, Bagheri, Lu, Ghorbani. A Detailed Analysis of the KDD CUP 99 Data Set. IEEE Symposium on
  Computational Intelligence for Security and Defense Applications, 2009, pp. 1-6.
