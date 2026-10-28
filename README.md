# Adaptive Threat Hunt

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Dataset](https://img.shields.io/badge/Dataset-NSL--KDD-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A research project on network intrusion detection under novelty, supervised by Dr. Pamela Thompson.
It is a work in progress: the results below are the ones the current code produces, and the open
items are listed in Status.

## Research question

When does a network intrusion detector catch an attack type it has never seen during training, and can
we tell in advance which new attacks it will miss?

Three hypotheses, to be tested rather than assumed:

- A supervised detector catches a new attack type when it resembles the types it was trained on.
- An anomaly detector catches a new attack type when it lies far from normal traffic.
- Attack types that lie close to normal traffic and far from every known attack type are missed by both,
  at a reasonable false-alarm rate.

## Status

- Done: a train / validation / test protocol. Alert thresholds are chosen on a validation split, results
  are averaged over 5 seeds, and recall is reported per attack type and per category at fixed
  false-alarm targets.
- Done: a leave-one-attack-type-out study on KDDTrain+ (`models/leave_one_out.py`). It gives recall at a
  matched false-alarm rate, which the KDDTest+ table cannot.
- Done: the detection map (`models/detection_map.py`). Positions, recall and rank correlations are computed.
- Done: label-free thresholds (quantiles of validation scores, `models/evaluate.py`). On this data they do
  not target a false-alarm rate, and the README says why.
- Done: a forest-plus-anomaly-detector evaluation at a fixed false-alarm budget (`models/hybrid.py`).
  It measured no gain on the test set.
- Done: a table of evaluation pitfalls (`models/pitfalls.py`).
- Not done: a second dataset, and a label-free threshold that targets a false-alarm rate (needs a
  benign-only capture).

The full details, with every table and its source file, are in [`RESULTS.md`](RESULTS.md).

## Results so far (NSL-KDD)

Models train on 80% of KDDTrain+ (125,973 flows, 47% attacks). The other 20%, a stratified split that
changes per seed, picks each detector's alert threshold. That threshold is then applied unchanged to
KDDTest+ (22,544 flows, 57% attacks). KDDTest+ contains 17 attack types that never appear in KDDTrain+
(3,750 flows). Isolation Forest, LOF and One-Class SVM get no labels during training; the validation split
does use labels, to choose the threshold. Random Forest uses labels in training. All numbers are means over
5 seeds. The spread across seeds is in `results/benchmark.json` and `results/benchmark_normal_only.json`.

Ranking quality on KDDTest+:

| Detector | Training | ROC-AUC | PR-AUC |
|---|---|---|---|
| Random Forest | labels | 0.961 | 0.963 |
| Isolation Forest | normal flows only | 0.927 | 0.949 |
| Isolation Forest | all training flows | 0.880 | 0.894 |
| One-Class SVM | normal flows only | 0.853 | 0.862 |

Recall at a fixed false-alarm target. The target is set on validation normal flows. The test column is
the false-alarm rate that the same threshold produces on KDDTest+:

| Detector | Training | Target | Test false-alarm rate | Recall, all | Recall, seen | Recall, unseen | Precision at 1% base rate |
|---|---|---|---|---|---|---|---|
| Isolation Forest | normal flows only | 1% | 0.007 | 0.540 | 0.595 | 0.407 | 0.42 |
| Isolation Forest | normal flows only | 5% | 0.022 | 0.638 | 0.644 | 0.622 | 0.22 |
| Isolation Forest | all training flows | 1% | 0.003 | 0.133 | 0.063 | 0.301 | 0.34 |
| Isolation Forest | all training flows | 5% | 0.014 | 0.258 | 0.137 | 0.552 | 0.17 |
| Random Forest | labels | 1% | 0.064 | 0.818 | 0.852 | 0.737 | 0.12 |
| Random Forest | labels | 5% | 0.126 | 0.960 | 0.979 | 0.913 | 0.07 |
| One-Class SVM | normal flows only | 5% | 0.079 | 0.661 | 0.783 | 0.366 | 0.08 |
| Local Outlier Factor | normal flows only | 5% | 0.102 | 0.474 | 0.554 | 0.281 | 0.05 |

Precision at 1% base rate re-weights the test recall and false-alarm rate to a world where 1% of flows
are attacks, following Axelsson (1999). It is there because NSL-KDD is 57% attacks, which flatters every
detector's precision.

What the table shows so far:

- Random Forest ranks flows best and recalls the most attacks at each target. Its alert threshold does not
  transfer to KDDTest+: a 1% validation target becomes a 6.4% false-alarm rate on the test set, and a 5%
  target becomes 12.6%. The gap is the distribution shift between the two files.
- Normal-only Isolation Forest keeps its false-alarm rate close to target (0.7% and 2.2%) and recalls 62% of
  unseen attack flows at the 5% target. It recalls much less than Random Forest at the same target, but at
  a fraction of the false alarms. A comparison at equal false-alarm rate on the test set is not yet
  possible: that needs thresholds that do not use test labels, which are planned.
- At each detector's best validation F1, normal-only Isolation Forest scores 0.821 and Random Forest 0.796.
  Isolation Forest's threshold sits at a 6.5% false-alarm rate and Random Forest's at 2.8%, so this F1
  comparison is not like-for-like. An earlier version of this README reported Isolation Forest beating
  Random Forest. That number used a threshold tuned on test labels and should not be used.
- Training Isolation Forest on normal flows only changes it a lot. Its false-alarm rate at best validation
  F1 falls from 36% to 6.5%, and ROC-AUC rises from 0.88 to 0.93. Recall on unseen types at that point
  falls from 0.87 to 0.75.
- The gap is widest on R2L attacks (2,885 test flows). At the 5% target Random Forest recalls 83% of them and
  normal-only Isolation Forest 8%. Probe and DoS are caught by both at the 5% target (DoS 0.78 and 0.999 for
  Isolation Forest and Random Forest, Probe 0.88 and 1.00).
- LOF trained on all flows flags almost everything at its best F1 (false-alarm rate 99.7%), so its F1 of
  0.726 is the flag-all score at this test set's 57% base rate. It is not a result.

### Leave-one-attack-type-out (KDDTrain+)

Each held-out type (13 types with at least 20 flows, plus the four categories) is removed from training
and validation. Its flows form the attack side of the test set, next to 20% of the normal flows, which no
model or threshold sees. Thresholds come from validation normals at a 5% target. Test normals come from the
same file as training, so the test false-alarm rate stays on target: 0.041 to 0.051 for every model and
category below. This is the matched comparison the KDDTest+ table cannot give.

Recall at a 5% false-alarm target, 5 seeds:

| Held out | Random Forest | IF, normal only | OC-SVM, normal only | LOF, normal only |
|---|---|---|---|---|
| DoS (6 types) | 0.993 | 0.909 | 0.938 | 0.518 |
| Probe (4 types) | 0.966 | 0.542 | 0.761 | 0.733 |
| R2L (8 types) | 0.473 | 0.169 | 0.441 | 0.467 |
| U2R (4 types) | 0.931 | 0.235 | 0.669 | 0.550 |

Single types show the same split. Random Forest recalls 1.000 of teardrop, pod and warezmaster flows, and
normal-only Isolation Forest recalls 0.105, 0.045 and 0.050 of them. Normal-only models never see attacks,
so their recall on a type reflects how far that type lies from normal traffic. Random Forest's weakest
single held-out type is warezclient (0.475). These are not zero-day tests in the strict sense: the other attack types
in training can still be close relatives of the held-out type.

### Detection map

For each attack type, x is its distance from normal training flows and y its distance from the other
attack types, in standardized feature units. The positions use the mean distance to the 5 nearest
reference flows, taken as the median over the type's flows. Reference flows come from KDDTrain+ only.
Of the 30 types (13 from KDDTrain+ and 17 that appear only in KDDTest+), 27 lie at x below 12. The
three that do not are xterm, sqlattack and xsnoop, all KDDTest+ types, at x between 64 and 145.
In KDDTest+, 30 unseen attack flows are exact copies of a KDDTrain+ normal flow: 28 are snmpgetattack, one
named and one snmpguess. Recall at 5% false alarms is in `results/detection_map.png`, one panel per detector. Held-out types take
their recall from the leave-one-out study, at matched false alarms. Unseen KDDTest+ types take it from the
benchmark at the 5% validation target, where the test false-alarm rate drifts (12.6% for Random Forest,
2.2% for normal-only Isolation Forest). The two groups are therefore also analysed separately.

Spearman rank correlation between position and recall over types, with 95% bootstrap intervals:

| Group (types) | x vs Random Forest recall | x vs IF normal-only recall | y vs Random Forest recall |
|---|---|---|---|
| All (30) | 0.74 [0.48, 0.89] | 0.62 [0.33, 0.84] | 0.41 [0.04, 0.70] |
| Held out (13) | 0.48 [-0.18, 0.87] | 0.37 [-0.25, 0.96] | 0.37 [-0.26, 0.83] |
| Unseen in KDDTest+ (17) | 0.76 [0.35, 0.94] | 0.68 [0.22, 0.91] | 0.31 [-0.20, 0.75] |

Leave-one-type-out prediction of recall from (x, y) does not beat the mean of the other types. Mean absolute
error over all 30 types is 0.17 for Random Forest against 0.17 for the mean, and 0.33 against 0.30 for
normal-only Isolation Forest.

What this says about the three hypotheses:

- Distance from normal traffic goes with recall for both detectors. This matches the second hypothesis for
  the anomaly detector.
- Distance from other attack types does not predict Random Forest recall in the direction the first
  hypothesis predicts. The pooled sign is positive: types close to known attacks are not caught more. The
  interval barely excludes zero.
- The blind-spot hypothesis, types near normal and far from other attacks, is not tested by these
  correlations yet.
- Position explains the ranking of types but does not predict the recall of an individual type.
- The x ranking is stable across neighbour counts (Spearman 0.97 at k=1, 0.99 at k=20). Encoding the
  categorical columns as one-hot moves it more (0.88 to 0.92), so the map depends partly on that choice.

### Label-free thresholds and the hybrid

A threshold set from the scores of all validation flows, with no labels, depends on how many attacks the
validation set contains, not on a false-alarm target. On this data the 95th percentile of validation scores
gives a test false-alarm rate of 0.0% to 0.6% for the detectors shown, and recall of 0.05 to 0.42. The
validation set is 47% attacks, so the percentile lands where the attacks are. A label-free rule that targets
a false-alarm rate needs a validation set known to be benign, which NSL-KDD does not have.

Forest plus anomaly detector, at a 5% false-alarm budget on validation normal flows: the forest alone has a
12.6% test false-alarm rate and 0.913 unseen recall. Forest plus normal-only Isolation Forest has 10.7% and
0.866. Splitting the budget shrinks the forest's share, and the recall it loses is larger than what the
detector adds. Per type, normal-only Isolation Forest adds nothing above 0.01 recall; normal-only One-Class SVM
adds sendmail (+0.17) and loses recall on four other types. The hybrid is an evaluation of a combination,
not a new detector, and it shows no gain on this test set.

## Limitations

- NSL-KDD is derived from DARPA 1998 traffic simulation. It is dated, and its attacks are simulated. These
  results describe this dataset, not current traffic.
- The alert thresholds use labels from a validation split (20% of KDDTrain+). The unsupervised models
  themselves train without labels.
- The false-alarm rate at a validation threshold moves on the test set. For Random Forest, the 1% and 5%
  targets give 6.4% and 12.6% on KDDTest+. Fixed-false-alarm comparisons across detectors on the test set
  are therefore not yet fair.
- Results use 38 numeric features. The three categorical columns are dropped in the main results. The
  capture pipeline uses a different, 8-feature set, so these results say nothing about it.
- The capture pipeline (`feature_extractor/extract.py`, then `train.py` and `score.py`) runs on a pcap and fails
  on a missing or empty capture. It was checked on a synthetic capture only, and it is not evaluated against
  labelled traffic.
- The map pools two operating points, so its pooled correlations mix a 5% matched false-alarm rate with
  drifted ones. With 13 to 30 types, the intervals are wide.
- One dataset. A second dataset with genuinely new attacks is planned.

## Setup

macOS or Linux:

```bash
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Windows (PowerShell):

```powershell
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Reproduce the results:

```bash
python models/evaluate.py                    # default protocol, about 5 minutes
python models/evaluate.py --train-on normal  # unsupervised models trained on normal flows only
python models/detection_map.py               # attack-type positions on the map
python models/hybrid.py                      # forest plus anomaly detector at a fixed budget
python models/pitfalls.py                    # evaluation pitfalls, read from the benchmark JSON
```

These write `results/benchmark.json`, `results/benchmark_normal_only.json`, `results/detection_map.json`,
`results/hybrid.json` and `results/pitfalls.json`, with figures for the benchmark and the map. The leave-one-attack-type-out study is
`python models/leave_one_out.py`. It takes about 1.5 hours and writes `results/leave_one_out.json`.

`bash scripts/run_all.sh` runs every step above in order, plus the other benchmark variants (one-hot, log1p, tuned);
`--with-cic` adds the CIC-IDS2017 study.

The commands above have not been tested from a fresh clone yet.

The NSL-KDD files are in `data/nslkdd/` (about 22 MB, tracked in git). The scripts download them if they
are missing. Checksums are not checked yet.

## Repository layout

```
models/              detectors, benchmark, leave-one-out study, detection map
feature_extractor/   pcap to flow features (experimental)
tests/               pytest suite
results/             JSON outputs and figures
data/nslkdd/         NSL-KDD files
notebooks/           analysis notebooks (not yet rewritten; their numbers are out of date)
```

## Acknowledgements

Research supervised by Dr. Pamela Thompson.

Dataset: NSL-KDD, University of New Brunswick, [https://www.unb.ca/cic/datasets/nsl.html](https://www.unb.ca/cic/datasets/nsl.html).

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

## License

MIT License, copyright 2025 Luca Accomando
