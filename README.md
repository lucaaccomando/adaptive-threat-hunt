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
- Done: a leave-one-attack-type-out study (`models/leave_one_out.py`). Its results are not generated yet.
- Partly done: the detection map (`models/detection_map.py`). Attack-type positions are computed; the
  recall analysis waits for the leave-one-out results.
- Not done: a second dataset, label-free thresholds, a hybrid detector, and a table of evaluation
  pitfalls.

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

### Detection map (positions only)

For each attack type, x is its distance from normal training flows and y its distance from the other
attack types, in standardized feature units. The positions use the mean distance to the 5 nearest
reference flows, taken as the median over the type's flows. Reference flows come from KDDTrain+ only.
Of the 30 types (13 from KDDTrain+ and 17 that appear only in KDDTest+), 27 lie at x below 12. The
three that do not are xterm, sqlattack and xsnoop, all KDDTest+ types, at x between 64 and 145.
In KDDTest+, 30 unseen attack flows are exact copies of a KDDTrain+ normal flow: 28 are snmpgetattack, one
named and one snmpguess. The map's recall colours are not computed yet.

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
- The capture pipeline is experimental. When no pcap is given, `feature_extractor/extract.py` writes two
  demo rows instead of failing. Fixing that is the next step on the list, and the path is not evaluated.
- One dataset. A second dataset with genuinely new attacks is planned.

## Setup

macOS or Linux:

```bash
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Windows (PowerShell):

```powershell
git clone https://github.com/lucaaccomando/adaptive-threat-hunt.git
cd adaptive-threat-hunt
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q
```

Reproduce the results:

```bash
python models/evaluate.py                    # default protocol, about 5 minutes
python models/evaluate.py --train-on normal  # unsupervised models trained on normal flows only
python models/detection_map.py               # attack-type positions on the map
```

These write `results/benchmark.json`, `results/benchmark_normal_only.json` and
`results/detection_map.json`, with a figure for each. The leave-one-attack-type-out study is
`python models/leave_one_out.py`. It takes about 1.5 hours and has not been run yet.

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
