import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "models"))
from pitfalls import MODELS, flag_all_f1, main


def _m(v):
    return {"mean": v, "std": 0.0}


def _model(f1, fpr, prec, prec1, unseen):
    op = {"f1": _m(f1), "fpr": _m(fpr), "precision": _m(prec), "precision_prev1": _m(prec1),
          "recall": _m(unseen), "recall_by_group": {"unseen": _m(unseen)}}
    return {"oracle_test_max_f1": {"f1": _m(f1 + 0.01)}, "val_threshold": op,
            "fpr_5pct": {"fpr": _m(fpr + 0.02), "recall": _m(unseen), "recall_by_group": {"unseen": _m(unseen)}},
            "default": {"f1": _m(f1 - 0.05)}}


def _run(prevalence, value):
    summary = {m: _model(value, 0.03, 0.9, 0.2, 0.5) for m in MODELS}
    return {"attack_prevalence": {"test": prevalence}, "summary": summary}


def test_pitfalls_read_fields_and_write_json(tmp_path):
    for name in ("benchmark.json", "benchmark_normal_only.json", "benchmark_onehot.json"):
        (tmp_path / name).write_text(json.dumps(_run(0.5, 0.8)))

    out = tmp_path / "pitfalls.json"
    main(["--results", str(tmp_path), "--out", str(out)])
    res = json.loads(out.read_text())
    assert len(res["rows"]) == 4 + 4 + 4 + 4 + 3 + 4 + 4 + 1
    assert len(res["not_yet"]) == 1

    (tmp_path / "cicids2017_benchmark.json").write_text(json.dumps(_run(0.5, 0.8)))
    main(["--results", str(tmp_path), "--out", str(out)])
    res = json.loads(out.read_text())
    assert res["test_attack_prevalence"] == 0.5
    assert len(res["rows"]) == 4 + 4 + 4 + 4 + 3 + 4 + 4 + 1 + 4 + 4
    assert res["not_yet"] == []
    leak = next(r for r in res["rows"] if r["pitfall"].startswith("threshold chosen on test")
                and r["model"] == "Random Forest")
    assert leak["with_mistake"] == 0.81 and leak["without_mistake"] == 0.8
    assert leak["shift"] == 0.01


def test_flag_all_f1_matches_definition():
    # flag everything: precision = p, recall = 1
    p = 0.3
    precision, recall = p, 1.0
    assert abs(flag_all_f1(p) - 2 * precision * recall / (precision + recall)) < 1e-12
