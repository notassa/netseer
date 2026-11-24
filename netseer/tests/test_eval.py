"""Eval helpers: ACP metrics, risk-model evaluation and UNSW-NB15 ground-truth matching on the A5.6 example."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from netseer.eval.acp_metrics import metrics, saturation
from netseer.eval.risk_eval import ablation, recompute, sensitivity, spearman
from netseer.eval.unsw_validate import validate
from netseer.src.engine.acp import run_acp
from netseer.src.engine.constants import BANDS
from netseer.tests.test_contextor import T0, conn  # noqa: F401 - fixture
from netseer.tests.test_scorer import WORKSTATION, worked_example


def test_metrics_and_saturation(conn):  # noqa: F811
    worked_example(conn)
    run_acp(conn, 1)
    m = metrics(conn, 1)
    assert (m["alerts"], m["groups"], m["incidents"], m["health"]) == (72, 6, 2, 62)
    assert m["bands"]["High"] == 1 and m["bands"]["Medium"] == 1
    assert saturation(conn, 1) == [(1, 67), (2, 62)]


def test_unsw_matching(conn):  # noqa: F811
    worked_example(conn)
    run_acp(conn, 1)
    epoch = lambda minutes: int((T0 + timedelta(minutes=minutes)).timestamp())  # noqa: E731
    gt = [{"start": epoch(10), "end": epoch(12), "category": "Backdoor", "pair": frozenset((WORKSTATION, "198.51.100.66"))},
          {"start": epoch(10), "end": epoch(12), "category": "Fuzzers", "pair": frozenset(("1.2.3.4", "10.0.0.9"))},
          {"start": epoch(900), "end": epoch(901), "category": "DoS", "pair": frozenset((WORKSTATION, "198.51.100.66"))}]
    r = validate(conn, 1, gt, tolerance=60)
    assert (r["in_range"], r["covered"]) == (2, 1)
    assert r["categories"] == {"Backdoor": (1, 1), "Fuzzers": (0, 1)}
    assert r["bands"]["High"] == [1, 0] and r["bands"]["Medium"] == [0, 1]
    assert r["suppressed"] == 0     # the covered Backdoor attack is matched by the High incident


def test_spearman():
    assert spearman([1, 2, 3, 4], [1, 2, 3, 4]) == pytest.approx(1.0)
    assert spearman([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    assert spearman([1, 1, 2], [1, 2, 2]) == pytest.approx(0.5)     # average ranks for ties


def test_recompute_matches_stored_band(conn):  # noqa: F811
    worked_example(conn)
    run_acp(conn, 1)
    for row in conn.execute("SELECT * FROM incidents WHERE analysis_id = 1"):
        assert recompute(json.loads(row["factors_json"])) == row["band"]


def test_sensitivity_and_ablation(conn):  # noqa: F811
    worked_example(conn)
    run_acp(conn, 1)
    rows = conn.execute("SELECT * FROM incidents WHERE analysis_id = 1").fetchall()
    s = sensitivity(rows)
    assert set(s) == {"L1", "L2", "L3", "L4", "L5", "I2", "I3"}
    a = ablation(rows)
    assert set(a) == {"L1", "L2", "L3", "L4", "L5", "I2", "I3", "baseline"}
    stored = {b: 0 for b in BANDS}
    for row in rows:
        stored[row["band"]] += 1
    assert a["baseline"] == stored
