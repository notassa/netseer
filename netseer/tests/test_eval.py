"""Eval helpers: ACP metrics and UNSW-NB15 ground-truth matching on the A5.6 example."""

from __future__ import annotations

from datetime import timedelta

from netseer.eval.acp_metrics import metrics, saturation
from netseer.eval.unsw_validate import validate
from netseer.src.engine.acp import run_acp
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
