"""Risk-model evaluation for the report: recompute, sensitivity, ablation and expert-rank agreement.

Read-only on the database; no scorer changes. Reuses the pure model from `netseer.src.engine.scorer` and the
`BANDS` order from `netseer.src.engine.constants`.

Usage:
  python -m netseer.eval.risk_eval <analysis_id> [--db path] [--expert ranks.csv]

`--expert` CSV has columns incident_id,expert_rank (1 = most urgent); the rank is compared with NetSeer's order
(band in `BANDS` order, Critical first, then score descending) by Spearman rho with average ranks for ties.
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import sqlite3
import sys
from pathlib import Path

from netseer.src.config import DEFAULT_DB_PATH
from netseer.src.database import db
from netseer.src.engine.constants import BANDS
from netseer.src.engine.scorer import band, impact, likelihood

FACTORS = ("L1", "L2", "L3", "L4", "L5", "I2", "I3")
_NEUTRAL = {"I2": 4, "I3": 4}   # other / other (CONCEPTS A5.2)


def _parsed(row: sqlite3.Row) -> dict:
    return json.loads(row["factors_json"] or "{}")


def recompute(factors: dict) -> str:
    """Band from the stored factor values: L = mean of L1..L5 present, I = impact(I2, I3)."""
    L = likelihood(factors[k]["value"] for k in ("L1", "L2", "L3", "L4", "L5"))  # noqa: N806
    I = impact(factors["I2"]["value"], factors["I3"]["value"])  # noqa: E741, N806
    return band(L, I)


def sensitivity(rows: list[sqlite3.Row], delta: float = 0.2) -> dict[str, float]:
    """% of incidents whose band changes when each factor moves ±delta (clipped to [0, 9]); None is skipped."""
    counts = {k: 0 for k in FACTORS}
    n = 0
    for row in rows:
        factors = _parsed(row)
        base = recompute(factors)
        n += 1
        for k in FACTORS:
            value = factors.get(k, {}).get("value")
            if value is None:
                continue
            changed = False
            for scale in (1 - delta, 1 + delta):
                perturbed = copy.deepcopy(factors)
                perturbed[k]["value"] = min(9.0, max(0.0, value * scale))
                changed = changed or recompute(perturbed) != base
            counts[k] += int(changed)
    return {k: 100 * counts[k] / n if n else 0.0 for k in FACTORS}


def _histogram(bands: list[str]) -> dict[str, int]:
    out = {b: 0 for b in BANDS}
    for b in bands:
        if b in out:
            out[b] += 1
    return out


def ablation(rows: list[sqlite3.Row]) -> dict[str, dict[str, int]]:
    """Band histogram per factor ablated (L set None, I2 4, I3 4) plus the baseline over stored values."""
    result = {"baseline": _histogram([recompute(_parsed(r)) for r in rows])}
    for k in FACTORS:
        bands = []
        for row in rows:
            factors = copy.deepcopy(_parsed(row))
            factors[k]["value"] = None if k.startswith("L") else _NEUTRAL[k]
            bands.append(recompute(factors))
        result[k] = _histogram(bands)
    return result


def _average_ranks(values: list[float]) -> list[float]:
    """1-based average rank per value; tied values share the mean of their positions."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i, n = 0, len(values)
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(a: list[float], b: list[float]) -> float:
    """Spearman rank correlation with average ranks for ties (stdlib only)."""
    if len(a) != len(b) or len(a) < 2:
        return 0.0
    ra, rb = _average_ranks(list(a)), _average_ranks(list(b))
    n = len(ra)
    ma, mb = sum(ra) / n, sum(rb) / n
    cov = sum((x - ma) * (y - mb) for x, y in zip(ra, rb))
    va = sum((x - ma) ** 2 for x in ra)
    vb = sum((y - mb) ** 2 for y in rb)
    return cov / (va * vb) ** 0.5 if va and vb else 0.0


def _netseer_ranks(rows: list[sqlite3.Row]) -> dict[int, float]:
    """NetSeer rank per incident id (1 = most urgent): band in BANDS order, then score descending."""
    scored = sorted((r for r in rows if r["band"] in BANDS and r["score"] is not None),
                    key=lambda r: (BANDS.index(r["band"]), -r["score"]))
    ranks: dict[int, float] = {}
    i, n = 0, len(scored)
    while i < n:
        j = i
        key = (scored[i]["band"], scored[i]["score"])
        while j + 1 < n and (scored[j + 1]["band"], scored[j + 1]["score"]) == key:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[scored[k]["id"]] = avg
        i = j + 1
    return ranks


def main(argv: list[str] | None = None) -> int:
    """Print sensitivity, ablation and (with --expert) the Spearman agreement as plain-text tables."""
    parser = argparse.ArgumentParser(prog="risk_eval")
    parser.add_argument("analysis_id", type=int)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--expert", type=Path, help="expert ranks CSV (incident_id, expert_rank)")
    args = parser.parse_args(argv)
    conn = db.connect(args.db)
    try:
        rows = conn.execute("SELECT * FROM incidents WHERE analysis_id = ?", (args.analysis_id,)).fetchall()
    finally:
        conn.close()

    print("Sensitivity (% of incidents whose band changes when the factor moves ±20%):")
    for k, pct in sensitivity(rows).items():
        print(f"  {k:<3} {pct:5.1f}%")

    ablation_table = ablation(rows)
    width = max(len(name) for name in ablation_table)
    header = " " * (width + 2) + "".join(f"{b:>10}" for b in BANDS)
    print("\nAblation (band counts with the factor removed / neutralised):")
    print(header)
    for name, hist in ablation_table.items():
        print(f"  {name:<{width}}" + "".join(f"{hist[b]:>10}" for b in BANDS))

    if args.expert:
        with open(args.expert, newline="", encoding="utf-8", errors="replace") as fh:
            expert = {int(r["incident_id"]): float(r["expert_rank"]) for r in csv.DictReader(fh)}
        ranks = _netseer_ranks(rows)
        netseer_order, expert_order = [], []
        for iid, erank in expert.items():
            if iid in ranks:
                netseer_order.append(ranks[iid])
                expert_order.append(erank)
        rho = spearman(netseer_order, expert_order)
        print(f"\nSpearman vs expert ranks (n={len(netseer_order)}): {rho:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
