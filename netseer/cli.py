"""NetSeer command line.

Usage:
  python -m netseer.cli init-db
  python -m netseer.cli run-offline capture1.pcap [capture2.pcap ...]
  python -m netseer.cli acp <analysis_id | all>
  python -m netseer.cli build-kb
  python -m netseer.cli pregen <analysis_id> [--top 5] [--intent explain_simple]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from netseer.src.config import DATABASE_DIR, DEFAULT_DB_PATH, get_setting
from netseer.src.database import db
from netseer.src.engine import ingest
from netseer.src.engine.acp import run_acp


def cmd_init_db(args: argparse.Namespace) -> int:
    """Create the SQLite database and its tables."""
    db.init_db(args.db)
    print(f"Database ready: {args.db}")
    return 0


def cmd_run_offline(args: argparse.Namespace) -> int:
    """Create one offline analysis from the given captures and process it in the foreground."""
    db.init_db(args.db)
    conn = db.connect(args.db)
    try:
        max_bytes = int(get_setting(conn, "max_upload_mb")) * (1 << 20)
        with ExitStack() as stack:
            uploads = [(p.name, stack.enter_context(open(p, "rb"))) for p in args.pcaps]
            analysis_id = ingest.create_offline_analysis(conn, args.data, uploads, max_bytes)
        started = time.monotonic()
        ingest.run_offline(args.db, args.data, analysis_id)
        elapsed = time.monotonic() - started
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        n_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
    except ingest.IngestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    print(f"Analysis {analysis_id}: {row['name']}")
    print(f"  status {row['status']}, {row['n_events']} events, {row['n_alerts']} alerts, "
          f"{n_devices} devices, {elapsed:.1f} s")
    if row["error"]:
        print(f"  {'error: ' if row['status'] == 'failed' else ''}{row['error']}", file=sys.stderr)
    return 0 if row["status"] != "failed" else 1


def cmd_acp(args: argparse.Namespace) -> int:
    """Rebuild alert groups and possible incidents (ACP 3–6) for one analysis or all of them."""
    conn = db.connect(args.db)
    try:
        ids = ([r[0] for r in conn.execute("SELECT id FROM analyses ORDER BY id")] if args.analysis == "all"
               else [int(args.analysis)])
        for analysis_id in ids:
            n_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE analysis_id = ?", (analysis_id,)).fetchone()[0]
            stats = run_acp(conn, analysis_id)
            reduction = 100 * (1 - stats["incidents"] / n_alerts) if n_alerts else 0.0
            print(f"Analysis {analysis_id}: {n_alerts} alerts → {stats['groups']} groups → {stats['incidents']} "
                  f"possible incidents ({reduction:.1f}% reduction) in {stats['seconds']:.2f} s")
    finally:
        conn.close()
    return 0


def cmd_build_kb(args: argparse.Namespace) -> int:
    """Build the RAG knowledge base (rules, ATT&CK, classtypes, playbooks) into ai/kb/kb.db."""
    from netseer.ai.kb import build_kb

    started = time.monotonic()
    counts = build_kb.build()
    print(f"Knowledge base ready: {build_kb.KB_PATH} in {time.monotonic() - started:.1f} s")
    for table, n in counts.items():
        print(f"  {table}: {n}")
    return 0


def cmd_pregen(args: argparse.Namespace) -> int:
    """Pre-generate explanations for an analysis's top incidents (demo preparation)."""
    from netseer.ai import explain
    from netseer.ai.llm_caller import LLMError

    conn = db.connect(args.db)
    try:
        ids = [r[0] for r in conn.execute("SELECT id FROM incidents WHERE analysis_id = ? ORDER BY score DESC LIMIT ?",
                                          (args.analysis, args.top))]
        for incident_id in ids:
            try:
                row = conn.execute("SELECT * FROM interpretations WHERE id = ?",
                                   (explain.generate(conn, incident_id, args.intent),)).fetchone()
            except LLMError as exc:
                print(f"Incident {incident_id}: {exc}", file=sys.stderr)
                return 1
            flags = json.loads(row["verification_json"])["flags"]
            print(f"Incident {incident_id}: {row['latency_s']:.0f} s, "
                  + ("verified" if not flags else f"{len(flags)} flagged ({', '.join(f['check'] for f in flags)})"))
    finally:
        conn.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run a sub-command."""
    parser = argparse.ArgumentParser(prog="netseer")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="SQLite database path")
    parser.add_argument("--data", type=Path, default=DATABASE_DIR, help="directory holding pcaps/ and eves/")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create the database").set_defaults(func=cmd_init_db)
    run = sub.add_parser("run-offline", help="analyse one or more captures as one offline analysis")
    run.add_argument("pcaps", nargs="+", type=Path)
    run.set_defaults(func=cmd_run_offline)
    acp = sub.add_parser("acp", help="rebuild incidents and scores for an analysis (or 'all')")
    acp.add_argument("analysis")
    acp.set_defaults(func=cmd_acp)
    sub.add_parser("build-kb", help="build the RAG knowledge base").set_defaults(func=cmd_build_kb)
    pregen = sub.add_parser("pregen", help="pre-generate AI explanations for the top incidents")
    pregen.add_argument("analysis", type=int)
    pregen.add_argument("--top", type=int, default=5)
    pregen.add_argument("--intent", default="explain_simple")
    pregen.set_defaults(func=cmd_pregen)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
