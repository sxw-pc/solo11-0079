"""Command-line entry points for offline runs, demos and the review console."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .ledger import record_run
from .pipeline import PipelineError, run_pipeline
from .reporting import build_report, write_reports
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drillverify",
        description="Offline restore-drill evidence verification bench",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "demo", "validate"):
        command = sub.add_parser(name)
        command.add_argument("--fixtures", type=Path, default=Path("fixtures"))
        if name != "validate":
            command.add_argument("--out", type=Path, default=Path("outputs"))
            command.add_argument("--strict", action="store_true")
        command.add_argument("--json", action="store_true", dest="as_json")
    serve = sub.add_parser("serve")
    serve.add_argument("--db", type=Path, default=Path("outputs/ledger.sqlite3"))
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=5000)
    return parser
def _print_fatal(findings: tuple) -> None:
    print("DrillVerify could not produce a run:", file=sys.stderr)
    for finding in findings:
        print(f"  {finding.rule_id} {finding.object_id}: {finding.message}", file=sys.stderr)
def _print_summary(bundle, outputs: dict[str, Path] | None, db_path: Path | None) -> None:
    payload = {
        "run_id": bundle.run_id,
        "as_of": bundle.plan.to_dict()["as_of"],
        "status": bundle.status,
        "summary": bundle.summary,
        "remediation_actions": len(bundle.actions),
        "outputs": {key: str(value) for key, value in sorted(outputs.items())} if outputs else {},
        "ledger": str(db_path) if db_path else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
def _run(args: argparse.Namespace) -> int:
    try:
        bundle = run_pipeline(args.fixtures)
    except PipelineError as exc:
        _print_fatal(exc.findings)
        return 2
    if args.command == "validate":
        payload = {
            "run_id": bundle.run_id,
            "status": bundle.status,
            "summary": bundle.summary,
            "findings": [item.to_dict() for item in bundle.findings],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    outputs = write_reports(bundle, args.out)
    db_path = args.out / "ledger.sqlite3"
    report = build_report(bundle)
    record_run(db_path, bundle, report)
    _print_summary(bundle, outputs, db_path)
    if args.strict and bundle.status == "fail":
        return 1
    return 0
def _serve(args: argparse.Namespace) -> int:
    from .web import serve, validate_bind_host
    try:
        validate_bind_host(args.host)
        serve(args.db, args.host, args.port)
    except (ValueError, FileNotFoundError) as exc:
        print(f"DrillVerify could not start: {exc}", file=sys.stderr)
        return 2
    return 0
def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    return _run(args)
