"""Read-only local review console. No write route and no remote bind by default."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask, abort, render_template, request

from .ledger import get_actions, get_findings, get_run, list_runs

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def validate_bind_host(host: str) -> str:
    """Reject any address other than explicit loopback aliases."""
    if host not in ALLOWED_HOSTS:
        raise ValueError(
            "refusing to bind DrillVerify outside loopback; "
            f"allowed hosts: {', '.join(sorted(ALLOWED_HOSTS))}"
        )
    return host


def _run_or_404(db_path: Path, run_pk: int) -> dict[str, Any]:
    run = get_run(db_path, run_pk)
    if run is None:
        abort(404)
    return run


def create_app(db_path: Path) -> Flask:
    """Build the local review app around an existing SQLite ledger."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.update(
        DB_PATH=str(db_path.resolve()),
        READ_ONLY=True,
        JSON_SORT_KEYS=True,
    )

    @app.before_request
    def enforce_read_only() -> None:
        if request.method not in READ_METHODS:
            abort(405)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "read_only": True}

    @app.get("/")
    def index() -> str:
        try:
            runs = list_runs(db_path)
        except FileNotFoundError:
            runs = []
        return render_template("index.html", runs=runs)

    @app.get("/runs/<int:run_pk>")
    def run_detail(run_pk: int) -> str:
        run = _run_or_404(db_path, run_pk)
        report = run["report"]
        return render_template("run_detail.html", run=run, report=report)

    @app.get("/runs/<int:run_pk>/datasets/<dataset_id>")
    def dataset_detail(run_pk: int, dataset_id: str) -> str:
        run = _run_or_404(db_path, run_pk)
        report = run["report"]
        dataset = next(
            (item for item in report.get("datasets", []) if item["dataset_id"] == dataset_id),
            None,
        )
        if dataset is None:
            abort(404)
        chains = [item for item in report.get("chains", []) if item["dataset_id"] == dataset_id]
        points = [
            item
            for item in report.get("restorable_points", [])
            if item["dataset_id"] == dataset_id
        ]
        drills = [item for item in report.get("drills", []) if item["dataset_id"] == dataset_id]
        backup_ids = {item["backup_id"] for item in chains}
        drill_ids = {item["drill_id"] for item in drills}
        findings = [
            item
            for item in report.get("findings", [])
            if item["object_id"] == dataset_id
            or item["object_id"] in backup_ids
            or item["object_id"] in drill_ids
        ]
        return render_template(
            "dataset_detail.html",
            run=run,
            report=report,
            dataset=dataset,
            chains=chains,
            points=points,
            drills=drills,
            findings=findings,
        )

    @app.get("/runs/<int:run_pk>/findings")
    def findings(run_pk: int) -> str:
        run = _run_or_404(db_path, run_pk)
        severity = request.args.get("severity", "").strip()[:20] or None
        query = request.args.get("q", "").strip()[:120] or None
        rows = get_findings(db_path, run_pk, severity=severity, query=query)
        return render_template(
            "findings.html",
            run=run,
            report=run["report"],
            findings=rows,
            selected_severity=severity or "",
            query=query or "",
        )

    @app.get("/runs/<int:run_pk>/plan")
    def plan(run_pk: int) -> str:
        run = _run_or_404(db_path, run_pk)
        actions = get_actions(db_path, run_pk)
        return render_template(
            "plan.html",
            run=run,
            report=run["report"],
            actions=actions,
        )

    @app.errorhandler(404)
    def not_found(error: Exception) -> tuple[str, int]:
        return render_template("not_found.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error: Exception) -> tuple[str, int]:
        return "Read-only console: method not allowed.\n", 405

    return app


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 5000) -> None:
    """Run the review console with the Werkzeug development server, loopback only."""
    host = validate_bind_host(host)
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not db_path.is_file():
        raise FileNotFoundError(f"ledger not found: {db_path}; run `make demo` first")
    app = create_app(db_path)
    app.run(host=host, port=port, debug=False, use_reloader=False)
