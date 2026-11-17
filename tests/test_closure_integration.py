"""End-to-end closure review: pipeline, reports, ledger and web display."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from approval_helpers import base_book, digest, entry
from drillverify.closure_ledger import get_closure_review
from drillverify.ledger import record_run
from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report, render_html, render_markdown, write_reports
from drillverify.web import create_app


@pytest.fixture
def book_fixture(tmp_path: Path, fixtures_root: Path) -> tuple[Path, Path]:
    """Copy fixtures, then add a book for the first demo action."""
    import shutil

    root = tmp_path / "fixtures"
    shutil.copytree(fixtures_root, root)
    bundle = run_pipeline(root)
    target = next(item for item in bundle.actions if item.object_type == "backup"
                  and item.rule_ids)
    (root / "evidence" / "completion-e1.txt").write_text("restore verified\n", encoding="utf-8")
    raw = base_book(root, target)
    entry(raw)["completion"]["evidence_sha256"] = digest(
        root, "evidence/completion-e1.txt")
    entry(raw)["completion"]["evidence_path"] = "evidence/completion-e1.txt"
    entry(raw)["revision_summary"] = {
        "priority": target.priority, "rule_ids": list(target.rule_ids),
        "probes": list(target.probes), "source_inputs": list(target.source_inputs),
    }
    for item in entry(raw)["approvals"]:
        item["evidence_version"] = entry(raw)["completion"]["evidence_version"]
    path = tmp_path / "approval-book.json"
    path.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return root, path


def test_no_book_leaves_plan_and_recovery_results_unchanged(bundle):
    review = bundle.closures
    assert review["availability"] == "no_approval_book"
    assert review["summary"]["open"] == len(bundle.actions)
    assert review["summary"]["closed"] == 0
    assert all(item["status"] == "open" for item in review["decisions"])
    assert all(item["closure_claimed"] is False for item in review["decisions"])
    report = build_report(bundle)
    assert report["status"] == "fail"
    assert report["summary"] == bundle.summary
    markdown = render_markdown(report)
    assert "No approval book was supplied" in markdown
    assert "technical recovery is not asserted" in markdown or "process" in markdown


def test_book_review_changes_only_closure_section(book_fixture, bundle):
    root, path = book_fixture
    reviewed = run_pipeline(root, path)
    assert [item.to_dict() for item in reviewed.actions] == [
        item.to_dict() for item in bundle.actions]
    assert reviewed.summary == bundle.summary
    assert reviewed.status == bundle.status
    assert reviewed.closures["availability"] == "approval_book"
    closed = [item for item in reviewed.closures["decisions"] if item["status"] == "closed"]
    assert len(closed) == 1
    assert closed[0]["claims_recovery_success"] is False


def test_ledger_stores_and_serves_closure_decisions(book_fixture, tmp_path: Path):
    root, path = book_fixture
    reviewed = run_pipeline(root, path)
    db = tmp_path / "ledger.sqlite3"
    run_pk = record_run(db, reviewed, build_report(reviewed))
    review = get_closure_review(db, run_pk)
    assert review["availability"] == "approval_book"
    assert review["summary"]["closed"] == 1
    assert len(review["decisions"]) == len(reviewed.actions)
    stored = next(item for item in review["decisions"] if item["status"] == "closed")
    assert stored["evidence"]["path"] == "evidence/completion-e1.txt"
    assert {item["role"] for item in stored["approvers"]} == {
        "compliance", "independent_verifier"}


def test_old_ledger_reports_not_recorded(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    run_pk = record_run(db, bundle, build_report(bundle))
    import sqlite3

    connection = sqlite3.connect(db)
    try:
        connection.execute("DROP TABLE closure_decisions")
        connection.execute("DROP TABLE closure_reviews")
        connection.commit()
    finally:
        connection.close()
    review = get_closure_review(db, run_pk)
    assert review["availability"] == "not_recorded"
    assert review["decisions"] == []


def test_web_plan_shows_closure_states_and_identity_paths(book_fixture, tmp_path: Path):
    root, path = book_fixture
    reviewed = run_pipeline(root, path)
    db = tmp_path / "ledger.sqlite3"
    record_run(db, reviewed, build_report(reviewed))
    app = create_app(db)
    app.config.update(TESTING=True)
    client = app.test_client()
    page = client.get("/runs/1/plan")
    assert page.status_code == 200
    text = page.data.decode("utf-8")
    assert "Closure review" in text
    assert "process" in text and "does not" in text
    assert "closed" in text
    assert "person-bob" in text and "person-dave" in text
    assert "compliance approval" in text and "independent verification" in text
    assert "open" in text


def test_web_plan_without_book_still_renders_original_plan(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    record_run(db, bundle, build_report(bundle))
    app = create_app(db)
    app.config.update(TESTING=True)
    client = app.test_client()
    page = client.get("/runs/1/plan")
    text = page.data.decode("utf-8")
    assert page.status_code == 200
    assert "No approval book was supplied" in text
    for item in bundle.actions[:3]:
        assert item.action_id in text


def test_report_files_include_closure_review(book_fixture, tmp_path: Path):
    root, path = book_fixture
    reviewed = run_pipeline(root, path)
    outputs = write_reports(reviewed, tmp_path / "out")
    document = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert document["closure_review"]["summary"]["closed"] == 1
    assert document["remediation_plan"]["actions"]
    html = render_html(document)
    assert "Closure review" in html


def test_changed_source_finding_invalidates_prior_approval(book_fixture, tmp_path: Path):
    """A later run whose source finding or probe changed must not inherit approval."""
    import csv
    import shutil

    root, book_path = book_fixture
    first = run_pipeline(root, book_path)
    closed = next(item for item in first.closures["decisions"] if item["status"] == "closed")
    target = next(item for item in first.actions if item.action_id == closed["action_id"])

    mutated = tmp_path / "mutated"
    shutil.copytree(root, mutated)
    catalog = mutated / "catalog" / "backup_catalog.csv"
    with catalog.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        rows = list(reader)
    # Give the same object an extra material finding: a missing parent adds
    # CHAIN-001, which changes the action's rule set and probes.
    for row in rows:
        if row.get("backup_id") == target.object_id:
            row["parent_backup_id"] = "bk-absent-999"
            row["backup_type"] = "incremental"
    with catalog.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    second = run_pipeline(mutated, book_path)
    same = next((item for item in second.actions if item.action_id == target.action_id), None)
    if same is not None:
        assert same.revision != target.revision
        decision = next(item for item in second.closures["decisions"]
                        if item["action_id"] == target.action_id)
        assert decision["status"] != "closed"
        assert decision["revision_matches"] is False
        assert "action_revision_changed" in {item["code"] for item in decision["witness"]}


def test_cli_book_flag_and_summary(book_fixture, tmp_path: Path, capsys):
    from drillverify.cli import main

    root, path = book_fixture
    code = main(["demo", "--fixtures", str(root), "--book", str(path),
                 "--out", str(tmp_path / "out")])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["closure_review"]["availability"] == "approval_book"
    assert payload["closure_review"]["summary"]["closed"] == 1
    assert (tmp_path / "out" / "ledger.sqlite3").is_file()


def test_unreadable_book_is_reported_not_applied(bundle, tmp_path: Path):
    from drillverify.approvals_load import load_book_file

    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    book = load_book_file(path)
    assert book is not None and book.valid is False
    assert book.issues[0]["code"] == "book_unreadable"
    reviewed = run_pipeline(Path(__file__).resolve().parents[1] / "fixtures", path)
    assert reviewed.closures["availability"] == "invalid_approval_book"
    assert reviewed.closures["summary"]["closed"] == 0
    assert reviewed.summary == bundle.summary
    assert [item.to_dict() for item in reviewed.actions] == [
        item.to_dict() for item in bundle.actions]
