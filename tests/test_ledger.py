from __future__ import annotations
import sqlite3
from pathlib import Path
from drillverify.ledger import get_actions, get_findings, get_run, list_runs, record_run
from drillverify.reporting import build_report
def _record(db: Path, bundle) -> int:
    return record_run(db, bundle, build_report(bundle))
def test_ledger_records_normalized_rows(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    first = _record(db, bundle)
    second = _record(db, bundle)
    assert first == 1 and second == 2
    runs = list_runs(db)
    assert [item["id"] for item in runs] == [2, 1]
    assert runs[0]["summary"] == bundle.summary
    assert get_run(db, first)["report"]["run_id"] == bundle.run_id
    assert get_run(db, 999) is None
def test_ledger_finding_filters_and_actions(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    run_pk = _record(db, bundle)
    findings = get_findings(db, run_pk)
    assert len(findings) == len(bundle.findings)
    critical = get_findings(db, run_pk, severity="critical")
    assert [item["rule_id"] for item in critical] == ["OBJ-POINT-001"]
    matched = get_findings(db, run_pk, query="bk-orders-030")
    assert matched
    assert all(
        "bk-orders-030" in item["object_id"]
        or item["evidence"].get("backup_id") == "bk-orders-030"
        for item in matched
    )
    actions = get_actions(db, run_pk)
    assert len(actions) == len(bundle.actions)
    assert actions[0]["action_id"] == bundle.actions[0].action_id
def test_ledger_tables_persist_input_hashes(bundle, tmp_path: Path):
    db = tmp_path / "ledger.sqlite3"
    run_pk = _record(db, bundle)
    connection = sqlite3.connect(db)
    try:
        count = connection.execute(
            "SELECT COUNT(*) FROM input_files WHERE run_pk = ?", (run_pk,)
        ).fetchone()[0]
        category = connection.execute(
            "SELECT category FROM findings WHERE run_pk = ? AND rule_id = 'CHAIN-001'",
            (run_pk,),
        ).fetchone()[0]
    finally:
        connection.close()
    assert count == len(bundle.inputs)
    assert category == "chain_integrity"
def test_missing_ledger_is_explicit(tmp_path: Path):
    try:
        list_runs(tmp_path / "absent.sqlite3")
    except FileNotFoundError as exc:
        assert "ledger not found" in str(exc)
    else:
        raise AssertionError("missing ledger must not create a database")
