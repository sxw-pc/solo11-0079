from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from drillverify.ledger import list_run_records, list_runs
from drillverify.reporting import build_report, render_trend_markdown
from drillverify.trend import (analyze_ledger, analyze_runs, build_spec,
                               load_observations)
from drillverify.web import create_app

# Ten distinct 5-run subsets of runs r0..r9; the last is exactly the recent window.
SUBSETS = [
    (0, 6, 7, 8, 9), (1, 5, 7, 8, 9), (2, 5, 6, 8, 9), (3, 5, 6, 7, 9),
    (4, 5, 6, 7, 8), (1, 6, 7, 8, 9), (2, 6, 7, 8, 9), (3, 6, 7, 8, 9),
    (4, 6, 7, 8, 9), (5, 6, 7, 8, 9),
]
BASELINE = [f"r{index}" for index in range(5)]
RECENT = [f"r{index}" for index in range(5, 10)]
METRICS = [f"rule:R{index}" for index in range(10)]


def make_record(run_id, rules, ledger_id=0, backup=63, drill=4, scope="ds-a,ds-b",
                version="1", window=7, severity="high"):
    findings = [{"rule_id": rule, "severity": severity, "category": "chain_integrity"}
                for rule in rules]
    report = {
        "comparability": {"plan_dataset_scope": scope, "rule_version": version,
                          "analysis_window_days": window},
        "plan": {"datasets": [{"dataset_id": item} for item in scope.split(",")],
                 "analysis_window_days": window},
        "findings": findings,
    }
    return {"id": ledger_id or int(run_id[1:]) + 1, "run_id": run_id,
            "as_of": "2026-11-10T00:00:00Z", "status": "fail",
            "summary": {"backup_count": backup, "drill_count": drill}, "report": report}


def counterexample_records(**overrides):
    records = []
    for index, run_id in enumerate(BASELINE + RECENT):
        rules = [f"R{j}" for j, subset in enumerate(SUBSETS) if index in subset]
        records.append(make_record(run_id, rules, **overrides))
    return records


def duty(metrics=(METRICS[-1],), records=None, **kwargs):
    spec = build_spec("duty", metrics, BASELINE, RECENT, **kwargs)
    return analyze_runs(records or counterexample_records(), spec)


def overview(metrics=METRICS, records=None, **kwargs):
    spec = build_spec("overview", metrics, BASELINE, RECENT, **kwargs)
    return analyze_runs(records or counterexample_records(), spec)


def write_ledger(path: Path, records) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE runs (id INTEGER PRIMARY KEY, run_id TEXT, as_of TEXT, "
            "status TEXT, summary_json TEXT, report_json TEXT)")
        connection.executemany(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
            [(row["id"], row["run_id"], row["as_of"], row["status"],
              json.dumps(row["summary"]), json.dumps(row["report"])) for row in records])
        connection.commit()
    finally:
        connection.close()


def test_duty_alerts_on_one_preselected_rule():
    result = duty()
    assert result["status"] == "alert" and result["alert"] is True
    metric = result["metrics"][0]
    assert metric["metric"] == "rule:R9"
    assert (metric["at_least_observed"], metric["permutations"]) == (1, 252)
    assert metric["p_exact"] == "1/252" and metric["p_value"] == pytest.approx(1 / 252)
    assert result["decision"]["regime"] == "duty"


def test_overview_family_max_does_not_alert_on_same_runs():
    result = overview()
    assert result["status"] == "no_alert" and result["alert"] is False
    assert result["family"]["at_least_observed"] == 10
    assert result["family"]["permutations"] == 252
    assert result["family"]["p_exact"] == "10/252"
    assert result["family"]["p_value"] == pytest.approx(10 / 252)
    assert [item["metric"] for item in result["metrics"] if item["is_family_max"]] == ["rule:R9"]
    assert all(item["p_value"] > 0.01 for item in result["metrics"][:-1])
    assert result["decision"]["p_value"] == pytest.approx(10 / 252)
    assert result["decision"]["alert"] is False


def test_finding_rows_in_one_run_are_not_independent_observations():
    padded = counterexample_records()
    for record in padded:
        rules = [item["rule_id"] for item in record["report"]["findings"]]
        record["report"]["findings"] = [
            {"rule_id": rule, "severity": "high", "category": "chain_integrity"}
            for rule in rules for _ in range(10)]
    assert duty(records=padded)["metrics"][0]["p_value"] == pytest.approx(1 / 252)
    sample = duty(records=padded)["sample"]["comparable_run_ids"]
    assert len(sample) == 10


def test_duplicate_run_id_row_keeps_p_values_and_audit(tmp_path):
    records = counterexample_records()
    db = tmp_path / "ledger.sqlite3"
    write_ledger(db, records)
    baseline_duty = analyze_ledger(db, build_spec("duty", [METRICS[-1]], BASELINE, RECENT))
    baseline_overview = analyze_ledger(db, build_spec("overview", METRICS, BASELINE, RECENT))
    duplicate = dict(records[-1], id=99)
    connection = sqlite3.connect(db)
    try:
        connection.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
                           (99, duplicate["run_id"], duplicate["as_of"], duplicate["status"],
                            json.dumps(duplicate["summary"]), json.dumps(duplicate["report"])))
        connection.commit()
    finally:
        connection.close()
    assert len(list_runs(db)) == 11
    observations, duplicates = load_observations(db)
    assert len(observations) == 10 and duplicates[0]["run_id"] == "r9"
    duplicate_duty = analyze_ledger(db, build_spec("duty", [METRICS[-1]], BASELINE, RECENT))
    duplicate_overview = analyze_ledger(db, build_spec("overview", METRICS, BASELINE, RECENT))
    assert duplicate_duty["decision"]["p_value"] == baseline_duty["decision"]["p_value"]
    assert duplicate_overview["decision"]["p_value"] == baseline_overview["decision"]["p_value"]
    assert duplicate_overview["sample"]["duplicates"][0]["ledger_ids"] == [10, 99]
    assert len(duplicate_overview["sample"]["comparable_run_ids"]) == 10


def test_mixed_plan_scope_or_rule_version_is_unproven():
    records = counterexample_records()
    records[-1] = make_record(records[-1]["run_id"], ["R9"], scope="ds-a")
    result = duty(records=records)
    assert result["status"] == "unproven" and "mix plan dataset scope" in result["reason"]
    records = counterexample_records()
    records[-1] = make_record(records[-1]["run_id"], ["R9"], version="2")
    assert duty(records=records)["status"] == "unproven"


def test_exposure_is_matched_not_raw_finding_counts():
    records = counterexample_records()
    for record in records[5:]:
        record["summary"]["backup_count"] *= 2
        record["report"]["findings"] = record["report"]["findings"] * 2
    result = overview(records=records)
    assert result["status"] == "unproven"
    assert "no exposure layer contains both baseline and recent" in result["reason"]


def test_stratified_exposure_compares_within_matching_layer():
    records = counterexample_records()
    for index, record in enumerate(records):
        record["summary"]["backup_count"] = 63 if index < 8 else 64
    records[8] = make_record(records[8]["run_id"], ["R9"], backup=64)
    records[9] = make_record(records[9]["run_id"], [], backup=64)
    result = overview(records=records, metrics=["rule:R9", "rule:R8"])
    assert result["status"] != "unproven"
    assert result["sample"]["excluded"]
    assert {layer["backup_count"] for layer in result["strata"]} == {63}


def test_zero_events_gives_p_one_and_no_alert():
    records = [make_record(f"z{index}", []) for index in range(10)]
    spec = build_spec("overview", ["severity:high"], [f"z{i}" for i in range(5)],
                      [f"z{i}" for i in range(5, 10)])
    result = analyze_runs(records, spec)
    assert result["status"] == "no_alert"
    assert result["metrics"][0]["at_least_observed"] == 252
    assert result["metrics"][0]["p_value"] == 1
    assert result["family"]["p_value"] == 1


def test_tied_statistics_are_counted_once_per_permutation():
    records = counterexample_records()
    for record in records:
        rules = [item["rule_id"] for item in record["report"]["findings"]]
        if "R9" in rules:
            record["report"]["findings"].append(
                {"rule_id": "R10", "severity": "high", "category": "chain_integrity"})
    spec = build_spec("overview", ["rule:R9", "rule:R10"], BASELINE, RECENT)
    result = analyze_runs(records, spec)
    tied = [item for item in result["metrics"] if item["is_family_max"]]
    assert {item["metric"] for item in tied} == {"rule:R9", "rule:R10"}
    assert result["metrics"][0]["at_least_observed"] == result["metrics"][1]["at_least_observed"]
    assert result["family"]["at_least_observed"] == result["metrics"][0]["at_least_observed"]
    assert result["family"]["p_value"] == pytest.approx(1 / 252)


def test_budget_exceeded_returns_unproven():
    result = duty(max_permutations=100)
    assert result["status"] == "unproven"
    assert "exceeds budget" in result["reason"]
    assert result["permutation"]["enumerated"] == 0
    assert result["alert"] is False


def test_trend_markdown_states_assumptions_and_sample():
    text = render_trend_markdown(duty())
    assert "Trend Audit" in text and "Comparable sample" in text
    assert "Assumptions" in text and "not a compliance or recovery certification" in text


def test_report_keeps_legacy_shape_and_adds_comparability(bundle):
    report = build_report(bundle)
    for key in ("run_id", "summary", "findings", "datasets", "remediation_plan"):
        assert key in report
    assert report["summary"] == bundle.summary
    assert report["comparability"] == {
        "plan_dataset_scope": "ds-events,ds-ledger,ds-orders",
        "rule_version": "1", "analysis_window_days": 7,
    }


def test_trend_console_renders_declared_sample(tmp_path):
    records = counterexample_records()
    db = tmp_path / "ledger.sqlite3"
    write_ledger(db, records)
    app = create_app(db)
    app.config.update(TESTING=True)
    client = app.test_client()
    query = ("/trend?mode=duty&metrics=rule:R9&baseline=" + ",".join(BASELINE)
             + "&recent=" + ",".join(RECENT))
    response = client.get(query)
    assert response.status_code == 200
    assert b"alert" in response.data and b"Statistical assumptions" in response.data
    assert b"r9" in response.data and b"not a compliance or recovery certification" in response.data
    assert client.get("/trend?mode=duty&metrics=rule:R9&baseline=r0&recent=r6&alpha=abc").status_code == 400


def test_real_ledger_duplicate_row_changes_nothing(bundle, tmp_path):
    from dataclasses import replace

    db = tmp_path / "ledger.sqlite3"
    baseline = replace(bundle, run_id="base-run")
    recent = replace(bundle, run_id="recent-run")
    from drillverify.ledger import record_run
    record_run(db, baseline, build_report(baseline))
    record_run(db, baseline, build_report(baseline))
    record_run(db, recent, build_report(recent))
    spec = build_spec("overview", ["severity:high", "rule:CHAIN-001"],
                      ["base-run"], ["recent-run"])
    with_duplicate = analyze_ledger(db, spec)
    observations, duplicates = load_observations(db)
    assert len(observations) == 2 and duplicates[0]["ledger_ids"] == [1, 2]
    assert [row["id"] for row in list_runs(db)] == [3, 2, 1]
    assert [row["id"] for row in list_run_records(db)] == [1, 2, 3]
    connection = sqlite3.connect(db)
    try:
        connection.execute("DELETE FROM runs WHERE id = 2")
        connection.commit()
    finally:
        connection.close()
    without_duplicate = analyze_ledger(db, spec)
    assert with_duplicate["decision"]["p_value"] == without_duplicate["decision"]["p_value"]
    assert with_duplicate["family"]["p_value"] == without_duplicate["family"]["p_value"]
    assert with_duplicate["sample"]["comparable_run_ids"] == ["base-run", "recent-run"]


def test_conflicting_duplicate_run_id_is_unproven(tmp_path):
    records = counterexample_records()
    conflicting = make_record("r9", ["R0"], ledger_id=50)
    write_ledger(tmp_path / "ledger.sqlite3", records)
    connection = sqlite3.connect(tmp_path / "ledger.sqlite3")
    try:
        connection.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?)",
                           (50, conflicting["run_id"], conflicting["as_of"],
                            conflicting["status"], json.dumps(conflicting["summary"]),
                            json.dumps(conflicting["report"])))
        connection.commit()
    finally:
        connection.close()
    result = analyze_ledger(tmp_path / "ledger.sqlite3",
                            build_spec("duty", ["rule:R9"], BASELINE, RECENT))
    assert result["status"] == "unproven"
    assert "missing or conflicting" in result["reason"]
    assert result["sample"]["duplicates"][0]["resolution"].startswith("conflicting")


def test_declared_metric_must_be_preregistered():
    assert duty(metrics=("severity:info",))["metrics"][0]["at_least_observed"] == 252
    records = counterexample_records()
    for spec_mode in ("duty",):
        invalid = analyze_runs(records, build_spec(spec_mode, ["rule:R9", "rule:R0"],
                                                  BASELINE, RECENT))
        assert invalid["status"] == "unproven" and "exactly one" in invalid["reason"]


def test_trend_console_tolerates_absent_ledger(tmp_path):
    app = create_app(tmp_path / "absent.sqlite3")
    app.config.update(TESTING=True)
    response = app.test_client().get("/trend")
    assert response.status_code == 200
    assert b"No ledger found" in response.data
