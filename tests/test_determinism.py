from __future__ import annotations

import json
from pathlib import Path

from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report, write_reports

ROOT = Path(__file__).resolve().parents[1]


def test_repeated_pipeline_is_byte_deterministic(fixtures_root: Path, bundle):
    repeated = run_pipeline(fixtures_root)
    assert repeated.run_id == bundle.run_id
    assert repeated.status == bundle.status
    assert [item.to_dict() for item in repeated.findings] == [
        item.to_dict() for item in bundle.findings
    ]
    assert [item.to_dict() for item in repeated.actions] == [
        item.to_dict() for item in bundle.actions
    ]
    assert repeated.schedule.to_dict() == bundle.schedule.to_dict()
    assert build_report(repeated) == build_report(bundle)


def test_repeated_reports_are_byte_identical(bundle, tmp_path: Path):
    first = write_reports(bundle, tmp_path / "first")
    second = write_reports(bundle, tmp_path / "second")
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()


def test_expected_demo_snapshots(fixtures_root: Path, bundle, report):
    expected = fixtures_root / "expected"
    summary = json.loads((expected / "demo_summary.json").read_text(encoding="utf-8"))
    findings = json.loads((expected / "demo_findings.json").read_text(encoding="utf-8"))
    actual_summary = {
        "run_id": report["run_id"],
        "status": report["status"],
        "summary": report["summary"],
        "datasets": [
            {"dataset_id": item["dataset_id"], "status": item["status"],
             "rpo_status": item["rpo"]["status"], "point_count": item["point_count"]}
            for item in report["datasets"]
        ],
        "actions": [
            {"action_id": item["action_id"], "priority": item["priority"],
             "rule_ids": item["rule_ids"], "object_id": item["object_id"]}
            for item in report["remediation_plan"]["actions"]
        ],
    }
    actual_findings = [
        {"rule_id": item["rule_id"], "severity": item["severity"],
         "object_type": item["object_type"], "object_id": item["object_id"]}
        for item in report["findings"]
    ]
    assert actual_summary == summary
    assert actual_findings == findings


def test_no_runtime_clock_is_used_in_source():
    offenders = []
    for path in (ROOT / "src" / "drillverify").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "datetime.now(" in text or "datetime.utcnow(" in text or "time.time(" in text:
            offenders.append(path.name)
    assert offenders == []
