from __future__ import annotations

import json
from pathlib import Path

from drillverify.reporting import render_markdown, write_reports


def test_all_report_formats_are_written(bundle, tmp_path: Path):
    outputs = write_reports(bundle, tmp_path)
    assert set(outputs) == {"json", "markdown", "html", "plan", "manifest"}
    assert all(path.is_file() for path in outputs.values())
    document = json.loads(outputs["json"].read_text(encoding="utf-8"))
    assert document["generated_at"] == document["as_of"] == "2026-11-10T00:00:00Z"
    assert document["run_id"] == bundle.run_id
    assert document["summary"]["overall_status"] == "fail"
    assert document["input_manifest"]
    assert document["remediation_plan"]["actions"]
    schedule = document["remediation_plan"]["schedule"]
    assert schedule["slot_minutes"] == 30
    assert schedule["objectives"]
    plan_file = json.loads(outputs["plan"].read_text(encoding="utf-8"))
    assert plan_file["schedule"] == schedule


def test_markdown_reports_overdue_and_unscheduled(bundle):
    from drillverify.reporting import build_report

    text = render_markdown(build_report(bundle))
    assert "## Remediation Schedule" in text
    assert "Overdue high-risk actions" in text
    assert "Unscheduled actions:" in text
    schedule = build_report(bundle)["remediation_plan"]["schedule"]
    for outcome in schedule["objectives"]:
        assert f"Objective `{outcome['objective']}`" in text
        for item in outcome["unscheduled"]:
            assert item["action_id"] in text


def test_html_is_self_contained(report):
    from drillverify.reporting import render_html

    html = render_html(report)
    assert "<!doctype html>" in html
    assert "<style>" in html
    assert "http://" not in html and "https://" not in html
    assert "cdn." not in html.lower()
    assert "<script" not in html.lower()
    assert "drill-orders-1106" in html


def test_markdown_is_stable_and_complete(report):
    first = render_markdown(report)
    second = render_markdown(build_report_copy(report))
    assert first == second
    assert "# DrillVerify Verification Report" in first
    assert "## Remediation Plan" in first
    assert "## Input Manifest" in first


def build_report_copy(report):
    return json.loads(json.dumps(report, sort_keys=True))
