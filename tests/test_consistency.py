from __future__ import annotations
def test_drill_success_and_failure_are_explained(bundle):
    drills = {item.drill_id: item for item in bundle.drills}
    assert drills["drill-orders-0915"].status == "success"
    assert drills["drill-events-0914"].status == "success"
    failed = drills["drill-orders-1106"]
    assert failed.status == "failed"
    assert failed.missing_steps == ("publish_report",)
    assert failed.failed_steps == ("verify_checksum",)
    assert not failed.evidence_ok
    ledger = drills["drill-ledger-0908"]
    assert ledger.missing_steps == ("verify_checksum",)
    assert ledger.skipped_steps == ("publish_report",)
    assert ledger.failed_steps == ("restore_base",)
def test_consistency_findings_have_expected_and_actual(bundle):
    rules = {item.rule_id: item for item in bundle.findings if item.object_id == "drill-orders-1106"}
    assert rules["CONS-001"].evidence["expected"] == 12000
    assert rules["CONS-001"].evidence["actual"] == 11990
    assert rules["CONS-002"].evidence["actual"] == "0" * 64
    assert rules["CONS-004"].severity == "medium"
    assert "EVID-004" in rules and "EVID-005" in rules
def test_retry_and_unexpected_step_are_warnings_or_info(bundle):
    by_rule = {item.rule_id: item for item in bundle.findings}
    assert by_rule["EVID-007"].severity == "warning"
    assert by_rule["EVID-008"].severity == "info"
    assert by_rule["EVID-008"].object_id == "drill-orders-0915"
