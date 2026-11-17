from __future__ import annotations
from drillverify.attribution import attribute
from drillverify.models import Finding
def test_attribution_categories_and_probes(bundle):
    assert bundle.attribution_summary["material_count"] == sum(
        1 for item in bundle.attribution if item.material
    )
    categories = set(bundle.attribution_summary["by_category"])
    assert {"chain_integrity", "artifact_integrity", "evidence_integrity", "data_consistency",
            "rpo_gap", "recoverability", "input_quality"} <= categories
    for item in bundle.attribution:
        assert item.rule_id.startswith(item.rule_id.split("-")[0])
        assert "file" in item.probe and "input_sha256" in item.probe
def test_attribution_is_sorted_by_severity_then_category():
    findings = (
        Finding("IN-006", "error", "backup", "b", "unknown dataset"),
        Finding("CHAIN-003", "critical", "backup", "a", "cycle"),
        Finding("EVID-007", "warning", "drill", "d", "retry"),
    )
    records, summary = attribute(findings)
    assert [item.rule_id for item in records] == ["CHAIN-003", "IN-006", "EVID-007"]
    assert summary["material_count"] == 2
    assert summary["by_severity"] == {"critical": 1, "error": 1, "warning": 1}
