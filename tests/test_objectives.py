from __future__ import annotations

from datetime import timedelta

from drillverify.objectives import evaluate_rpo
from drillverify.results import RestorablePoint


def test_rpo_breach_and_pass_are_classified(bundle):
    results = {item.dataset_id: item for item in bundle.rpo}
    assert results["ds-orders"].status == "breach"
    assert results["ds-orders"].max_gap_minutes == 710
    assert results["ds-events"].status == "pass"
    assert results["ds-ledger"].status == "no_points"
    assert results["ds-ledger"].point_count == 0


def test_rto_includes_failed_attempts(bundle):
    results = {item.drill_id: item for item in bundle.rto}
    assert results["drill-orders-0915"].duration_minutes == 58
    assert results["drill-orders-0915"].status == "pass"
    assert results["drill-orders-1106"].duration_minutes == 105
    assert results["drill-orders-1106"].status == "breach"
    assert results["drill-ledger-0908"].status == "not_met"
    assert not results["drill-ledger-0908"].successful


def test_rpo_boundary_is_inclusive_passing(bundle):
    dataset = next(item for item in bundle.plan.datasets if item.dataset_id == "ds-events")
    point = RestorablePoint(
        "ds-events",
        "bk-boundary-001",
        bundle.plan.as_of - timedelta(minutes=dataset.rpo_minutes),
        1,
        "a" * 64,
        "3",
    )
    results, findings = evaluate_rpo(bundle.plan, (point,), "catalog", "hash")
    event_result = next(item for item in results if item.dataset_id == "ds-events")
    assert event_result.status == "pass"
    assert not any(item.rule_id == "OBJ-RPO-001" and item.object_id == "ds-events" for item in findings)
