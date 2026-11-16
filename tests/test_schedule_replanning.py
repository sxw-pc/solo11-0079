from __future__ import annotations

from dataclasses import replace

from drillverify.actions import OBJECTIVES
from drillverify.planner import build_plan
from drillverify.scheduler import build_schedule
from tests.schedule_fixtures import action, dataset, dependency, plan, profiles, selector


def _base_plan(*, capacity: int = 1, horizon_days: int = 7):
    return plan(
        (dataset("ds-a", "team-a", "wed:01:00-03:00Z"),),
        capacities={"team-a": capacity},
        profiles_value=profiles(
            chain_integrity=(60, 60),
            rpo_gap=(60, 30),
            evidence_integrity=(60, 30),
            artifact_integrity=(60, 90),
        ),
        horizon_days=horizon_days,
    )


def test_rpo_finding_changes_executable_window():
    """Adding an RPO action consumes the shared window and moves other actions."""
    plan_value = _base_plan()
    base = [
        action("chain", category="chain_integrity", due_at="2026-11-30"),
        action("artifact", category="artifact_integrity", due_at="2026-11-30"),
    ]
    without_rpo = build_schedule(plan_value, tuple(base)).outcome_for(OBJECTIVES[1])
    with_rpo = build_schedule(
        plan_value,
        tuple(base + [action("rpo", category="rpo_gap", due_at="2026-11-30")]),
    ).outcome_for(OBJECTIVES[1])
    windows_without = {
        item.action_id: (item.start_slot, item.end_slot) for item in without_rpo.scheduled
    }
    windows_with = {
        item.action_id: (item.start_slot, item.end_slot) for item in with_rpo.scheduled
    }
    assert windows_without != {k: v for k, v in windows_with.items() if k in windows_without}
    assert "rpo" in windows_with
    assert with_rpo.unscheduled


def test_rto_finding_and_dependency_change_unschedulable_conclusion():
    """A dependent replay changes state as its prerequisite appears or disappears."""
    plan_value = plan(
        (dataset("ds-a", "team-a", "wed:01:00-02:00Z"),),
        capacities={"team-a": 1},
        profiles_value=profiles(chain_integrity=(120, 90), evidence_integrity=(60, 30)),
        horizon_days=7,
        dependencies=(
            dependency(
                "ds-a",
                selector(category="chain_integrity"),
                selector(category="evidence_integrity"),
            ),
        ),
    )
    without_pre = [
        action("replay", category="evidence_integrity", due_at="2026-11-30"),
    ]
    result_without = build_schedule(plan_value, tuple(without_pre)).outcome_for(OBJECTIVES[0])
    assert result_without.unscheduled[0].reason == "dependency_missing"

    with_pre = [
        action("rebuild", category="chain_integrity", due_at="2026-11-30"),
        action("replay", category="evidence_integrity", due_at="2026-11-30"),
    ]
    result_with = build_schedule(plan_value, tuple(with_pre)).outcome_for(OBJECTIVES[0])
    reasons = {item.action_id: item.reason for item in result_with.unscheduled}
    # The 120-minute prerequisite cannot fit the 60-minute window, so the
    # dependent replay's unschedulable reason changes explicitly.
    assert reasons["rebuild"] == "no_window_slot_in_horizon"
    assert reasons["replay"] == "dependency_unschedulable"
    assert result_with.scheduled == ()


def test_planner_binds_schedule_to_stable_action_ids(bundle):
    schedule = bundle.schedule
    for outcome in schedule.outcomes:
        for item in outcome.scheduled:
            assert item.action_id in {entry.action_id for entry in bundle.actions}
        for item in outcome.unscheduled:
            assert item.action_id in {entry.action_id for entry in bundle.actions}


def test_replanning_with_changed_findings_is_deterministic():
    plan_value = _base_plan()
    actions = (
        action("b1", category="chain_integrity", due_at="2026-11-30"),
        action("a1", category="evidence_integrity", due_at="2026-11-30"),
    )
    first = build_schedule(plan_value, actions)
    second = build_schedule(plan_value, actions)
    assert first.to_dict() == second.to_dict()
    assert first.as_of == "2026-11-10T00:00:00Z"


def test_rpo_and_chain_findings_change_actions_and_schedule():
    """A new RPO objective finding grows the action set and changes placement."""
    from drillverify.models import Finding

    plan_value = plan(
        (dataset("ds-a", "team-a", "wed:01:00-02:00Z"),),
        capacities={"team-a": 1},
        profiles_value=profiles(
            chain_integrity=(60, 60), rpo_gap=(60, 30), artifact_integrity=(60, 90)
        ),
        horizon_days=7,
    )
    chain = Finding(
        "CHAIN-001", "high", "backup", "bk-a-1", "parent absent", "catalog.csv", 2
    )
    artifact = Finding(
        "ART-003", "high", "backup", "bk-a-1", "artifact missing", "catalog.csv", 2
    )
    base_actions, _ = build_plan(plan_value, (chain, artifact), (), ())
    rpo = Finding(
        "OBJ-RPO-001", "high", "dataset", "ds-a", "gap exceeds RPO", "catalog.csv", 0
    )
    with_rpo, _ = build_plan(plan_value, (chain, artifact, rpo), (), ())

    without = build_schedule(plan_value, base_actions).outcome_for(OBJECTIVES[1])
    after = build_schedule(plan_value, with_rpo).outcome_for(OBJECTIVES[1])

    # The RPO finding adds an action, so the executable set cannot be identical.
    assert {item.action_id for item in without.scheduled} != {
        item.action_id for item in after.scheduled
    }
    assert len(with_rpo) == len(base_actions) + 1
    assert after.unscheduled or len(after.scheduled) > len(without.scheduled)
