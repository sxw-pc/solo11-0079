from __future__ import annotations

from datetime import datetime

from drillverify.actions import OBJECTIVES
from drillverify.scheduler import build_schedule
from tests.schedule_fixtures import (
    AS_OF,
    action,
    dataset,
    dependency,
    plan,
    profiles,
    selector,
)

import pytest


def _schedule(plan_value, actions):
    return build_schedule(plan_value, tuple(actions))


def test_actions_land_inside_their_own_maintenance_window():
    plan_value = plan((dataset("ds-a", "team-a", "wed:01:00-03:00Z"),))
    result = _schedule(plan_value, [action("a1"), action("a2")])
    assert result.selected.scheduled
    for item in result.selected.scheduled:
        start = datetime.fromisoformat(item.start_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(item.end_at.replace("Z", "+00:00"))
        assert start.weekday() == 2  # Wednesday
        assert start.hour >= 1 and end <= start.replace(hour=3, minute=0, second=0)
        assert item.maintenance_window == "wed:01:00-03:00Z"
        assert item.dataset_id == "ds-a"


def test_team_capacity_is_never_exceeded():
    plan_value = plan(
        (dataset("ds-a", "team-a"), dataset("ds-b", "team-a")),
        capacities={"team-a": 1},
    )
    actions = [
        action("a1", dataset_id="ds-a", team="team-a"),
        action("a2", dataset_id="ds-b", team="team-a"),
    ]
    result = _schedule(plan_value, actions)
    occupied: dict[int, int] = {}
    for item in result.selected.scheduled:
        for slot in range(item.start_slot, item.end_slot):
            occupied[slot] = occupied.get(slot, 0) + 1
    assert occupied and max(occupied.values()) <= 1


def test_action_over_the_horizon_is_unplanable_not_truncated():
    plan_value = plan((dataset("ds-a", "team-a", "mon:01:00-02:00Z"),), horizon_days=1)
    result = _schedule(plan_value, [action("a1")])
    assert result.fully_scheduled is False
    assert result.selected.scheduled == ()
    assert result.selected.unscheduled[0].reason == "no_window_slot_in_horizon"


def test_action_batches_above_the_limit_are_rejected_whole():
    plan_value = plan((dataset("ds-a", "team-a"),), action_limit=2)
    actions = [action(f"a{index}") for index in range(3)]
    result = _schedule(plan_value, actions)
    assert result.planable is False
    assert result.planable_reason == "action_limit_exceeded"
    assert all(item.reason == "action_limit_exceeded" for item in result.selected.unscheduled)
    assert len(result.selected.unscheduled) == 3


def test_explicit_dependency_orders_execution():
    plan_value = plan(
        (dataset("ds-a", "team-a"),),
        dependencies=(
            dependency(
                "ds-a",
                selector(category="artifact_integrity"),
                selector(category="evidence_integrity"),
            ),
        ),
    )
    actions = [
        action("artifact", category="artifact_integrity", due_at="2026-11-30"),
        action("replay", category="evidence_integrity", due_at="2026-11-30"),
    ]
    result = _schedule(plan_value, actions)
    by_id = {item.action_id: item for item in result.selected.scheduled}
    assert by_id["artifact"].end_slot <= by_id["replay"].start_slot
    assert "artifact" in by_id["replay"].dependency_ids


def test_dependency_cycle_is_reported_not_ignored():
    plan_value = plan(
        (dataset("ds-a", "team-a"),),
        dependencies=(
            dependency("ds-a", selector(action_id="x"), selector(action_id="y")),
            dependency("ds-a", selector(action_id="y"), selector(action_id="x")),
        ),
    )
    result = _schedule(plan_value, [action("x"), action("y")])
    assert {item.reason for item in result.selected.unscheduled} == {"dependency_cycle"}
    assert result.selected.scheduled == ()


def test_missing_prerequisite_is_explicit():
    plan_value = plan(
        (dataset("ds-a", "team-a"),),
        dependencies=(
            dependency("ds-a", selector(action_id="absent"), selector(action_id="y")),
        ),
    )
    result = _schedule(plan_value, [action("y")])
    assert result.selected.unscheduled[0].reason == "dependency_missing"


def test_actions_are_never_merged_across_datasets():
    plan_value = plan(
        (dataset("ds-a", "team-a"), dataset("ds-b", "team-b")),
        capacities={"team-a": 2, "team-b": 2},
    )
    actions = [
        action("a1", dataset_id="ds-a", team="team-a"),
        action("b1", dataset_id="ds-b", team="team-b"),
    ]
    result = _schedule(plan_value, actions)
    pairs = {(item.action_id, item.dataset_id) for item in result.selected.scheduled}
    assert pairs == {("a1", "ds-a"), ("b1", "ds-b")}


def test_objectives_use_identical_hard_constraints():
    plan_value = plan((dataset("ds-a", "team-a"),), capacities={"team-a": 1})
    actions = [action(f"a{index}") for index in range(3)]
    result = _schedule(plan_value, actions)
    assert result.objectives == OBJECTIVES
    for outcome in result.outcomes:
        starts = [item.start_slot for item in outcome.scheduled]
        assert len(starts) == len(set(starts))
        assert all(item.start_slot >= 0 for item in outcome.scheduled)


def test_unschedulable_reason_reports_team_capacity_conflict():
    plan_value = plan(
        (dataset("ds-a", "team-a", "wed:01:00-02:00Z"),),
        capacities={"team-a": 1},
        horizon_days=7,
    )
    actions = [action(f"a{index}", due_at="2026-11-30") for index in range(4)]
    result = _schedule(plan_value, actions)
    outcomes = {item.objective: item for item in result.outcomes}
    scheduled = outcomes["min_impact"].scheduled
    # The only Wednesday occurrence in this horizon fits one 60-minute action.
    assert len(scheduled) == 1
    assert outcomes["min_impact"].unscheduled
    assert {item.reason for item in outcomes["min_impact"].unscheduled} == {"capacity_conflict"}


def test_schedule_is_deterministic_for_same_inputs_and_as_of():
    plan_value = plan((dataset("ds-a", "team-a"),))
    actions = [action("a1"), action("a2"), action("a3")]
    first = build_schedule(plan_value, tuple(actions))
    second = build_schedule(plan_value, tuple(actions))
    assert first.to_dict() == second.to_dict()
    assert plan_value.as_of == AS_OF


def test_missing_scheduling_policy_is_explicit():
    plan_value = plan((dataset(),))
    from dataclasses import replace

    plan_value = replace(plan_value, scheduling=None)
    result = _schedule(plan_value, [action("a1")])
    assert result.planable is False
    assert result.planable_reason == "scheduling_not_declared"
    assert result.unschedulable_actions
