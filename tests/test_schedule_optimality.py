"""Objective divergence and brute-force optimality checks for the scheduler."""

from __future__ import annotations

from datetime import timedelta
from itertools import product
from typing import Any

from drillverify.actions import OBJECTIVES
from drillverify.rules import is_high_risk
from drillverify.schedule_windows import allowed_start_slots
from drillverify.scheduler import build_schedule
from drillverify.timeutil import parse_utc
from tests.schedule_fixtures import action, dataset, plan, profiles


def _window_plan(*, capacity: int = 1, horizon_days: int = 14):
    # Two Saturday 03:00-05:00Z occurrences inside the horizon. The long high-risk
    # action fills one occurrence exactly, so the short action is pushed to the
    # next occurrence when the high-risk action goes first.
    return plan(
        (dataset("ds-a", "team-a", "sat:03:00-05:00Z"),),
        capacities={"team-a": capacity},
        profiles_value=profiles(
            chain_integrity=(120, 90),  # long, high maintenance impact
            input_quality=(30, 0),  # short, near-zero impact
        ),
        horizon_days=horizon_days,
    )


def _divergent_actions():
    return [
        action(
            "high-long",
            category="chain_integrity",
            priority="high",
            due_at="2026-11-20",
        ),
        action(
            "low-short",
            category="input_quality",
            priority="medium",
            due_at="2026-11-20",
        ),
    ]


def test_objectives_diverge_on_execution_window_and_overdue():
    """One 2-hour occurrence, capacity 1: the two objectives pick different actions."""
    plan_value = plan(
        (dataset("ds-a", "team-a", "wed:01:00-03:00Z"),),
        capacities={"team-a": 1},
        profiles_value=profiles(chain_integrity=(120, 90), input_quality=(30, 0)),
        horizon_days=7,
    )
    result = build_schedule(plan_value, tuple(_divergent_actions()))
    high = result.outcome_for(OBJECTIVES[0])
    low = result.outcome_for(OBJECTIVES[1])

    high_windows = {item.action_id: (item.start_at, item.end_at) for item in high.scheduled}
    low_windows = {item.action_id: (item.start_at, item.end_at) for item in low.scheduled}

    # High-risk objective: the long high-risk action gets the window, on time.
    assert high_windows == {"high-long": ("2026-11-11T01:00:00Z", "2026-11-11T03:00:00Z")}
    assert high.overdue_high_count == 0
    assert [item.action_id for item in high.unscheduled] == ["low-short"]

    # Impact objective: the short low-impact action gets the window instead.
    assert low_windows == {"low-short": ("2026-11-11T01:00:00Z", "2026-11-11T01:30:00Z")}
    assert low.total_impact_minutes == 0
    assert [item.action_id for item in low.unscheduled] == ["high-long"]
    # The overdue conclusion flips: leaving the high-risk action unplaced counts it.
    assert low.overdue_high_count == 1

    # Different actual execution window and different overdue conclusion.
    assert high_windows != low_windows
    assert low.overdue_high_count > high.overdue_high_count


def test_both_objectives_respect_the_same_capacity_and_window_constraints():
    plan_value = _window_plan()
    result = build_schedule(plan_value, tuple(_divergent_actions()))
    for outcome in result.outcomes:
        for item in outcome.scheduled:
            assert item.start_slot >= 0
            assert item.end_slot <= result.horizon_slots
            assert item.maintenance_window == "sat:03:00-05:00Z"
        intervals = [(item.start_slot, item.end_slot) for item in outcome.scheduled]
        for index, one in enumerate(intervals):
            for two in intervals[index + 1 :]:
                assert not (one[0] < two[1] and two[0] < one[1])


def test_each_objective_is_optimal_against_brute_force():
    plan_value = _window_plan()
    actions = _divergent_actions()
    result = build_schedule(plan_value, tuple(actions))
    for outcome in result.outcomes:
        assert outcome.optimal
        assert _score(outcome, outcome.objective) == _brute_force(
            plan_value, actions, outcome.objective
        )


def test_three_action_capacity_scenario_matches_brute_force():
    """A three-action, two-occurrence case where a greedy severity order loses."""
    plan_value = plan(
        (dataset("ds-a", "team-a", "sat:03:00-05:00Z"),),
        capacities={"team-a": 1},
        profiles_value=profiles(
            chain_integrity=(120, 90), artifact_integrity=(120, 10), input_quality=(30, 0)
        ),
        horizon_days=14,
    )
    actions = [
        action("huge", category="chain_integrity", priority="critical", due_at="2026-11-20"),
        action("cheap", category="artifact_integrity", priority="high", due_at="2026-11-20"),
        action("short", category="input_quality", priority="medium", due_at="2026-11-20"),
    ]
    result = build_schedule(plan_value, tuple(actions))
    for outcome in result.outcomes:
        assert outcome.optimal
        assert _score(outcome, outcome.objective) == _brute_force(
            plan_value, actions, outcome.objective
        )


def _candidates(plan_value, action_value) -> tuple[int, ...]:
    dataset_cfg = plan_value.dataset_map()[action_value.dataset_id]
    profile = plan_value.scheduling.profile_for(action_value.category)
    horizon_end = plan_value.as_of + timedelta(days=plan_value.scheduling.horizon_days)
    return allowed_start_slots(
        dataset_cfg.maintenance_window,
        plan_value.as_of,
        horizon_end,
        profile.duration_minutes,
        30,
    )


def _brute_force(plan_value, actions, objective) -> tuple[Any, ...]:
    """Enumerate all slot choices, including leaving each action unscheduled."""
    options = [tuple(_candidates(plan_value, item)) + (None,) for item in actions]
    best: tuple[Any, ...] | None = None
    for choice in product(*options):
        if not _legal(plan_value, actions, choice):
            continue
        score = _score_pair(plan_value, actions, choice, objective)
        if best is None or score < best:
            best = score
    assert best is not None
    return best


def _legal(plan_value, actions, choice) -> bool:
    config = plan_value.scheduling
    intervals = []
    for item, start in zip(actions, choice):
        if start is None:
            continue
        profile = config.profile_for(item.category)
        intervals.append((start, start + profile.duration_minutes // config.slot_minutes))
    for index, one in enumerate(intervals):
        for two in intervals[index + 1 :]:
            if one[0] < two[1] and two[0] < one[1]:
                return False
    return True


def _score_pair(plan_value, actions, choice, objective) -> tuple[Any, ...]:
    config = plan_value.scheduling
    missing = overdue_high = overdue_total = impact = 0
    for item, start in zip(actions, choice):
        if start is None:
            missing += 1
            overdue_total += 1
            overdue_high += 1 if is_high_risk(item.priority) else 0
            continue
        profile = config.profile_for(item.category)
        end = plan_value.as_of + timedelta(
            minutes=start * config.slot_minutes + profile.duration_minutes
        )
        due_end = parse_utc(f"{item.due_at}T00:00:00Z") + timedelta(days=1)
        if end > due_end:
            overdue_total += 1
            overdue_high += 1 if is_high_risk(item.priority) else 0
        impact += profile.impact_minutes
    if objective == OBJECTIVES[0]:
        return (overdue_high, missing, impact, overdue_total)
    return (missing, impact, overdue_high, overdue_total)


def _score(outcome, objective) -> tuple[Any, ...]:
    if objective == OBJECTIVES[0]:
        return (
            outcome.overdue_high_count,
            len(outcome.unscheduled),
            outcome.total_impact_minutes,
            outcome.overdue_total_count,
        )
    return (
        len(outcome.unscheduled),
        outcome.total_impact_minutes,
        outcome.overdue_high_count,
        outcome.overdue_total_count,
    )
