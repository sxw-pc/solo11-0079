"""Strict parsing of the plan's remediation-scheduling declaration."""

from __future__ import annotations

import re
from typing import Any, Callable

from .actions import MAX_HORIZON_DAYS, MAX_SCHEDULE_ACTIONS, OBJECTIVES, SLOT_MINUTES
from .models import (
    SELECTOR_FIELDS,
    ActionProfile,
    ActionSelector,
    DependencyRule,
    SchedulingConfig,
    TeamCapacity,
)
from .rules import REMEDIATION

_TEAM_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_MAX_CAPACITY = 16
_MAX_DURATION = 24 * 60

Issue = Callable[[str, str], None]


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_selector(raw: object, prefix: str, issue: Issue) -> ActionSelector | None:
    if not isinstance(raw, dict) or not raw:
        issue(prefix, f"{prefix} must be a non-empty mapping.")
        return None
    unknown = sorted(set(raw) - set(SELECTOR_FIELDS))
    if unknown:
        issue(prefix, f"{prefix} has unknown fields: {', '.join(unknown)}.")
        return None
    pairs: list[tuple[str, str]] = []
    for key in SELECTOR_FIELDS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, str) or not value.strip():
            issue(prefix, f"{prefix}.{key} must be a non-empty string.")
            return None
        pairs.append((key, value.strip()))
    return ActionSelector(tuple(pairs))


def _parse_capacities(raw: object, teams: set[str], issue: Issue) -> tuple[TeamCapacity, ...] | None:
    if not isinstance(raw, dict) or not raw:
        issue("scheduling.team_capacities", "team_capacities must be a non-empty mapping.")
        return None
    parsed: list[TeamCapacity] = []
    for team in sorted(raw):
        if not isinstance(team, str) or not _TEAM_RE.fullmatch(team):
            issue("scheduling.team_capacities", f"Invalid team name: {team!r}.")
            return None
        capacity = raw[team]
        if not _is_int(capacity) or not 1 <= capacity <= _MAX_CAPACITY:
            issue(
                "scheduling.team_capacities",
                f"Capacity for {team} must be an integer from 1 to {_MAX_CAPACITY}.",
            )
            return None
        parsed.append(TeamCapacity(team, capacity))
    missing = sorted(teams - set(raw))
    if missing:
        issue(
            "scheduling.team_capacities",
            f"No per-slot capacity declared for owner teams: {', '.join(missing)}.",
        )
        return None
    return tuple(parsed)


def _parse_profiles(raw: object, issue: Issue) -> tuple[ActionProfile, ...] | None:
    if not isinstance(raw, dict) or not raw:
        issue("scheduling.action_profiles", "action_profiles must be a non-empty mapping.")
        return None
    parsed: list[ActionProfile] = []
    for category in sorted(raw):
        if not isinstance(category, str) or not _CATEGORY_RE.fullmatch(category):
            issue("scheduling.action_profiles", f"Invalid category name: {category!r}.")
            return None
        if category not in REMEDIATION:
            issue("scheduling.action_profiles", f"Unknown remediation category: {category}.")
            return None
        body = raw[category]
        if not isinstance(body, dict):
            issue("scheduling.action_profiles", f"Profile for {category} must be a mapping.")
            return None
        unknown = sorted(set(body) - {"duration_minutes", "impact_minutes"})
        if unknown:
            issue("scheduling.action_profiles", f"Profile for {category} has unknown fields: {', '.join(unknown)}.")
            return None
        duration = body.get("duration_minutes")
        impact = body.get("impact_minutes")
        if not _is_int(duration) or not 1 <= duration <= _MAX_DURATION:
            issue("scheduling.action_profiles", f"duration_minutes for {category} is invalid.")
            return None
        if not _is_int(impact) or not 0 <= impact <= _MAX_DURATION:
            issue("scheduling.action_profiles", f"impact_minutes for {category} is invalid.")
            return None
        parsed.append(ActionProfile(category, duration, impact))
    missing = sorted(set(REMEDIATION) - set(raw))
    if missing:
        issue(
            "scheduling.action_profiles",
            f"No duration declared for categories: {', '.join(missing)}.",
        )
        return None
    return tuple(parsed)


def _parse_dependency(
    raw: object, prefix: str, teams: set[str], issue: Issue
) -> DependencyRule | None:
    if not isinstance(raw, dict):
        issue(prefix, f"{prefix} must be a mapping.")
        return None
    missing = [key for key in ("dataset_id", "prerequisite", "dependent") if key not in raw]
    if missing:
        issue(prefix, f"{prefix} misses fields: {', '.join(missing)}.")
        return None
    unknown = sorted(set(raw) - {"dataset_id", "prerequisite", "dependent"})
    if unknown:
        issue(prefix, f"{prefix} has unknown fields: {', '.join(unknown)}.")
        return None
    dataset_id = raw["dataset_id"]
    if not isinstance(dataset_id, str) or not dataset_id.strip():
        issue(prefix, f"{prefix}.dataset_id must be a non-empty string.")
        return None
    prerequisite = _parse_selector(raw["prerequisite"], f"{prefix}.prerequisite", issue)
    dependent = _parse_selector(raw["dependent"], f"{prefix}.dependent", issue)
    if prerequisite is None or dependent is None:
        return None
    return DependencyRule(dataset_id.strip(), prerequisite, dependent)


def parse_scheduling(
    raw: object, teams: set[str], issue: Issue
) -> SchedulingConfig | None:
    """Parse and validate the optional ``scheduling`` block; None on any issue."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        issue("scheduling", "scheduling must be a mapping.")
        return None
    allowed = {
        "slot_minutes",
        "horizon_days",
        "action_limit",
        "objectives",
        "default_objective",
        "team_capacities",
        "action_profiles",
        "dependencies",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        issue("scheduling", f"scheduling has unknown fields: {', '.join(unknown)}.")
        return None
    slot = raw.get("slot_minutes", SLOT_MINUTES)
    if not _is_int(slot) or slot != SLOT_MINUTES:
        issue("scheduling.slot_minutes", "slot_minutes must be the fixed discrete slot size 30.")
        return None
    horizon = raw.get("horizon_days")
    if not _is_int(horizon) or not 1 <= horizon <= MAX_HORIZON_DAYS:
        issue("scheduling.horizon_days", f"horizon_days must be an integer from 1 to {MAX_HORIZON_DAYS}.")
        return None
    action_limit = raw.get("action_limit", MAX_SCHEDULE_ACTIONS)
    if not _is_int(action_limit) or not 1 <= action_limit <= MAX_SCHEDULE_ACTIONS:
        issue(
            "scheduling.action_limit",
            f"action_limit must be an integer from 1 to {MAX_SCHEDULE_ACTIONS}.",
        )
        return None
    objectives_raw = raw.get("objectives")
    if (
        not isinstance(objectives_raw, list)
        or not objectives_raw
        or any(item not in OBJECTIVES for item in objectives_raw)
        or len(set(objectives_raw)) != len(objectives_raw)
    ):
        issue("scheduling.objectives", f"objectives must be a unique subset of {', '.join(OBJECTIVES)}.")
        return None
    default = raw.get("default_objective")
    if default is None:
        default = objectives_raw[0]
    if default not in objectives_raw:
        issue("scheduling.default_objective", "default_objective must be one of the declared objectives.")
        return None
    capacities = _parse_capacities(raw.get("team_capacities"), teams, issue)
    if capacities is None:
        return None
    profiles = _parse_profiles(raw.get("action_profiles"), issue)
    if profiles is None:
        return None
    dependencies_raw = raw.get("dependencies", [])
    if not isinstance(dependencies_raw, list):
        issue("scheduling.dependencies", "dependencies must be a list.")
        return None
    dependencies: list[DependencyRule] = []
    for index, item in enumerate(dependencies_raw):
        rule = _parse_dependency(item, f"scheduling.dependencies[{index}]", teams, issue)
        if rule is None:
            return None
        dependencies.append(rule)
    dependencies.sort(key=_dependency_sort_key)
    return SchedulingConfig(
        slot_minutes=slot,
        horizon_days=horizon,
        action_limit=action_limit,
        objectives=tuple(objectives_raw),
        default_objective=default,
        team_capacities=capacities,
        action_profiles=profiles,
        dependencies=tuple(dependencies),
    )


def _dependency_sort_key(item: DependencyRule) -> tuple[Any, ...]:
    return (
        item.dataset_id,
        tuple(item.prerequisite.fields),
        tuple(item.dependent.fields),
    )
