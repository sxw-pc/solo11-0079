"""Small synthetic scheduling scenarios used by the scheduler tests."""

from __future__ import annotations

from datetime import datetime, timezone

from drillverify.actions import PlanAction
from drillverify.models import (
    ActionProfile,
    ActionSelector,
    DatasetConfig,
    DependencyRule,
    RecoveryPlan,
    SchedulingConfig,
    TeamCapacity,
)
from drillverify.rules import REMEDIATION

AS_OF = datetime(2026, 11, 10, tzinfo=timezone.utc)  # Tuesday


def profiles(**overrides: tuple[int, int]) -> tuple[ActionProfile, ...]:
    """Default duration/impact per category, with optional per-category overrides."""
    return tuple(
        ActionProfile(
            category,
            overrides.get(category, (60, 30))[0],
            overrides.get(category, (60, 30))[1],
        )
        for category in REMEDIATION
    )


def dataset(
    dataset_id: str = "ds-a",
    team: str = "team-a",
    window: str = "wed:01:00-03:00Z",
) -> DatasetConfig:
    return DatasetConfig(
        dataset_id=dataset_id,
        display_name=f"{dataset_id} display",
        rpo_minutes=240,
        rto_minutes=90,
        required_steps=("precheck",),
        checksum_required=True,
        rowcount_required=True,
        owner_team=team,
        maintenance_window=window,
        artifact_manifest_path="artifacts",
    )


def action(
    action_id: str,
    *,
    dataset_id: str = "ds-a",
    team: str = "team-a",
    category: str = "chain_integrity",
    priority: str = "high",
    due_at: str = "2026-11-12",
    object_type: str = "backup",
    object_id: str | None = None,
) -> PlanAction:
    return PlanAction(
        action_id=action_id,
        priority=priority,
        category=category,
        owner_team=team,
        dataset_id=dataset_id,
        object_type=object_type,
        object_id=object_id or action_id,
        rule_id="CHAIN-001",
        rule_ids=("CHAIN-001",),
        title=f"action {action_id}",
        rationale="synthetic",
        instruction="synthetic",
        due_at=due_at,
        probes=(),
    )


def selector(**fields: str) -> ActionSelector:
    return ActionSelector(tuple(sorted(fields.items())))


def plan(
    datasets: tuple[DatasetConfig, ...],
    *,
    capacities: dict[str, int] | None = None,
    profiles_value: tuple[ActionProfile, ...] | None = None,
    dependencies: tuple[DependencyRule, ...] = (),
    horizon_days: int = 28,
    action_limit: int = 12,
    objectives: tuple[str, ...] = ("min_overdue_high", "min_impact"),
) -> RecoveryPlan:
    teams = {item.owner_team for item in datasets}
    caps = capacities or {team: 2 for team in sorted(teams)}
    scheduling = SchedulingConfig(
        slot_minutes=30,
        horizon_days=horizon_days,
        action_limit=action_limit,
        objectives=objectives,
        default_objective=objectives[0],
        team_capacities=tuple(TeamCapacity(team, caps[team]) for team in sorted(caps)),
        action_profiles=profiles_value or profiles(),
        dependencies=dependencies,
    )
    return RecoveryPlan(
        as_of=AS_OF,
        analysis_window_days=7,
        datasets=datasets,
        plan_path="plans/recovery_plan.yaml",
        scheduling=scheduling,
    )


def dependency(
    dataset_id: str,
    prerequisite: ActionSelector,
    dependent: ActionSelector,
) -> DependencyRule:
    return DependencyRule(dataset_id, prerequisite, dependent)
