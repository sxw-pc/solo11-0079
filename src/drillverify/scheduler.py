"""Plan-authorized scheduling orchestration: windows, dependencies, objectives."""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any

from .actions import MAX_SCHEDULE_ACTIONS, PlanAction, SchedulePlan
from .models import RecoveryPlan
from .schedule_deps import resolve_dependencies
from .schedule_outcome import build_outcome, structural_unscheduled, unscheduled_dict
from .schedule_solver import BatchItem, SolveResult, solve_batch
from .schedule_windows import allowed_start_slots, parse_window
from .timeutil import format_utc, parse_utc

UNKNOWN_DATASET = "unknown_dataset"
INVALID_WINDOW = "invalid_maintenance_window"
NO_CAPACITY = "no_team_capacity"
NO_PROFILE = "no_duration_profile"
NO_SLOT_IN_HORIZON = "no_window_slot_in_horizon"
ACTION_LIMIT = "action_limit_exceeded"
SEARCH_INCOMPLETE = "search_incomplete"
NOT_DECLARED = "scheduling_not_declared"


def build_schedule(plan: RecoveryPlan, actions: tuple[PlanAction, ...]) -> SchedulePlan:
    """Produce a slot-level schedule and explicit unschedulable explanations."""
    config = plan.scheduling
    if config is None:
        return _no_policy(plan, actions)
    horizon_end = plan.as_of + timedelta(days=config.horizon_days)
    datasets = plan.dataset_map()
    reasons: dict[str, tuple[str, str]] = {}
    items: dict[str, BatchItem] = {}
    teams: dict[str, list[str]] = {}
    notes: list[str] = []
    batch_rows: list[dict[str, Any]] = []
    for action in actions:
        dataset = datasets.get(action.dataset_id)
        team = dataset.owner_team if dataset else action.owner_team
        profile = config.profile_for(action.category)
        capacity = config.capacity_for(team) if dataset else None
        reason = detail = ""
        if dataset is None:
            reason, detail = UNKNOWN_DATASET, "Action has no declared dataset or maintenance window."
        elif parse_window(dataset.maintenance_window) is None:
            reason = INVALID_WINDOW
            detail = f"Unparseable maintenance_window {dataset.maintenance_window!r}."
        elif capacity is None:
            reason, detail = NO_CAPACITY, f"No per-slot capacity for owner team {team}."
        elif profile is None:
            reason = NO_PROFILE
            detail = f"No duration/impact profile for category {action.category}."
        else:
            candidates = allowed_start_slots(
                dataset.maintenance_window,
                plan.as_of,
                horizon_end,
                profile.duration_minutes,
                config.slot_minutes,
            )
            if not candidates:
                reason = NO_SLOT_IN_HORIZON
                detail = (
                    f"{profile.duration_minutes} min cannot fit any {dataset.maintenance_window} "
                    f"occurrence inside the {config.horizon_days}-day horizon."
                )
        if reason:
            reasons[action.action_id] = (reason, detail)
            continue
        items[action.action_id] = BatchItem(
            action_id=action.action_id,
            priority=action.priority,
            category=action.category,
            team=team,
            duration_slots=int(math.ceil(profile.duration_minutes / config.slot_minutes)),
            duration_minutes=profile.duration_minutes,
            impact_minutes=profile.impact_minutes,
            due_end=_due_end(action.due_at),
            candidates=candidates,
            start_origin=plan.as_of,
            slot_minutes=config.slot_minutes,
        )
        teams.setdefault(team, []).append(action.action_id)
    prereqs = resolve_dependencies(actions, config, items, reasons, notes)
    # Batches are the independent exact-solve units: capacity is declared per team
    # and every dependency is dataset-scoped, so no slot constraint crosses a team.
    # Solving each team exactly is therefore exact overall. The action cap applies
    # to each batch; an over-cap batch is rejected whole, never silently truncated.
    limit_hit = False
    for team in sorted(teams):
        batch = sorted(teams[team])
        over = len(batch) > config.action_limit
        batch_rows.append(
            {
                "team": team,
                "action_count": len(batch),
                "limit": config.action_limit,
                "over_limit": over,
            }
        )
        if not over:
            continue
        limit_hit = True
        detail = (
            f"Owner team {team} batch has {len(batch)} actions but the plan authorizes "
            f"exact scheduling for at most {config.action_limit}. The whole batch is "
            "returned unplanable; no action is silently truncated or decimated."
        )
        notes.append(f"action_limit_exceeded:{team}:{len(batch)}")
        for action_id in batch:
            reasons[action_id] = (ACTION_LIMIT, detail)
    outcomes = []
    incomplete_objectives: set[str] = set()
    for objective in config.objectives:
        slots: dict[str, int] = {}
        team_results: dict[
            str, tuple[SolveResult, dict[str, BatchItem], dict[str, tuple[str, ...]]]
        ] = {}
        nodes = 0
        objective_complete = True
        for team in sorted(teams):
            batch = [key for key in sorted(teams[team]) if key not in reasons]
            if not batch:
                continue
            subset = {key: items[key] for key in batch}
            local = {
                key: tuple(parent for parent in prereqs.get(key, ()) if parent in subset)
                for key in batch
            }
            capacity = config.capacity_for(team) or 0
            result = solve_batch(subset, local, capacity, objective)
            slots.update(result.slots)
            nodes += result.nodes
            objective_complete = objective_complete and result.optimal
            team_results[team] = (result, subset, local)
        if not objective_complete:
            incomplete_objectives.add(objective)
        outcomes.append(
            build_outcome(
                plan, config, objective, items, actions, prereqs, reasons, slots,
                team_results, nodes, objective_complete,
            )
        )
    incomplete = bool(incomplete_objectives)
    notes.extend(f"search_incomplete:{objective}" for objective in sorted(incomplete_objectives))
    planable = not limit_hit and not incomplete
    fully_scheduled = planable and not reasons
    status = _status(actions, planable, fully_scheduled, outcomes)
    return SchedulePlan(
        as_of=format_utc(plan.as_of),
        window_start=format_utc(plan.window_start),
        horizon_end=format_utc(horizon_end),
        slot_minutes=config.slot_minutes,
        horizon_days=config.horizon_days,
        horizon_slots=int(
            (horizon_end - plan.as_of).total_seconds() // 60 // config.slot_minutes
        ),
        selected_objective=config.default_objective,
        objectives=config.objectives,
        outcomes=tuple(outcomes),
        action_count=len(actions),
        action_limit=config.action_limit,
        batches=tuple(batch_rows),
        status=status,
        planable=planable,
        fully_scheduled=fully_scheduled,
        planable_reason="" if planable else _planable_reason(actions, limit_hit, incomplete),
        unschedulable_actions=tuple(
            item.to_dict()
            for item in sorted(
                structural_unscheduled(actions, reasons, items),
                key=lambda entry: entry.sort_key(),
            )
        ),
        notes=tuple(sorted(notes)),
    )


def _no_policy(plan: RecoveryPlan, actions: tuple[PlanAction, ...]) -> SchedulePlan:
    return SchedulePlan(
        as_of=format_utc(plan.as_of),
        window_start=format_utc(plan.window_start),
        horizon_end=format_utc(plan.as_of),
        slot_minutes=30,
        horizon_days=0,
        horizon_slots=0,
        selected_objective="",
        objectives=(),
        outcomes=(),
        action_count=len(actions),
        action_limit=MAX_SCHEDULE_ACTIONS,
        batches=(),
        status="unplanable",
        planable=False,
        fully_scheduled=False,
        planable_reason=NOT_DECLARED,
        unschedulable_actions=tuple(
            unscheduled_dict(
                action, NOT_DECLARED,
                "Recovery plan does not declare a scheduling policy.", False,
            )
            for action in sorted(actions, key=PlanAction.sort_key)
        ),
        notes=(NOT_DECLARED,),
    )


def _due_end(due_at: str) -> datetime:
    return parse_utc(f"{due_at}T00:00:00Z") + timedelta(days=1)


def _planable_reason(
    actions: tuple[PlanAction, ...], limit_hit: bool, incomplete: bool
) -> str:
    if not actions:
        return "no_actions_to_schedule"
    if limit_hit:
        return ACTION_LIMIT
    if incomplete:
        return SEARCH_INCOMPLETE
    return "not_fully_schedulable"


def _status(
    actions: tuple[PlanAction, ...],
    planable: bool,
    fully_scheduled: bool,
    outcomes: list[Any],
) -> str:
    """One stable schedule-level label for reports and the ledger."""
    if not actions:
        return "empty"
    if not planable:
        return "unplanable"
    if fully_scheduled:
        return "feasible"
    if any(outcome.unscheduled for outcome in outcomes):
        return "partial"
    return "feasible"
