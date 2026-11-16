"""Assemble per-objective scheduling outcomes and unschedulable explanations."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .actions import (
    ObjectiveOutcome,
    PlanAction,
    ScheduledAction,
    UnscheduledAction,
)
from .models import RecoveryPlan, SchedulingConfig
from .schedule_reasons import unscheduled_reason
from .schedule_solver import BatchItem, SolveResult
from .timeutil import format_utc

from .rules import is_high_risk

SEARCH_INCOMPLETE = "search_incomplete"
NOT_DECLARED = "scheduling_not_declared"


def unscheduled_dict(action: PlanAction, reason: str, detail: str, before_due: bool) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "owner_team": action.owner_team,
        "dataset_id": action.dataset_id,
        "priority": action.priority,
        "category": action.category,
        "object_type": action.object_type,
        "object_id": action.object_id,
        "reason": reason,
        "detail": detail,
        "before_due_possible": before_due,
    }


def structural_unscheduled(
    actions: tuple[PlanAction, ...],
    reasons: dict[str, tuple[str, str]],
    items: dict[str, BatchItem],
) -> list[UnscheduledAction]:
    by_id = {action.action_id: action for action in actions}
    result: list[UnscheduledAction] = []
    for action_id in sorted(reasons):
        reason, detail = reasons[action_id]
        action = by_id[action_id]
        item = items.get(action_id)
        result.append(
            UnscheduledAction(
                action_id=action_id,
                owner_team=action.owner_team,
                dataset_id=action.dataset_id,
                priority=action.priority,
                category=action.category,
                object_type=action.object_type,
                object_id=action.object_id,
                reason=reason,
                detail=detail,
                before_due_possible=_before_due(item),
            )
        )
    return result


def _before_due(item: BatchItem | None) -> bool:
    return bool(item and any(item.end_at(slot) <= item.due_end for slot in item.candidates))


def build_outcome(
    plan: RecoveryPlan,
    config: SchedulingConfig,
    objective: str,
    items: dict[str, BatchItem],
    actions: tuple[PlanAction, ...],
    prereqs: dict[str, tuple[str, ...]],
    reasons: dict[str, tuple[str, str]],
    slots: dict[str, int],
    team_results: dict[str, tuple[SolveResult, dict[str, BatchItem], dict[str, tuple[str, ...]]]],
    nodes: int,
    optimal: bool,
) -> ObjectiveOutcome:
    datasets = plan.dataset_map()
    scheduled: list[ScheduledAction] = []
    unscheduled: list[UnscheduledAction] = []
    for action in sorted(actions, key=PlanAction.sort_key):
        action_id = action.action_id
        item = items.get(action_id)
        start = slots.get(action_id)
        if item is None or start is None:
            entry = _missed(action, item, reasons, team_results, config, datasets)
            unscheduled.append(entry)
            continue
        scheduled.append(
            _scheduled(plan, config, action, item, start, prereqs, slots, items, datasets)
        )
    overdue_high = sum(
        1 for entry in scheduled if entry.overdue and is_high_risk(entry.priority)
    ) + sum(1 for entry in unscheduled if is_high_risk(entry.priority))
    overdue_total = sum(1 for entry in scheduled if entry.overdue) + len(unscheduled)
    counts: dict[str, int] = {}
    for entry in unscheduled:
        counts[entry.reason] = counts.get(entry.reason, 0) + 1
    return ObjectiveOutcome(
        objective=objective,
        scheduled=tuple(sorted(scheduled, key=ScheduledAction.sort_key)),
        unscheduled=tuple(sorted(unscheduled, key=UnscheduledAction.sort_key)),
        overdue_high_count=overdue_high,
        overdue_total_count=overdue_total,
        overdue_scheduled_high_count=sum(
            1 for entry in scheduled if entry.overdue and is_high_risk(entry.priority)
        ),
        overdue_scheduled_count=sum(1 for entry in scheduled if entry.overdue),
        total_impact_minutes=sum(entry.impact_minutes for entry in scheduled),
        optimal=optimal,
        exhaustive_nodes=nodes,
        reason_counts=dict(sorted(counts.items())),
        notes=tuple(f"{reason}={count}" for reason, count in sorted(counts.items())),
    )


def _missed(
    action: PlanAction,
    item: BatchItem | None,
    reasons: dict[str, tuple[str, str]],
    team_results: dict[str, tuple[SolveResult, dict[str, BatchItem], dict[str, tuple[str, ...]]]],
    config: SchedulingConfig,
    datasets: dict[str, Any],
) -> UnscheduledAction:
    reason, detail = reasons.get(action.action_id, ("", ""))
    if not reason and item is not None:
        dataset = datasets.get(action.dataset_id)
        team = dataset.owner_team if dataset else action.owner_team
        result, subset, local = team_results.get(team, (SolveResult({}, 0, True), {}, {}))
        reason, detail = unscheduled_reason(
            item, action.action_id, local, result.slots, subset,
            config.capacity_for(team) or 0,
        )
    return UnscheduledAction(
        action_id=action.action_id,
        owner_team=action.owner_team,
        dataset_id=action.dataset_id,
        priority=action.priority,
        category=action.category,
        object_type=action.object_type,
        object_id=action.object_id,
        reason=reason or SEARCH_INCOMPLETE,
        detail=detail or "No schedule was produced for this action.",
        before_due_possible=_before_due(item),
    )


def _scheduled(
    plan: RecoveryPlan,
    config: SchedulingConfig,
    action: PlanAction,
    item: BatchItem,
    start: int,
    prereqs: dict[str, tuple[str, ...]],
    slots: dict[str, int],
    items: dict[str, BatchItem],
    datasets: dict[str, Any],
) -> ScheduledAction:
    start_at = plan.as_of + timedelta(minutes=start * config.slot_minutes)
    end_at = start_at + timedelta(minutes=item.duration_minutes)
    earliest = item.candidates[0]
    parent_ready = max(
        (
            slots[parent] + items[parent].duration_slots
            for parent in prereqs.get(action.action_id, ())
            if parent in slots
        ),
        default=earliest,
    )
    if parent_ready > earliest and start == parent_ready:
        delay = "dependency_delay"
    elif start > parent_ready:
        delay = "capacity_delay"
    else:
        delay = ""
    parents = tuple(sorted(parent for parent in prereqs.get(action.action_id, ()) if parent in slots))
    return ScheduledAction(
        action_id=action.action_id,
        owner_team=action.owner_team,
        dataset_id=action.dataset_id,
        priority=action.priority,
        category=action.category,
        object_type=action.object_type,
        object_id=action.object_id,
        maintenance_window=datasets[action.dataset_id].maintenance_window,
        due_at=action.due_at,
        start_slot=start,
        start_at=format_utc(start_at),
        end_at=format_utc(end_at),
        duration_slots=item.duration_slots,
        duration_minutes=item.duration_minutes,
        impact_minutes=item.impact_minutes,
        overdue=end_at > item.due_end,
        overdue_minutes=max(0, int((end_at - item.due_end).total_seconds() // 60)),
        due_feasible=item.end_at(earliest) <= item.due_end,
        delay_reason=delay,
        dependency_ids=parents,
        finding_rule_ids=action.rule_ids,
        probes=action.probes,
    )
