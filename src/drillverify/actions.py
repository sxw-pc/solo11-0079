"""Attribution, remediation and remediation-scheduling action types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .rules import SEVERITY_RANK

SLOT_MINUTES = 30
MAX_SCHEDULE_ACTIONS = 12
MAX_HORIZON_DAYS = 28
OBJECTIVES = ("min_overdue_high", "min_impact")


@dataclass(frozen=True)
class AttributionRecord:
    category: str
    rule_id: str
    severity: str
    object_type: str
    object_id: str
    root_cause: str
    material: bool
    probe: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "root_cause": self.root_cause,
            "material": self.material,
            "probe": self.probe,
        }


@dataclass(frozen=True)
class PlanAction:
    action_id: str
    priority: str
    category: str
    owner_team: str
    dataset_id: str
    object_type: str
    object_id: str
    rule_id: str
    rule_ids: tuple[str, ...]
    title: str
    rationale: str
    instruction: str
    due_at: str
    probes: tuple[dict[str, Any], ...]

    def sort_key(self) -> tuple[Any, ...]:
        return (
            SEVERITY_RANK.get(self.priority, 99),
            self.due_at,
            self.dataset_id,
            self.action_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "priority": self.priority,
            "category": self.category,
            "owner_team": self.owner_team,
            "dataset_id": self.dataset_id,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "rule_id": self.rule_id,
            "rule_ids": list(self.rule_ids),
            "title": self.title,
            "rationale": self.rationale,
            "instruction": self.instruction,
            "due_at": self.due_at,
            "probes": sorted(
                self.probes,
                key=lambda item: (item.get("file", ""), item.get("line", 0)),
            ),
        }


@dataclass(frozen=True)
class ScheduledAction:
    """One PlanAction bound to a discrete maintenance-window slot."""

    action_id: str
    owner_team: str
    dataset_id: str
    priority: str
    category: str
    object_type: str
    object_id: str
    maintenance_window: str
    due_at: str
    start_slot: int
    start_at: str
    end_at: str
    duration_slots: int
    duration_minutes: int
    impact_minutes: int
    overdue: bool
    overdue_minutes: int
    due_feasible: bool
    delay_reason: str
    dependency_ids: tuple[str, ...]
    finding_rule_ids: tuple[str, ...]
    probes: tuple[dict[str, Any], ...]

    @property
    def end_slot(self) -> int:
        return self.start_slot + self.duration_slots

    def sort_key(self) -> tuple[Any, ...]:
        return (self.start_slot, self.owner_team, self.dataset_id, self.action_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "owner_team": self.owner_team,
            "dataset_id": self.dataset_id,
            "priority": self.priority,
            "category": self.category,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "maintenance_window": self.maintenance_window,
            "due_at": self.due_at,
            "start_slot": self.start_slot,
            "end_slot": self.end_slot,
            "start_at": self.start_at,
            "end_at": self.end_at,
            "duration_slots": self.duration_slots,
            "duration_minutes": self.duration_minutes,
            "impact_minutes": self.impact_minutes,
            "overdue": self.overdue,
            "overdue_minutes": self.overdue_minutes,
            "due_feasible": self.due_feasible,
            "delay_reason": self.delay_reason,
            "dependency_ids": list(self.dependency_ids),
            "finding_rule_ids": list(self.finding_rule_ids),
            "probes": sorted(
                self.probes, key=lambda item: (item.get("file", ""), item.get("line", 0))
            ),
        }


@dataclass(frozen=True)
class UnscheduledAction:
    action_id: str
    owner_team: str
    dataset_id: str
    priority: str
    category: str
    object_type: str
    object_id: str
    reason: str
    detail: str
    before_due_possible: bool

    def sort_key(self) -> tuple[Any, ...]:
        return (SEVERITY_RANK.get(self.priority, 99), self.dataset_id, self.action_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "owner_team": self.owner_team,
            "dataset_id": self.dataset_id,
            "priority": self.priority,
            "category": self.category,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "reason": self.reason,
            "detail": self.detail,
            "before_due_possible": self.before_due_possible,
        }


@dataclass(frozen=True)
class ObjectiveOutcome:
    """Selected-objective schedule and its measured optimization metrics."""

    objective: str
    scheduled: tuple[ScheduledAction, ...]
    unscheduled: tuple[UnscheduledAction, ...]
    overdue_high_count: int
    overdue_total_count: int
    overdue_scheduled_high_count: int
    overdue_scheduled_count: int
    total_impact_minutes: int
    optimal: bool
    exhaustive_nodes: int
    reason_counts: dict[str, int]
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "overdue_high_count": self.overdue_high_count,
            "overdue_total_count": self.overdue_total_count,
            "overdue_scheduled_high_count": self.overdue_scheduled_high_count,
            "overdue_scheduled_count": self.overdue_scheduled_count,
            "total_impact_minutes": self.total_impact_minutes,
            "scheduled_count": len(self.scheduled),
            "unscheduled_count": len(self.unscheduled),
            "optimal": self.optimal,
            "exhaustive_nodes": self.exhaustive_nodes,
            "reason_counts": dict(sorted(self.reason_counts.items())),
            "notes": list(self.notes),
            "scheduled": [item.to_dict() for item in self.scheduled],
            "unscheduled": [item.to_dict() for item in self.unscheduled],
        }


@dataclass(frozen=True)
class SchedulePlan:
    """Complete, deterministic remediation-scheduling outcome."""

    as_of: str
    window_start: str
    horizon_end: str
    slot_minutes: int
    horizon_days: int
    horizon_slots: int
    selected_objective: str
    objectives: tuple[str, ...]
    outcomes: tuple[ObjectiveOutcome, ...]
    action_count: int
    action_limit: int
    batches: tuple[dict[str, Any], ...]
    status: str
    planable: bool
    fully_scheduled: bool
    planable_reason: str
    unschedulable_actions: tuple[dict[str, Any], ...]
    notes: tuple[str, ...]

    @property
    def selected(self) -> ObjectiveOutcome | None:
        return self.outcome_for(self.selected_objective)

    def outcome_for(self, objective: str) -> ObjectiveOutcome | None:
        for item in self.outcomes:
            if item.objective == objective:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        selected = self.selected
        return {
            "as_of": self.as_of,
            "window_start": self.window_start,
            "horizon_end": self.horizon_end,
            "slot_minutes": self.slot_minutes,
            "horizon_days": self.horizon_days,
            "horizon_slots": self.horizon_slots,
            "selected_objective": self.selected_objective,
            "authorized_objectives": list(self.objectives),
            "action_count": self.action_count,
            "action_limit": self.action_limit,
            "batches": [dict(item) for item in self.batches],
            "status": self.status,
            "planable": self.planable,
            "fully_scheduled": self.fully_scheduled,
            "planable_reason": self.planable_reason,
            "summary": selected.to_dict() if selected else None,
            "objectives": [item.to_dict() for item in self.outcomes],
            "unschedulable_actions": list(self.unschedulable_actions),
            "notes": list(self.notes),
        }
