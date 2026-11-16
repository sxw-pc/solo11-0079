"""Resolve plan-declared dependency selectors and detect broken dependencies."""

from __future__ import annotations

from .actions import PlanAction
from .models import SchedulingConfig

DEP_MISSING = "dependency_missing"
DEP_CYCLE = "dependency_cycle"
DEP_UNSCHEDULABLE = "dependency_unschedulable"


def resolve_dependencies(
    actions: tuple[PlanAction, ...],
    config: SchedulingConfig,
    items: dict[str, object],
    reasons: dict[str, tuple[str, str]],
    notes: list[str],
) -> dict[str, tuple[str, ...]]:
    """Map every action ID to the prerequisite action IDs that must finish first."""
    by_dataset: dict[str, list[PlanAction]] = {}
    for action in actions:
        by_dataset.setdefault(action.dataset_id, []).append(action)
    prereqs: dict[str, set[str]] = {}
    for index, rule in enumerate(config.dependencies):
        label = f"dependencies[{index}]"
        members = sorted(by_dataset.get(rule.dataset_id, []), key=PlanAction.sort_key)
        prior = [entry for entry in members if rule.prerequisite.matches(entry)]
        dependent = [entry for entry in members if rule.dependent.matches(entry)]
        if not prior:
            if dependent:
                for entry in dependent:
                    reasons.setdefault(
                        entry.action_id,
                        (
                            DEP_MISSING,
                            f"{label} prerequisite {rule.prerequisite.to_dict()} matches "
                            f"no action in {rule.dataset_id}.",
                        ),
                    )
            else:
                notes.append(f"dependency_unresolved:{label}:no_prerequisite_match")
            continue
        if not dependent:
            notes.append(f"dependency_unresolved:{label}:no_dependent_match")
            continue
        for entry in dependent:
            bucket = prereqs.setdefault(entry.action_id, set())
            bucket.update(item.action_id for item in prior)
            missing = sorted(item.action_id for item in prior if item.action_id not in items)
            if missing:
                reasons.setdefault(
                    entry.action_id,
                    (
                        DEP_UNSCHEDULABLE,
                        f"{label} prerequisite {', '.join(missing)} cannot be scheduled.",
                    ),
                )
    resolved = {key: tuple(sorted(value)) for key, value in prereqs.items()}
    detect_cycles(resolved, reasons)
    propagate_blocked(resolved, reasons)
    return resolved


def detect_cycles(
    prereqs: dict[str, tuple[str, ...]], reasons: dict[str, tuple[str, str]]
) -> None:
    """Mark every action on a dependency cycle as explicitly unschedulable."""
    state: dict[str, int] = {}

    def visit(node: str, trail: list[str]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            start = trail.index(node) if node in trail else 0
            for member in trail[start:]:
                reasons.setdefault(
                    member, (DEP_CYCLE, "Action lies on an explicit dependency cycle.")
                )
            return
        state[node] = 1
        trail.append(node)
        for parent in prereqs.get(node, ()):
            visit(parent, trail)
        trail.pop()
        state[node] = 2

    for node in sorted(prereqs):
        visit(node, [])


def propagate_blocked(
    prereqs: dict[str, tuple[str, ...]], reasons: dict[str, tuple[str, str]]
) -> None:
    """Reject any action whose prerequisite is already unschedulable."""
    changed = True
    while changed:
        changed = False
        for action_id, parents in prereqs.items():
            if action_id in reasons:
                continue
            blocked = sorted(parent for parent in parents if parent in reasons)
            if blocked:
                reasons[action_id] = (
                    DEP_UNSCHEDULABLE,
                    f"Prerequisite {', '.join(blocked)} cannot be scheduled.",
                )
                changed = True
