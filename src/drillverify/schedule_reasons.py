"""Explain every action the selected objective leaves unscheduled."""

from __future__ import annotations

from .schedule_solver import BatchItem


def unscheduled_reason(
    item: BatchItem,
    action_id: str,
    prereqs: dict[str, tuple[str, ...]],
    scheduled: dict[str, int],
    items: dict[str, BatchItem],
    capacity: int,
) -> tuple[str, str]:
    """Return a stable reason code and human detail for one unscheduled action."""
    missing = [parent for parent in prereqs.get(action_id, ()) if parent not in scheduled]
    if missing:
        return (
            "dependency_conflict",
            f"Prerequisite {', '.join(sorted(missing))} is not in the selected schedule.",
        )
    if not any(item.end_at(slot) <= item.due_end for slot in item.candidates):
        return (
            "window_conflict",
            "No maintenance-window slot in the horizon completes this action by its due date.",
        )
    if not _has_free_slot(item, action_id, scheduled, items, capacity):
        return (
            "capacity_conflict",
            "Every maintenance-window slot is reserved by another action under the "
            f"selected objective (parallel capacity {capacity}).",
        )
    return (
        "objective_tradeoff",
        "A feasible slot exists, but the selected objective prefers other actions.",
    )


def _has_free_slot(
    item: BatchItem,
    action_id: str,
    scheduled: dict[str, int],
    items: dict[str, BatchItem],
    capacity: int,
) -> bool:
    for start in item.candidates:
        if all(
            sum(
                1
                for other, other_start in scheduled.items()
                if other != action_id
                and other_start <= slot < other_start + items[other].duration_slots
            )
            < capacity
            for slot in range(start, start + item.duration_slots)
        ):
            return True
    return False
