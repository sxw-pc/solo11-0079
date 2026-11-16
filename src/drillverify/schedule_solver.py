"""Exact branch-and-bound solver for one owner-team scheduling batch.

A batch shares one per-slot parallel capacity. Dependencies inside the batch form
a DAG and actions are explored in a fixed topological order. Both objectives use
identical hard constraints and report every action they leave unscheduled.

* ``min_overdue_high`` minimizes overdue high-risk actions first, then the number
  of unscheduled actions. Unscheduled high-risk work counts as overdue, so this
  objective never rewards dropping work.
* ``min_impact`` maximizes scheduled coverage first, then minimizes total
  maintenance-impact minutes. Coverage is primary because a do-nothing schedule
  would otherwise be a trivial and useless optimum.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .actions import OBJECTIVES
from .rules import SEVERITY_RANK, is_high_risk
NODE_BUDGET = 2_000_000


@dataclass(frozen=True)
class BatchItem:
    action_id: str
    priority: str
    category: str
    team: str
    duration_slots: int
    duration_minutes: int
    impact_minutes: int
    due_end: datetime
    candidates: tuple[int, ...]
    start_origin: datetime
    slot_minutes: int

    @property
    def high_risk(self) -> bool:
        return is_high_risk(self.priority)

    def end_at(self, start: int) -> datetime:
        return self.start_origin + timedelta(
            minutes=start * self.slot_minutes + self.duration_minutes
        )


@dataclass(frozen=True)
class SolveResult:
    slots: dict[str, int]
    nodes: int
    optimal: bool


def _topological_order(
    items: dict[str, BatchItem], prereqs: dict[str, tuple[str, ...]]
) -> list[str]:
    pending = {
        key: {parent for parent in parents if parent in items}
        for key, parents in prereqs.items()
    }
    dependents: dict[str, int] = {key: 0 for key in items}
    for parents in pending.values():
        for parent in parents:
            dependents[parent] = dependents.get(parent, 0) + 1
    remaining = set(items)
    order: list[str] = []
    while remaining:
        ready = [key for key in remaining if not (pending.get(key, set()) & remaining)]
        if not ready:
            ready = list(remaining)
        ready.sort(
            key=lambda key: (
                len(items[key].candidates),
                -dependents.get(key, 0),
                SEVERITY_RANK.get(items[key].priority, 99),
                key,
            )
        )
        chosen = ready[0]
        order.append(chosen)
        remaining.remove(chosen)
    return order


def _signature(item: BatchItem) -> tuple[Any, ...]:
    return (
        item.team,
        item.duration_slots,
        item.priority,
        item.impact_minutes,
        item.due_end,
        item.candidates,
    )


def solve_batch(
    items: dict[str, BatchItem],
    prereqs: dict[str, tuple[str, ...]],
    capacity: int,
    objective: str,
) -> SolveResult:
    """Return the exact optimum for the objective, or the best found with a flag."""
    if not items or capacity <= 0:
        return SolveResult({}, 0, True)
    order = _topological_order(items, prereqs)
    has_deps = any(prereqs.get(key) for key in items)
    previous: dict[str, str] = {}
    if not has_deps:
        groups: dict[tuple[Any, ...], list[str]] = {}
        for key in order:
            groups.setdefault(_signature(items[key]), []).append(key)
        for members in groups.values():
            for left, right in zip(members, members[1:]):
                previous[right] = left
    total = len(order)
    assignment: dict[str, int] = {}
    ends: dict[str, int] = {}
    usage: dict[int, int] = {}
    state = {"nodes": 0, "cut": False}
    forced_high = [0] * (total + 1)
    for index in range(total - 1, -1, -1):
        item = items[order[index]]
        forced = 0 if any(item.end_at(s) <= item.due_end for s in item.candidates) else 1
        forced_high[index] = forced_high[index + 1] + (forced if item.high_risk else 0)

    def feasible(item: BatchItem, start: int) -> bool:
        action_id = item.action_id
        for parent in prereqs.get(action_id, ()):
            if parent not in assignment or ends[parent] > start:
                return False
        prior = previous.get(action_id)
        if prior is not None and prior in assignment and assignment[prior] > start:
            return False
        if all(
            usage.get(slot, 0) < capacity
            for slot in range(start, start + item.duration_slots)
        ):
            return True
        return False

    def occupy(item: BatchItem, start: int, delta: int) -> None:
        for slot in range(start, start + item.duration_slots):
            usage[slot] = usage.get(slot, 0) + delta
            if usage[slot] == 0:
                del usage[slot]

    def leaf_key(late_high: int, late_total: int, impact: int) -> tuple[Any, ...]:
        missing = total - len(assignment)
        high_missing = sum(
            1 for key in order if key not in assignment and items[key].high_risk
        )
        overdue_high = late_high + high_missing
        overdue_total = late_total + missing
        signature = tuple(sorted((slot, key) for key, slot in assignment.items()))
        # Unscheduled actions count as overdue, so dropping work never improves an
        # objective. Coverage then breaks ties deterministically.
        if objective == OBJECTIVES[0]:
            return (overdue_high, missing, impact, overdue_total, signature)
        return (missing, impact, overdue_high, overdue_total, signature)

    best: dict[str, Any] = {"key": None, "slots": {}}
    _seed_greedy(order, items, prereqs, previous, capacity, objective, best, leaf_key)

    def bounded(index: int, scheduled: int, late_high: int, impact: int) -> bool:
        key = best["key"]
        if key is None:
            return False
        missing_lb = index - scheduled
        if objective == OBJECTIVES[0]:
            high_lb = late_high + forced_high[index]
            return (
                high_lb > key[0]
                or (high_lb == key[0] and missing_lb > key[1])
                or (high_lb == key[0] and missing_lb == key[1] and impact > key[2])
            )
        return missing_lb > key[0] or (missing_lb == key[0] and impact > key[1])

    def visit(index: int, scheduled: int, late_high: int, late_total: int, impact: int) -> None:
        state["nodes"] += 1
        if state["nodes"] > NODE_BUDGET:
            state["cut"] = True
            return
        if bounded(index, scheduled, late_high, impact):
            return
        if index == total:
            key = leaf_key(late_high, late_total, impact)
            if best["key"] is None or key < best["key"]:
                best["key"] = key
                best["slots"] = dict(assignment)
            return
        item = items[order[index]]
        action_id = item.action_id
        for start in item.candidates:
            if not feasible(item, start):
                continue
            occupy(item, start, 1)
            assignment[action_id] = start
            ends[action_id] = start + item.duration_slots
            late = item.end_at(start) > item.due_end
            visit(
                index + 1,
                scheduled + 1,
                late_high + (1 if late and item.high_risk else 0),
                late_total + (1 if late else 0),
                impact + item.impact_minutes,
            )
            del assignment[action_id]
            del ends[action_id]
            occupy(item, start, -1)
            if state["cut"]:
                return
        visit(index + 1, scheduled, late_high, late_total, impact)

    visit(0, 0, 0, 0, 0)
    return SolveResult(dict(best["slots"]), state["nodes"], not state["cut"])


def _seed_greedy(
    order: list[str],
    items: dict[str, BatchItem],
    prereqs: dict[str, tuple[str, ...]],
    previous: dict[str, str],
    capacity: int,
    objective: str,
    best: dict[str, Any],
    leaf_key: Any,
) -> None:
    """Seed the bound with a deterministic first-fit schedule."""
    slots: dict[str, int] = {}
    ends: dict[str, int] = {}
    usage: dict[int, int] = {}
    late_high = late_total = impact = 0
    for key in order:
        item = items[key]
        placed = None
        for start in item.candidates:
            if any(parent not in slots or ends[parent] > start for parent in prereqs.get(key, ())):
                continue
            if prior := previous.get(key):
                if prior in slots and slots[prior] > start:
                    continue
            if any(usage.get(s, 0) >= capacity for s in range(start, start + item.duration_slots)):
                continue
            placed = start
            break
        if placed is None:
            continue
        for s in range(placed, placed + item.duration_slots):
            usage[s] = usage.get(s, 0) + 1
        slots[key] = placed
        ends[key] = placed + item.duration_slots
        late = item.end_at(placed) > item.due_end
        late_high += 1 if late and item.high_risk else 0
        late_total += 1 if late else 0
        impact += item.impact_minutes
    if not slots:
        return
    order_ids = list(order)
    missing = len(order_ids) - len(slots)
    high_missing = sum(1 for key in order_ids if key not in slots and items[key].high_risk)
    overdue_high = late_high + high_missing
    overdue_total = late_total + missing
    signature = tuple(sorted((slot, key) for key, slot in slots.items()))
    if objective == OBJECTIVES[0]:
        best["key"] = (overdue_high, missing, impact, overdue_total, signature)
    else:
        best["key"] = (missing, impact, overdue_high, overdue_total, signature)
    best["slots"] = slots
