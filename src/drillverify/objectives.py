"""RPO and RTO objective evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping

from .models import DatasetConfig, Finding, RecoveryPlan
from .records import DrillEvent
from .results import RestorablePoint, RpoResult, RtoResult
from .timeutil import format_utc, minutes_between


@dataclass(frozen=True)
class ObjectiveAssessment:
    rpo: tuple[RpoResult, ...]
    rto: tuple[RtoResult, ...]
    findings: tuple[Finding, ...]


def _in_window_points(
    dataset_id: str,
    window_start: datetime,
    as_of: datetime,
    points: Iterable[RestorablePoint],
) -> list[RestorablePoint]:
    return sorted(
        (
            point
            for point in points
            if point.dataset_id == dataset_id
            and window_start <= point.finished_at <= as_of
        ),
        key=lambda item: (item.finished_at, item.backup_id),
    )


def summarize_rpo(
    dataset: DatasetConfig,
    window_start: datetime,
    as_of: datetime,
    points: Iterable[RestorablePoint],
) -> RpoResult:
    """Measure adjacent in-window gaps and freshness at as_of for one dataset.

    Pure metric core of :func:`evaluate_rpo` (no findings), so simulations
    such as retention planning can recompute RPO conclusions for a reduced
    set of restorable points.
    """
    in_window = _in_window_points(dataset.dataset_id, window_start, as_of, points)
    if not in_window:
        return RpoResult(
            dataset.dataset_id, "no_points", dataset.rpo_minutes, 0,
            None, None, None, None, None,
        )
    gaps = [
        (minutes_between(left.finished_at, right.finished_at), left, right)
        for left, right in zip(in_window, in_window[1:])
    ]
    last = in_window[-1]
    since_last = minutes_between(last.finished_at, as_of)
    gaps.append((since_last, last, None))
    max_gap, gap_from, gap_to = max(gaps, key=lambda item: (item[0], item[1].finished_at))
    return RpoResult(
        dataset.dataset_id,
        "breach" if max_gap > dataset.rpo_minutes else "pass",
        dataset.rpo_minutes,
        len(in_window),
        max_gap,
        format_utc(gap_from.finished_at),
        format_utc(gap_to.finished_at) if gap_to else format_utc(as_of),
        format_utc(last.finished_at),
        since_last,
    )


def evaluate_rpo(
    plan: RecoveryPlan,
    points: tuple[RestorablePoint, ...],
    catalog_path: str,
    catalog_hash: str,
) -> tuple[tuple[RpoResult, ...], tuple[Finding, ...]]:
    """Measure adjacent restorable-point gaps and freshness at as_of."""
    results: list[RpoResult] = []
    findings: list[Finding] = []
    for dataset in plan.datasets:
        result = summarize_rpo(dataset, plan.window_start, plan.as_of, points)
        results.append(result)
        if result.status == "no_points":
            findings.append(
                Finding(
                    "OBJ-POINT-001",
                    "critical",
                    "dataset",
                    dataset.dataset_id,
                    "No restorable backup exists inside the analysis window.",
                    catalog_path,
                    0,
                    {
                        "window_start": format_utc(plan.window_start),
                        "as_of": format_utc(plan.as_of),
                    },
                    catalog_hash,
                )
            )
            continue
        if result.status == "breach":
            in_window = _in_window_points(
                dataset.dataset_id, plan.window_start, plan.as_of, points
            )
            last = in_window[-1]
            findings.append(
                Finding(
                    "OBJ-RPO-001",
                    "high",
                    "dataset",
                    dataset.dataset_id,
                    "Maximum recovery-point gap exceeds the declared RPO.",
                    catalog_path,
                    0,
                    {
                        "rpo_minutes": dataset.rpo_minutes,
                        "max_gap_minutes": result.max_gap_minutes,
                        "gap_from": result.gap_from,
                        "gap_to": result.gap_to,
                        "last_point_backup_id": last.backup_id,
                    },
                    catalog_hash,
                )
            )
    return tuple(results), tuple(findings)


def evaluate_rto(
    plan: RecoveryPlan,
    events: tuple[DrillEvent, ...],
    drill_success: Mapping[str, bool],
    drill_path: str,
    drill_hash: str,
) -> tuple[tuple[RtoResult, ...], tuple[Finding, ...]]:
    """Measure wall-clock drill duration including failed attempts."""
    datasets = plan.dataset_map()
    grouped: dict[str, list[DrillEvent]] = {}
    for event in events:
        grouped.setdefault(event.drill_id, []).append(event)
    results: list[RtoResult] = []
    findings: list[Finding] = []
    for drill_id in sorted(grouped):
        drill_events = grouped[drill_id]
        started = min(event.started_at for event in drill_events)
        finished = max(event.finished_at for event in drill_events)
        dataset_id = drill_events[0].dataset_id
        backup_id = drill_events[0].backup_id
        duration = minutes_between(started, finished)
        target = datasets[dataset_id].rto_minutes
        successful = bool(drill_success.get(drill_id, False))
        if duration > target:
            status = "breach"
        elif successful:
            status = "pass"
        else:
            status = "not_met"
        results.append(
            RtoResult(
                drill_id=drill_id,
                dataset_id=dataset_id,
                backup_id=backup_id,
                status=status,
                rto_minutes=target,
                duration_minutes=duration,
                started_at=format_utc(started),
                finished_at=format_utc(finished),
                successful=successful,
            )
        )
        if duration > target:
            findings.append(
                Finding(
                    "OBJ-RTO-001",
                    "high",
                    "drill",
                    drill_id,
                    "Drill wall-clock duration exceeds the declared RTO.",
                    drill_path,
                    drill_events[0].line_no,
                    {
                        "rto_minutes": target,
                        "duration_minutes": duration,
                        "started_at": format_utc(started),
                        "finished_at": format_utc(finished),
                        "successful": successful,
                    },
                    drill_hash,
                )
            )
    return tuple(results), tuple(findings)
