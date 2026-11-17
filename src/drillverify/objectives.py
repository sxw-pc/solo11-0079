"""RPO and RTO objective evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import Finding, RecoveryPlan
from .records import DrillEvent
from .results import RestorablePoint, RpoResult, RtoResult
from .timeutil import format_utc, minutes_between


@dataclass(frozen=True)
class ObjectiveAssessment:
    rpo: tuple[RpoResult, ...]
    rto: tuple[RtoResult, ...]
    findings: tuple[Finding, ...]


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
        in_window = sorted(
            (
                point
                for point in points
                if point.dataset_id == dataset.dataset_id
                and plan.window_start <= point.finished_at <= plan.as_of
            ),
            key=lambda item: (item.finished_at, item.backup_id),
        )
        if not in_window:
            results.append(
                RpoResult(
                    dataset_id=dataset.dataset_id,
                    status="no_points",
                    rpo_minutes=dataset.rpo_minutes,
                    point_count=0,
                    max_gap_minutes=None,
                    gap_from=None,
                    gap_to=None,
                    last_point_at=None,
                    minutes_since_last_point=None,
                )
            )
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
        gaps: list[tuple[int, RestorablePoint, RestorablePoint | None]] = []
        for left, right in zip(in_window, in_window[1:]):
            gaps.append((minutes_between(left.finished_at, right.finished_at), left, right))
        last = in_window[-1]
        since_last = minutes_between(last.finished_at, plan.as_of)
        gaps.append((since_last, last, None))
        max_gap, gap_from, gap_to = max(gaps, key=lambda item: (item[0], item[1].finished_at))
        breach = max_gap > dataset.rpo_minutes
        results.append(
            RpoResult(
                dataset_id=dataset.dataset_id,
                status="breach" if breach else "pass",
                rpo_minutes=dataset.rpo_minutes,
                point_count=len(in_window),
                max_gap_minutes=max_gap,
                gap_from=format_utc(gap_from.finished_at),
                gap_to=format_utc(gap_to.finished_at) if gap_to else format_utc(plan.as_of),
                last_point_at=format_utc(last.finished_at),
                minutes_since_last_point=since_last,
            )
        )
        if breach:
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
                        "max_gap_minutes": max_gap,
                        "gap_from": format_utc(gap_from.finished_at),
                        "gap_to": format_utc(gap_to.finished_at) if gap_to else format_utc(plan.as_of),
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
    drill_status: Mapping[str, str] | None = None,
) -> tuple[tuple[RtoResult, ...], tuple[Finding, ...]]:
    """Measure wall-clock drill duration including failed attempts.

    Duration always spans the first attempt through the last finish, so failed
    retries count toward RTO. Only a drill proven successful can pass; an
    inconclusive drill with valid duration is reported as ``not_met``.
    """
    datasets = plan.dataset_map()
    grouped: dict[str, list[DrillEvent]] = {}
    for event in events:
        grouped.setdefault(event.drill_id, []).append(event)
    results: list[RtoResult] = []
    findings: list[Finding] = []
    drill_status = drill_status or {}
    for drill_id in sorted(grouped):
        drill_events = grouped[drill_id]
        started = min(event.started_at for event in drill_events)
        finished = max(event.finished_at for event in drill_events)
        dataset_id = drill_events[0].dataset_id
        backup_id = drill_events[0].backup_id
        duration = minutes_between(started, finished)
        target = datasets[dataset_id].rto_minutes
        successful = bool(drill_success.get(drill_id, False))
        conclusion = drill_status.get(drill_id, "failed" if not successful else "success")
        status = "breach" if duration > target else ("pass" if successful else "not_met")
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
                        "drill_status": conclusion,
                    },
                    drill_hash,
                )
            )
    return tuple(results), tuple(findings)
