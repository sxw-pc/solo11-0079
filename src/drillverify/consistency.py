"""Drill-step completeness and restored-data consistency checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, RecoveryPlan
from .records import ArtifactManifest, BackupRecord, DrillEvent
from .results import BackupChainResult, DrillSummary


@dataclass(frozen=True)
class DrillAssessment:
    summaries: tuple[DrillSummary, ...]
    findings: tuple[Finding, ...]
    success: dict[str, bool]


def _effective(events: list[DrillEvent]) -> dict[str, DrillEvent]:
    """Choose the highest attempt per step, breaking ties by physical line."""
    effective: dict[str, DrillEvent] = {}
    for event in events:
        current = effective.get(event.step)
        if current is None or (event.attempt, event.line_no) > (current.attempt, current.line_no):
            effective[event.step] = event
    return effective


def _finding(
    rule: str,
    severity: str,
    drill_id: str,
    message: str,
    path: str,
    line: int,
    file_hash: str,
    **evidence: Any,
) -> Finding:
    return Finding(rule, severity, "drill", drill_id, message, path, line, evidence, file_hash)


def assess_drills(
    plan: RecoveryPlan,
    events: tuple[DrillEvent, ...],
    backups: tuple[BackupRecord, ...],
    chains: tuple[BackupChainResult, ...],
    manifests: dict[str, ArtifactManifest],
    valid_evidence: set[str],
    drill_path: str,
    drill_hash: str,
) -> DrillAssessment:
    """Check mandatory steps, evidence, restorability and reconciliation values."""
    datasets = plan.dataset_map()
    backups_by_id = {item.backup_id: item for item in backups}
    chain_by_id = {item.backup_id: item for item in chains}
    grouped: dict[str, list[DrillEvent]] = {}
    for event in events:
        grouped.setdefault(event.drill_id, []).append(event)
    summaries: list[DrillSummary] = []
    findings: list[Finding] = []
    success: dict[str, bool] = {}

    for drill_id in sorted(grouped):
        drill_events = sorted(grouped[drill_id], key=lambda item: (item.started_at, item.step, item.attempt))
        effective = _effective(drill_events)
        first_line = drill_events[0].line_no
        dataset = datasets[drill_events[0].dataset_id]
        backup = backups_by_id[drill_events[0].backup_id]
        required = set(dataset.required_steps)
        missing = sorted(required - set(effective))
        failed = sorted(step for step in required if step in effective and effective[step].status == "failed")
        skipped = sorted(step for step in required if step in effective and effective[step].status == "skipped")
        unexpected = sorted(set(effective) - required)
        evidence_ok = all(event.evidence_ref in valid_evidence for event in drill_events)
        backup_ready = bool(chain_by_id.get(backup.backup_id) and chain_by_id[backup.backup_id].restorable)
        consistency_ok = True

        if missing:
            findings.append(
                _finding(
                    "EVID-004",
                    "high",
                    drill_id,
                    "Required drill steps are missing.",
                    drill_path,
                    first_line,
                    drill_hash,
                    missing_steps=missing,
                    required_steps=list(dataset.required_steps),
                )
            )
        if failed:
            findings.append(
                _finding(
                    "EVID-005",
                    "high",
                    drill_id,
                    "Required drill steps failed.",
                    drill_path,
                    first_line,
                    drill_hash,
                    failed_steps=failed,
                )
            )
        if skipped:
            findings.append(
                _finding(
                    "EVID-006",
                    "medium",
                    drill_id,
                    "Required drill steps were skipped.",
                    drill_path,
                    first_line,
                    drill_hash,
                    skipped_steps=skipped,
                )
            )
        retries = sorted(step for step in {event.step for event in drill_events} if sum(
            1 for event in drill_events if event.step == step
        ) > 1)
        if retries:
            findings.append(
                _finding(
                    "EVID-007",
                    "warning",
                    drill_id,
                    "Drill retried one or more steps; wall-clock RTO includes retries.",
                    drill_path,
                    first_line,
                    drill_hash,
                    retried_steps=retries,
                )
            )
        if unexpected:
            findings.append(
                _finding(
                    "EVID-008",
                    "info",
                    drill_id,
                    "Drill contains steps outside the required procedure.",
                    drill_path,
                    first_line,
                    drill_hash,
                    unexpected_steps=unexpected,
                )
            )
        if not backup_ready:
            findings.append(
                _finding(
                    "EVID-009",
                    "high",
                    drill_id,
                    "Drill references a backup that is not a restorable point.",
                    drill_path,
                    first_line,
                    drill_hash,
                    backup_id=backup.backup_id,
                )
            )

        manifest = manifests.get(backup.backup_id)
        expected_rows = manifest.row_count if manifest else backup.row_count
        expected_sha = manifest.data_sha256 if manifest else None
        row_event = effective.get("verify_rowcount")
        sha_event = effective.get("verify_checksum")
        if row_event and row_event.rows_restored is not None and row_event.rows_restored != expected_rows:
            consistency_ok = False
            findings.append(
                _finding(
                    "CONS-001",
                    "high",
                    drill_id,
                    "Restored row count does not match the artifact manifest.",
                    drill_path,
                    row_event.line_no,
                    drill_hash,
                    backup_id=backup.backup_id,
                    expected=expected_rows,
                    actual=row_event.rows_restored,
                )
            )
        if sha_event and sha_event.reported_sha256 is not None and expected_sha is not None:
            if sha_event.reported_sha256 != expected_sha:
                consistency_ok = False
                findings.append(
                    _finding(
                        "CONS-002",
                        "high",
                        drill_id,
                        "Restored checksum does not match the artifact manifest.",
                        drill_path,
                        sha_event.line_no,
                        drill_hash,
                        backup_id=backup.backup_id,
                        expected=expected_sha,
                        actual=sha_event.reported_sha256,
                    )
                )
        if dataset.rowcount_required and not (
            row_event and row_event.rows_restored is not None and row_event.status == "success"
        ):
            consistency_ok = False
            findings.append(
                _finding(
                    "CONS-003",
                    "medium",
                    drill_id,
                    "A required row-count verification value is unavailable.",
                    drill_path,
                    row_event.line_no if row_event else first_line,
                    drill_hash,
                )
            )
        if dataset.checksum_required and not (
            sha_event and sha_event.reported_sha256 is not None and sha_event.status == "success"
        ):
            consistency_ok = False
            findings.append(
                _finding(
                    "CONS-004",
                    "medium",
                    drill_id,
                    "A required checksum verification value is unavailable.",
                    drill_path,
                    sha_event.line_no if sha_event else first_line,
                    drill_hash,
                )
            )

        drill_ok = (
            not missing
            and not failed
            and not skipped
            and evidence_ok
            and backup_ready
            and consistency_ok
        )
        success[drill_id] = drill_ok
        summaries.append(
            DrillSummary(
                drill_id=drill_id,
                dataset_id=dataset.dataset_id,
                backup_id=backup.backup_id,
                status="success" if drill_ok else "failed",
                step_count=len(drill_events),
                required_step_count=len(dataset.required_steps),
                missing_steps=tuple(missing),
                failed_steps=tuple(failed),
                skipped_steps=tuple(skipped),
                evidence_ok=evidence_ok,
            )
        )

    return DrillAssessment(
        tuple(sorted(summaries, key=lambda item: item.drill_id)),
        tuple(sorted(findings, key=Finding.sort_key)),
        success,
    )
