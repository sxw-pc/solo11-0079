"""Result types for chains, objectives and drill assessments."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .timeutil import format_utc


@dataclass(frozen=True)
class BackupChainResult:
    dataset_id: str
    backup_id: str
    parent_backup_id: str | None
    finished_at: str
    chain_complete: bool
    artifact_ready: bool
    restorable: bool
    failure_rules: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "parent_backup_id": self.parent_backup_id,
            "finished_at": self.finished_at,
            "chain_complete": self.chain_complete,
            "artifact_ready": self.artifact_ready,
            "restorable": self.restorable,
            "failure_rules": list(self.failure_rules),
        }


@dataclass(frozen=True)
class RestorablePoint:
    dataset_id: str
    backup_id: str
    finished_at: datetime
    row_count: int
    data_sha256: str
    schema_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "finished_at": format_utc(self.finished_at),
            "row_count": self.row_count,
            "data_sha256": self.data_sha256,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class RpoResult:
    dataset_id: str
    status: str
    rpo_minutes: int
    point_count: int
    max_gap_minutes: int | None
    gap_from: str | None
    gap_to: str | None
    last_point_at: str | None
    minutes_since_last_point: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "status": self.status,
            "rpo_minutes": self.rpo_minutes,
            "point_count": self.point_count,
            "max_gap_minutes": self.max_gap_minutes,
            "gap_from": self.gap_from,
            "gap_to": self.gap_to,
            "last_point_at": self.last_point_at,
            "minutes_since_last_point": self.minutes_since_last_point,
        }


@dataclass(frozen=True)
class RtoResult:
    drill_id: str
    dataset_id: str
    backup_id: str
    status: str
    rto_minutes: int
    duration_minutes: int
    started_at: str
    finished_at: str
    successful: bool
    drill_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "drill_id": self.drill_id,
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "status": self.status,
            "rto_minutes": self.rto_minutes,
            "duration_minutes": self.duration_minutes,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "successful": self.successful,
            "drill_status": self.drill_status,
        }


@dataclass(frozen=True)
class EvidenceDecision:
    """One audited adopt/invalidate decision for a successful step event."""

    drill_id: str
    step: str
    attempt: int
    line_no: int
    decision: str
    reason: str
    recovery_gen: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "drill_id": self.drill_id,
            "step": self.step,
            "attempt": self.attempt,
            "line": self.line_no,
            "decision": self.decision,
            "reason": self.reason,
            "recovery_gen": self.recovery_gen,
        }


@dataclass(frozen=True)
class DrillSummary:
    drill_id: str
    dataset_id: str
    backup_id: str
    status: str
    step_count: int
    required_step_count: int
    missing_steps: tuple[str, ...]
    failed_steps: tuple[str, ...]
    skipped_steps: tuple[str, ...]
    evidence_ok: bool
    recovery_gen: str | None
    evidence_decisions: tuple[EvidenceDecision, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "drill_id": self.drill_id,
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "status": self.status,
            "step_count": self.step_count,
            "required_step_count": self.required_step_count,
            "missing_steps": list(self.missing_steps),
            "failed_steps": list(self.failed_steps),
            "skipped_steps": list(self.skipped_steps),
            "evidence_ok": self.evidence_ok,
            "recovery_gen": self.recovery_gen,
            "evidence_decisions": [item.to_dict() for item in self.evidence_decisions],
        }
