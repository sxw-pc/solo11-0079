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
        }


@dataclass(frozen=True)
class AssignmentWitness:
    """One complete legal attribution with its net-gap certificate."""

    assignments: tuple[tuple[str, str], ...]
    total_gap: int
    transaction_gaps: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assignments": [
                {"part_id": part, "anchor": anchor} for part, anchor in self.assignments
            ],
            "total_gap": self.total_gap,
            "transaction_gaps": [
                {"anchor": anchor, "gap": gap} for anchor, gap in self.transaction_gaps
            ],
        }


@dataclass(frozen=True)
class CohortProof:
    """Exact min/max net gap over every legal attribution of a cohort."""

    status: str
    cause: str
    contribution_count: int
    transaction_count: int
    nodes_explored: int
    assignments_evaluated: int
    budget: int
    min_gap: int | None
    max_gap: int | None
    min_witness: AssignmentWitness | None
    max_witness: AssignmentWitness | None
    conserving_witnesses: tuple[AssignmentWitness, ...]
    unassigned_part_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "cause": self.cause,
            "contribution_count": self.contribution_count,
            "transaction_count": self.transaction_count,
            "nodes_explored": self.nodes_explored,
            "assignments_evaluated": self.assignments_evaluated,
            "budget": self.budget,
            "min_gap": self.min_gap,
            "max_gap": self.max_gap,
            "min_witness": self.min_witness.to_dict() if self.min_witness else None,
            "max_witness": self.max_witness.to_dict() if self.max_witness else None,
            "conserving_witnesses": [item.to_dict() for item in self.conserving_witnesses],
            "unassigned_part_ids": list(self.unassigned_part_ids),
        }


@dataclass(frozen=True)
class CohortMemberResult:
    dataset_id: str
    backup_id: str
    finished_at: str
    manifest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "finished_at": self.finished_at,
            "manifest_sha256": self.manifest_sha256,
        }


@dataclass(frozen=True)
class CohortResult:
    """Verdict for one cohort, grounded only in its transaction summaries."""

    cohort_id: str
    purpose: str
    status: str
    cause: str
    members: tuple[CohortMemberResult, ...]
    contribution_count: int
    proof: CohortProof | None
    publish_gate: str
    manual_verification_required: bool
    evidence_basis: str
    evidence_window_end: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort_id": self.cohort_id,
            "purpose": self.purpose,
            "status": self.status,
            "cause": self.cause,
            "detail": self.detail,
            "members": [item.to_dict() for item in self.members],
            "contribution_count": self.contribution_count,
            "publish_gate": self.publish_gate,
            "manual_verification_required": self.manual_verification_required,
            "evidence_basis": self.evidence_basis,
            "evidence_window_end": self.evidence_window_end,
            "proof": self.proof.to_dict() if self.proof else None,
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
        }
