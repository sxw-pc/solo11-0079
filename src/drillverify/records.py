"""Input record types retained after validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .timeutil import format_utc


@dataclass(frozen=True)
class BackupRecord:
    dataset_id: str
    backup_id: str
    parent_backup_id: str | None
    backup_type: str
    started_at: datetime
    finished_at: datetime
    artifact_path: str
    artifact_size_bytes: int
    sha256: str
    row_count: int
    schema_version: str
    line_no: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "parent_backup_id": self.parent_backup_id,
            "backup_type": self.backup_type,
            "started_at": format_utc(self.started_at),
            "finished_at": format_utc(self.finished_at),
            "artifact_path": self.artifact_path,
            "artifact_size_bytes": self.artifact_size_bytes,
            "sha256": self.sha256,
            "row_count": self.row_count,
            "schema_version": self.schema_version,
            "line": self.line_no,
        }


@dataclass(frozen=True)
class DrillEvent:
    drill_id: str
    dataset_id: str
    backup_id: str
    step: str
    status: str
    attempt: int
    started_at: datetime
    finished_at: datetime
    evidence_ref: str
    detail: str
    rows_restored: int | None
    reported_sha256: str | None
    line_no: int
    recovery_generation: str | None = None
    data_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "drill_id": self.drill_id,
            "dataset_id": self.dataset_id,
            "backup_id": self.backup_id,
            "step": self.step,
            "status": self.status,
            "attempt": self.attempt,
            "started_at": format_utc(self.started_at),
            "finished_at": format_utc(self.finished_at),
            "evidence_ref": self.evidence_ref,
            "detail": self.detail,
            "rows_restored": self.rows_restored,
            "reported_sha256": self.reported_sha256,
            "recovery_generation": self.recovery_generation,
            "data_digest": self.data_digest,
            "line": self.line_no,
        }


@dataclass(frozen=True)
class ArtifactManifest:
    backup_id: str
    row_count: int
    data_sha256: str
    schema_version: str
    path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "row_count": self.row_count,
            "data_sha256": self.data_sha256,
            "schema_version": self.schema_version,
            "path": self.path,
        }


@dataclass(frozen=True)
class ArtifactCheck:
    backup_id: str
    artifact_ready: bool
    manifest: ArtifactManifest | None
    failure_rules: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "artifact_ready": self.artifact_ready,
            "manifest": self.manifest.to_dict() if self.manifest else None,
            "failure_rules": list(self.failure_rules),
        }


@dataclass(frozen=True)
class EvidenceCheck:
    evidence_ref: str
    exists: bool
    readable: bool
    valid: bool
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_ref": self.evidence_ref,
            "exists": self.exists,
            "readable": self.readable,
            "valid": self.valid,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }
