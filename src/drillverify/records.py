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
            "dataset_id": self.dataset_id, "backup_id": self.backup_id,
            "parent_backup_id": self.parent_backup_id, "backup_type": self.backup_type,
            "started_at": format_utc(self.started_at),
            "finished_at": format_utc(self.finished_at),
            "artifact_path": self.artifact_path,
            "artifact_size_bytes": self.artifact_size_bytes, "sha256": self.sha256,
            "row_count": self.row_count, "schema_version": self.schema_version,
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
    def to_dict(self) -> dict[str, Any]:
        return {
            "drill_id": self.drill_id, "dataset_id": self.dataset_id,
            "backup_id": self.backup_id, "step": self.step, "status": self.status,
            "attempt": self.attempt, "started_at": format_utc(self.started_at),
            "finished_at": format_utc(self.finished_at),
            "evidence_ref": self.evidence_ref, "detail": self.detail,
            "rows_restored": self.rows_restored,
            "reported_sha256": self.reported_sha256, "line": self.line_no,
        }
@dataclass(frozen=True)
class ShardSpec:
    """One declared XOR data/parity shard of a versioned sharded manifest."""
    shard_id: str
    coefficients: tuple[int, ...]
    path: str
    size_bytes: int
    sha256: str
    fault_domain: str
    def to_dict(self) -> dict[str, Any]:
        return {"shard_id": self.shard_id, "coefficients": list(self.coefficients),
                "path": self.path, "size_bytes": self.size_bytes,
                "sha256": self.sha256, "fault_domain": self.fault_domain}
@dataclass(frozen=True)
class ShardProof:
    """Reviewable per-shard verification and the GF(2) linear proof built on it."""
    shard_id: str
    fault_domain: str
    coefficients: tuple[int, ...]
    path: str
    declared_size: int
    actual_size: int
    declared_sha256: str
    actual_sha256: str
    usable: bool
    failure_rules: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]:
        return {
            "shard_id": self.shard_id, "fault_domain": self.fault_domain,
            "coefficients": list(self.coefficients), "path": self.path,
            "declared_size_bytes": self.declared_size,
            "actual_size_bytes": self.actual_size,
            "declared_sha256": self.declared_sha256,
            "actual_sha256": self.actual_sha256, "usable": self.usable,
            "failure_rules": list(self.failure_rules),
        }
@dataclass(frozen=True)
class ShardAssessment:
    """The full static proof for one versioned sharded manifest."""
    manifest_version: str
    stripe_count: int
    recovery_purpose: str
    shard_count: int
    usable_count: int
    rank: int
    basis_vectors: tuple[tuple[int, ...], ...]
    missing_dimensions: tuple[int, ...]
    witness_vectors: tuple[tuple[int, ...], ...]
    current_rebuildable: bool
    single_fault_tolerant: bool
    first_failed_domain: str | None
    first_failed_domain_rank: int | None
    shard_proofs: tuple[ShardProof, ...]
    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": self.manifest_version, "stripe_count": self.stripe_count,
            "recovery_purpose": self.recovery_purpose, "shard_count": self.shard_count,
            "usable_count": self.usable_count, "rank": self.rank,
            "basis_vectors": [list(v) for v in self.basis_vectors],
            "missing_dimensions": list(self.missing_dimensions),
            "witness_vectors": [list(v) for v in self.witness_vectors],
            "current_rebuildable": self.current_rebuildable,
            "single_fault_tolerant": self.single_fault_tolerant,
            "first_failed_domain": self.first_failed_domain,
            "first_failed_domain_remaining_rank": self.first_failed_domain_rank,
            "shard_proofs": [item.to_dict() for item in self.shard_proofs],
        }
@dataclass(frozen=True)
class ArtifactManifest:
    backup_id: str
    row_count: int
    data_sha256: str
    schema_version: str
    path: str
    manifest_version: str = "1"
    stripe_count: int | None = None
    recovery_purpose: str | None = None
    shards: tuple[ShardSpec, ...] = ()
    @property
    def is_sharded(self) -> bool:
        return self.manifest_version != "1"
    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id, "row_count": self.row_count,
            "data_sha256": self.data_sha256, "schema_version": self.schema_version,
            "path": self.path, "manifest_version": self.manifest_version,
            "stripe_count": self.stripe_count, "recovery_purpose": self.recovery_purpose,
            "shards": [item.to_dict() for item in self.shards],
        }
@dataclass(frozen=True)
class ArtifactCheck:
    backup_id: str
    artifact_ready: bool
    manifest: ArtifactManifest | None
    failure_rules: tuple[str, ...]
    shard_assessment: ShardAssessment | None = None
    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id, "artifact_ready": self.artifact_ready,
            "manifest": self.manifest.to_dict() if self.manifest else None,
            "failure_rules": list(self.failure_rules),
            "shard_assessment": self.shard_assessment.to_dict()
            if self.shard_assessment else None,
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
            "evidence_ref": self.evidence_ref, "exists": self.exists,
            "readable": self.readable, "valid": self.valid,
            "sha256": self.sha256, "size_bytes": self.size_bytes,
        }
