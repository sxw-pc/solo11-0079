"""Typed domain objects shared by validation, analysis, reporting and the ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .rules import SEVERITY_RANK
from .timeutil import format_utc


@dataclass(frozen=True)
class FileFingerprint:
    path: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "size_bytes": self.size_bytes}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    object_type: str
    object_id: str
    message: str
    file: str = ""
    line: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    input_sha256: str = ""

    def sort_key(self) -> tuple[Any, ...]:
        return (
            SEVERITY_RANK.get(self.severity, 99),
            self.rule_id,
            self.object_type,
            self.object_id,
            self.file,
            self.line,
            self.message,
        )

    def dedupe_key(self) -> tuple[Any, ...]:
        return (self.rule_id, self.object_type, self.object_id, self.file, self.line)

    def probe(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "input_sha256": self.input_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "input_sha256": self.input_sha256,
            "evidence": {k: self.evidence[k] for k in sorted(self.evidence)},
        }


@dataclass(frozen=True)
class ColumnDecl:
    """One declared column of a versioned schema contract."""

    name: str
    type: str
    required: bool
    key_role: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type, "required": self.required, "key_role": self.key_role}


@dataclass(frozen=True)
class SchemaContract:
    """The declared shape of one schema version."""

    version: str
    columns: tuple[ColumnDecl, ...]

    def column_map(self) -> dict[str, ColumnDecl]:
        return {column.name: column for column in self.columns}

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "columns": [item.to_dict() for item in self.columns]}


@dataclass(frozen=True)
class ColumnMap:
    """One declarative source-to-target column mapping of a migration edge."""

    source: str
    target: str
    transform: str
    range_proof: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "target": self.target, "transform": self.transform, "range_proof": self.range_proof}


@dataclass(frozen=True)
class MigrationEdge:
    """A declarative, code-free migration step between two schema versions."""

    edge_id: str
    from_version: str
    to_version: str
    column_maps: tuple[ColumnMap, ...] = ()
    dropped_columns: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "column_maps": [item.to_dict() for item in self.column_maps],
            "dropped_columns": list(self.dropped_columns),
        }


@dataclass(frozen=True)
class SchemaMigrationConfig:
    """The plan-declared restore target, purpose, contracts and edges."""

    target_version: str
    purpose: str
    contracts: tuple[SchemaContract, ...]
    edges: tuple[MigrationEdge, ...]

    def contract_map(self) -> dict[str, SchemaContract]:
        return {contract.version: contract for contract in self.contracts}

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_version": self.target_version,
            "purpose": self.purpose,
            "contracts": [item.to_dict() for item in self.contracts],
            "edges": [item.to_dict() for item in self.edges],
        }


@dataclass(frozen=True)
class DatasetConfig:
    dataset_id: str
    display_name: str
    rpo_minutes: int
    rto_minutes: int
    required_steps: tuple[str, ...]
    checksum_required: bool
    rowcount_required: bool
    owner_team: str
    maintenance_window: str
    artifact_manifest_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "display_name": self.display_name,
            "rpo_minutes": self.rpo_minutes,
            "rto_minutes": self.rto_minutes,
            "required_steps": list(self.required_steps),
            "checksum_required": self.checksum_required,
            "rowcount_required": self.rowcount_required,
            "owner_team": self.owner_team,
            "maintenance_window": self.maintenance_window,
            "artifact_manifest_path": self.artifact_manifest_path,
        }


@dataclass(frozen=True)
class RecoveryPlan:
    as_of: datetime
    analysis_window_days: int
    datasets: tuple[DatasetConfig, ...]
    plan_path: str
    schema_migration: SchemaMigrationConfig | None = None

    @property
    def window_start(self) -> datetime:
        from datetime import timedelta

        return self.as_of - timedelta(days=self.analysis_window_days)

    def dataset_map(self) -> dict[str, DatasetConfig]:
        return {dataset.dataset_id: dataset for dataset in self.datasets}

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": format_utc(self.as_of),
            "analysis_window_days": self.analysis_window_days,
            "window_start": format_utc(self.window_start),
            "datasets": [dataset.to_dict() for dataset in self.datasets],
            "plan_path": self.plan_path,
            "schema_migration": self.schema_migration.to_dict() if self.schema_migration else None,
        }
