"""Typed domain objects shared by validation, analysis, reporting and the ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
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
class PricingStep:
    """One tiered-price step; ``up_to_mb`` is None for the unbounded final step."""

    up_to_mb: Decimal | None
    per_mb: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {
            "up_to_mb": str(self.up_to_mb) if self.up_to_mb is not None else None,
            "per_mb": str(self.per_mb),
        }


@dataclass(frozen=True)
class TierPricing:
    """Exact decimal price ladder plus the minimum fee for one storage tier."""

    steps: tuple[PricingStep, ...]
    min_fee: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {"steps": [step.to_dict() for step in self.steps], "min_fee": str(self.min_fee)}


@dataclass(frozen=True)
class ChargebackConfig:
    """Authorized storage-billing configuration from the recovery plan."""

    inventory_path: str
    currency: str
    max_teams: int
    max_subsets: int
    pricing: dict[str, TierPricing]

    def to_dict(self) -> dict[str, Any]:
        return {
            "inventory_path": self.inventory_path,
            "currency": self.currency,
            "max_teams": self.max_teams,
            "max_subsets": self.max_subsets,
            "pricing": {tier: self.pricing[tier].to_dict() for tier in sorted(self.pricing)},
        }


@dataclass(frozen=True)
class RecoveryPlan:
    as_of: datetime
    analysis_window_days: int
    datasets: tuple[DatasetConfig, ...]
    plan_path: str

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
        }
