"""Result types for chains, objectives, drill assessments and chargeback."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from fractions import Fraction
from typing import Any

from .models import ChargebackConfig, Finding
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


def format_decimal(value: Decimal) -> str:
    """Render an exact decimal without scientific notation or trailing zeros."""
    if value == value.to_integral_value():
        return str(value.quantize(Decimal(1)))
    return format(value.normalize(), "f")


def format_amount(value: Fraction) -> str:
    """Exact amount string: terminating decimal when possible, else num/den."""
    denominator, twos, fives = value.denominator, 0, 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        return f"{value.numerator}/{value.denominator}"
    scale = max(twos, fives)
    scaled = value.numerator * 2 ** (scale - twos) * 5 ** (scale - fives)
    sign, digits = ("-" if scaled < 0 else ""), str(abs(scaled)).rjust(scale + 1, "0")
    if not scale:
        return f"{sign}{digits}"
    return f"{sign}{digits[:-scale]}.{digits[-scale:]}".rstrip("0").rstrip(".")


@dataclass(frozen=True)
class BucketBill:
    period: str
    tier: str
    block_ids: tuple[str, ...]
    union_bytes: int
    invoice: Decimal

    def to_dict(self) -> dict[str, Any]:
        return {
            "period": self.period,
            "tier": self.tier,
            "block_ids": list(self.block_ids),
            "union_bytes": self.union_bytes,
            "invoice": format_decimal(self.invoice),
        }


@dataclass(frozen=True)
class TeamCharge:
    team: str
    amount: Fraction
    witnesses: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "team": self.team,
            "amount": format_amount(self.amount),
            "witnesses": list(self.witnesses),
        }


@dataclass(frozen=True)
class ContractSettlement:
    contract: str
    status: str
    reason: str | None
    total: Fraction | None
    teams: tuple[TeamCharge, ...]

    def to_dict(self) -> dict[str, Any]:
        settled = self.status == "settled" and self.total is not None
        return {
            "contract": self.contract,
            "status": self.status,
            "reason": self.reason,
            "total": format_amount(self.total) if self.total is not None else None,
            "budget_balanced": settled and self.total == sum((c.amount for c in self.teams), Fraction(0)),
            "non_negative": settled and all(c.amount >= 0 for c in self.teams),
            "teams": [c.to_dict() for c in self.teams],
        }


@dataclass(frozen=True)
class ChargebackReport:
    status: str
    findings: tuple[Finding, ...]
    logical_bytes: int
    team_logical_bytes: tuple[tuple[str, int], ...]
    buckets: tuple[BucketBill, ...] | None
    total_invoice: Decimal | None
    contracts: tuple[ContractSettlement, ...]
    currency: str
    config: ChargebackConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        physical = None
        if self.buckets is not None:
            physical = {
                "total_invoice": format_decimal(self.total_invoice),
                "buckets": [bucket.to_dict() for bucket in self.buckets],
            }
        return {
            "status": self.status,
            "currency": self.currency,
            "config": self.config.to_dict() if self.config else None,
            "logical_bytes": self.logical_bytes,
            "team_logical_bytes": [
                {"team": team, "logical_bytes": size} for team, size in self.team_logical_bytes
            ],
            "physical": physical,
            "contracts": [contract.to_dict() for contract in self.contracts],
            "findings": [finding.to_dict() for finding in self.findings],
        }
