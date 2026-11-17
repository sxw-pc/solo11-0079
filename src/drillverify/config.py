"""Recovery-plan loading and strict configuration validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml

from .models import ChargebackConfig, DatasetConfig, FileFingerprint, Finding, PricingStep, RecoveryPlan, TierPricing
from .paths import UnsafePath, normalize_relative, resolve_under, safe_relative, sha256_file
from .timeutil import TimestampError, parse_utc

_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_STEP_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_REQUIRED_DATASET = (
    "dataset_id",
    "display_name",
    "rpo_minutes",
    "rto_minutes",
    "required_steps",
    "checksum_required",
    "rowcount_required",
    "owner_team",
    "maintenance_window",
    "artifact_manifest_path",
)


@dataclass(frozen=True)
class PlanLoad:
    plan: RecoveryPlan | None
    findings: tuple[Finding, ...]
    fingerprint: FileFingerprint | None
    chargeback: ChargebackConfig | None = None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _decimal(value: object) -> Decimal | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    try:
        parsed = Decimal(value.strip())
    except InvalidOperation:
        return None
    return parsed if parsed.is_finite() else None


def _pricing(raw: object, prefix: str, issue: Any) -> TierPricing | None:
    def bad(message: str) -> None:
        issue("BILL-007", f"{prefix}: {message}", "chargeback")

    if not isinstance(raw, dict):
        return bad("must be a mapping")
    min_fee, steps_raw = _decimal(raw.get("min_fee", 0)), raw.get("steps")
    if min_fee is None or min_fee < 0 or not isinstance(steps_raw, list) or not steps_raw:
        return bad("min_fee must be non-negative and steps a non-empty list")
    steps: list[PricingStep] = []
    previous = Decimal(0)
    for index, item in enumerate(steps_raw):
        per_mb = _decimal(item.get("per_mb")) if isinstance(item, dict) else None
        if per_mb is None or per_mb < 0:
            return bad("per_mb must be a non-negative decimal")
        up_to = _decimal(item.get("up_to_mb")) if item.get("up_to_mb") is not None else None
        if item.get("up_to_mb") is not None and (up_to is None or up_to <= previous):
            return bad("up_to_mb must be positive and strictly ascending")
        if up_to is None and index != len(steps_raw) - 1:
            return bad("only the final step may be unbounded")
        previous = up_to if up_to is not None else previous
        steps.append(PricingStep(up_to, per_mb))
    if steps[-1].up_to_mb is not None:
        return bad("the final step must be unbounded")
    return TierPricing(tuple(steps), min_fee)


def _parse_chargeback(raw: object, issue: Any, root: Path) -> ChargebackConfig | None:
    def bad(message: str) -> None:
        issue("BILL-007", f"chargeback: {message}", "chargeback")

    if raw is None:
        return None
    if not isinstance(raw, dict):
        return bad("must be a mapping")
    try:
        inventory_path = normalize_relative(raw.get("inventory_path"), field="chargeback.inventory_path")
        resolve_under(root, inventory_path, field="chargeback.inventory_path")
    except UnsafePath as exc:
        return bad(str(exc))
    currency = raw.get("currency", "units")
    max_teams = raw.get("max_teams", 8)
    max_subsets = raw.get("max_subsets", 256)
    if not isinstance(currency, str) or not currency.strip():
        return bad("currency must be a non-empty string")
    if not _is_int(max_teams) or not 1 <= max_teams <= 12 or not _is_int(max_subsets) or not 2 <= max_subsets <= 65536:
        return bad("max_teams (1..12) or max_subsets (2..65536) is out of range")
    pricing_raw = raw.get("pricing")
    if not isinstance(pricing_raw, dict) or "default" not in pricing_raw:
        return bad("pricing must define a 'default' tier")
    pricing: dict[str, TierPricing] = {}
    for tier in sorted(pricing_raw):
        if not isinstance(tier, str) or not tier.strip():
            return bad("pricing tier names must be non-empty strings")
        parsed = _pricing(pricing_raw[tier], f"chargeback.pricing.{tier}", issue)
        if parsed is None:
            return None
        pricing[tier] = parsed
    return ChargebackConfig(inventory_path, currency.strip(), max_teams, max_subsets, pricing)


def _fingerprint(root: Path, path: Path) -> FileFingerprint | None:
    if not path.is_file():
        return None
    return FileFingerprint(
        path=safe_relative(root, path),
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
    )


def load_plan(plan_path: Path, fixtures_root: Path) -> PlanLoad:
    """Load and validate recovery_plan.yaml without executing any write."""
    root = fixtures_root.resolve()
    path = plan_path.resolve()
    findings: list[Finding] = []
    try:
        rel_path = safe_relative(root, path)
    except ValueError:
        rel_path = path.name
        findings.append(
            Finding(
                "CFG-004",
                "critical",
                "plan",
                path.name,
                "Recovery plan must live under the fixture root.",
                rel_path,
            )
        )
        return PlanLoad(None, tuple(findings), None)

    fingerprint = _fingerprint(root, path)
    if fingerprint is None:
        findings.append(
            Finding(
                "CFG-001",
                "critical",
                "plan",
                rel_path,
                "Recovery plan file does not exist.",
                rel_path,
            )
        )
        return PlanLoad(None, tuple(findings), None)

    file_hash = fingerprint.sha256

    def issue(rule: str, message: str, object_id: str, **evidence: Any) -> None:
        findings.append(
            Finding(
                rule,
                "error",
                "plan",
                object_id,
                message,
                rel_path,
                0,
                evidence,
                file_hash,
            )
        )

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        issue("CFG-001", f"Recovery plan cannot be parsed: {type(exc).__name__}.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    if not isinstance(raw, dict):
        issue("CFG-001", "Recovery plan root must be a mapping.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    as_of_raw = raw.get("as_of")
    try:
        as_of = parse_utc(as_of_raw, require_z=True)
    except TimestampError as exc:
        issue("CFG-001", f"as_of is invalid: {exc}.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    window = raw.get("analysis_window_days")
    if not _is_int(window) or not 1 <= window <= 365:
        issue("CFG-001", "analysis_window_days must be an integer from 1 to 365.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    datasets_raw = raw.get("datasets")
    if not isinstance(datasets_raw, list) or not datasets_raw:
        issue("CFG-003", "At least one dataset declaration is required.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    datasets: list[DatasetConfig] = []
    seen: set[str] = set()
    for index, item in enumerate(datasets_raw):
        prefix = f"datasets[{index}]"
        if not isinstance(item, dict):
            issue("CFG-001", f"{prefix} must be a mapping.", prefix)
            continue
        missing = [name for name in _REQUIRED_DATASET if name not in item]
        if missing:
            issue("CFG-001", f"{prefix} misses fields: {', '.join(missing)}.", prefix)
            continue
        dataset_id = item.get("dataset_id")
        if not isinstance(dataset_id, str) or not _ID_RE.fullmatch(dataset_id):
            issue("CFG-001", f"{prefix}.dataset_id is invalid.", str(dataset_id))
            continue
        if dataset_id in seen:
            issue("CFG-002", f"Dataset {dataset_id} is declared more than once.", dataset_id)
            continue
        seen.add(dataset_id)
        display_name = item.get("display_name")
        owner = item.get("owner_team")
        window_label = item.get("maintenance_window")
        if not isinstance(display_name, str) or not display_name.strip():
            issue("CFG-001", "display_name must be a non-empty string.", dataset_id)
            continue
        if not isinstance(owner, str) or not owner.strip():
            issue("CFG-001", "owner_team must be a non-empty string.", dataset_id)
            continue
        if not isinstance(window_label, str) or not window_label.strip():
            issue("CFG-001", "maintenance_window must be a non-empty string.", dataset_id)
            continue
        rpo, rto = item.get("rpo_minutes"), item.get("rto_minutes")
        if not _is_int(rpo) or not 1 <= rpo <= 525600:
            issue("CFG-001", "rpo_minutes must be a positive integer.", dataset_id)
            continue
        if not _is_int(rto) or not 1 <= rto <= 525600:
            issue("CFG-001", "rto_minutes must be a positive integer.", dataset_id)
            continue
        steps = item.get("required_steps")
        if (
            not isinstance(steps, list)
            or not steps
            or len(set(map(str, steps))) != len(steps)
            or any(not isinstance(step, str) or not _STEP_RE.fullmatch(step) for step in steps)
        ):
            issue("CFG-001", "required_steps must be unique lowercase step identifiers.", dataset_id)
            continue
        checksum, rowcount = item.get("checksum_required"), item.get("rowcount_required")
        if not isinstance(checksum, bool) or not isinstance(rowcount, bool):
            issue("CFG-001", "checksum_required and rowcount_required must be booleans.", dataset_id)
            continue
        try:
            manifest_dir = resolve_under(
                root,
                item.get("artifact_manifest_path"),
                field="artifact_manifest_path",
            )
        except UnsafePath as exc:
            issue("CFG-004", str(exc), dataset_id)
            continue
        if not manifest_dir.is_dir():
            issue(
                "ART-001",
                "Artifact manifest directory does not exist.",
                dataset_id,
                artifact_manifest_path=item.get("artifact_manifest_path"),
            )
        datasets.append(
            DatasetConfig(
                dataset_id=dataset_id,
                display_name=display_name.strip(),
                rpo_minutes=rpo,
                rto_minutes=rto,
                required_steps=tuple(steps),
                checksum_required=checksum,
                rowcount_required=rowcount,
                owner_team=owner.strip(),
                maintenance_window=window_label.strip(),
                artifact_manifest_path=str(item["artifact_manifest_path"]),
            )
        )

    if not datasets:
        issue("CFG-003", "No valid dataset declaration remains.", rel_path)
        return PlanLoad(None, tuple(findings), fingerprint)

    chargeback = _parse_chargeback(raw.get("chargeback"), issue, root)
    plan = RecoveryPlan(
        as_of=as_of,
        analysis_window_days=window,
        datasets=tuple(sorted(datasets, key=lambda item: item.dataset_id)),
        plan_path=rel_path,
    )
    return PlanLoad(plan, tuple(sorted(findings, key=Finding.sort_key)), fingerprint, chargeback)
