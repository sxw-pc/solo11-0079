"""Row-level catalog and drill validation with no silent drops."""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .loaders import CATALOG_COLUMNS, LoadedRows
from .models import Finding, RecoveryPlan
from .records import BackupRecord, DrillEvent
from .paths import UnsafePath, normalize_relative, resolve_under
from .timeutil import TimestampError, parse_utc
_ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
_STEP_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_EVENT_FIELDS = (
    "drill_id",
    "dataset_id",
    "backup_id",
    "step",
    "status",
    "attempt",
    "started_at",
    "finished_at",
    "evidence_ref",
    "detail",
    "rows_restored",
    "reported_sha256",
)
_EVENT_STATUS = {"success", "failed", "skipped"}
@dataclass(frozen=True)
class CatalogValidation:
    records: tuple[BackupRecord, ...]
    findings: tuple[Finding, ...]
    raw_count: int
    rejected_count: int
@dataclass(frozen=True)
class DrillValidation:
    events: tuple[DrillEvent, ...]
    findings: tuple[Finding, ...]
    raw_count: int
    rejected_count: int
def _as_int(value: object, *, minimum: int = 0) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= minimum else None
    if isinstance(value, str):
        try:
            parsed = int(value.strip(), 10)
        except ValueError:
            return None
        return parsed if parsed >= minimum else None
    return None
def validate_catalog(
    loaded: LoadedRows,
    plan: RecoveryPlan,
    fixtures_root: Path,
) -> CatalogValidation:
    """Validate catalog rows against schema, plan identities and safe paths."""
    file_hash = loaded.fingerprint.sha256 if loaded.fingerprint else ""
    datasets = plan.dataset_map()
    findings = list(loaded.findings)
    records: list[BackupRecord] = []
    claimed: set[str] = set()
    def issue(rule: str, object_id: str, message: str, line: int, **evidence: Any) -> None:
        findings.append(
            Finding(rule, "error", "backup", object_id, message, loaded.path, line, evidence, file_hash)
        )
    for line_no, raw in loaded.rows:
        missing = [name for name in CATALOG_COLUMNS if str(raw.get(name, "")).strip() == ""]
        optional_missing = [name for name in missing if name != "parent_backup_id"]
        backup_id = str(raw.get("backup_id", "")).strip() or f"line-{line_no}"
        if optional_missing:
            issue("IN-002", backup_id, f"Missing required values: {', '.join(optional_missing)}.", line_no)
            continue
        if not _ID_RE.fullmatch(backup_id):
            issue("IN-003", backup_id, "backup_id is not a valid lowercase identifier.", line_no)
            continue
        if backup_id in claimed:
            issue("IN-005", backup_id, "Duplicate backup_id; later row was rejected.", line_no)
            continue
        claimed.add(backup_id)
        dataset_id = str(raw.get("dataset_id", "")).strip()
        if dataset_id not in datasets:
            issue("IN-006", backup_id, f"Unknown dataset_id {dataset_id!r}.", line_no)
            continue
        backup_type = str(raw.get("backup_type", "")).strip()
        if backup_type not in {"full", "incremental"}:
            issue("IN-008", backup_id, f"Invalid backup_type {backup_type!r}.", line_no)
            continue
        parent_raw = str(raw.get("parent_backup_id", "")).strip()
        parent = parent_raw or None
        if backup_type == "full" and parent is not None:
            issue("IN-008", backup_id, "A full backup must not declare a parent.", line_no)
            continue
        if backup_type == "incremental" and parent is None:
            issue("IN-002", backup_id, "An incremental backup requires a parent_backup_id.", line_no)
            continue
        if parent is not None and not _ID_RE.fullmatch(parent):
            issue("IN-003", backup_id, "parent_backup_id has an invalid format.", line_no)
            continue
        size = _as_int(raw.get("artifact_size_bytes"))
        rows = _as_int(raw.get("row_count"))
        if size is None:
            issue("IN-003", backup_id, "artifact_size_bytes must be a non-negative integer.", line_no)
            continue
        if rows is None:
            issue("IN-003", backup_id, "row_count must be a non-negative integer.", line_no)
            continue
        digest = str(raw.get("sha256", "")).strip()
        if not _SHA_RE.fullmatch(digest):
            issue("IN-011", backup_id, "sha256 must be exactly 64 hexadecimal characters.", line_no)
            continue
        try:
            started = parse_utc(raw.get("started_at"))
            finished = parse_utc(raw.get("finished_at"))
        except TimestampError as exc:
            issue("IN-004", backup_id, f"Invalid backup timestamp: {exc}.", line_no)
            continue
        if finished < started:
            issue("IN-015", backup_id, "finished_at is earlier than started_at.", line_no)
            continue
        try:
            artifact_rel = normalize_relative(raw.get("artifact_path"), field="artifact_path")
            resolve_under(fixtures_root, artifact_rel, field="artifact_path")
        except UnsafePath as exc:
            issue("IN-009", backup_id, str(exc), line_no)
            continue
        schema_version = str(raw.get("schema_version", "")).strip()
        if not schema_version:
            issue("IN-002", backup_id, "schema_version is required.", line_no)
            continue
        if size == 0:
            findings.append(
                Finding(
                    "IN-003",
                    "warning",
                    "backup",
                    backup_id,
                    "Artifact size is zero; verify the synthetic artifact is intentional.",
                    loaded.path,
                    line_no,
                    {"artifact_size_bytes": 0},
                    file_hash,
                )
            )
        records.append(
            BackupRecord(
                dataset_id=dataset_id,
                backup_id=backup_id,
                parent_backup_id=parent,
                backup_type=backup_type,
                started_at=started,
                finished_at=finished,
                artifact_path=artifact_rel,
                artifact_size_bytes=size,
                sha256=digest.lower(),
                row_count=rows,
                schema_version=schema_version,
                line_no=line_no,
            )
        )
    ordered = sorted(records, key=lambda item: (item.dataset_id, item.finished_at, item.backup_id))
    return CatalogValidation(
        tuple(ordered),
        tuple(sorted(findings, key=Finding.sort_key)),
        len(loaded.rows),
        len(loaded.rows) - len(records),
    )
def _event_hash(loaded: LoadedRows) -> str:
    return loaded.fingerprint.sha256 if loaded.fingerprint else ""
def validate_drills(
    loaded: LoadedRows,
    plan: RecoveryPlan,
    backups: tuple[BackupRecord, ...],
    fixtures_root: Path,
) -> DrillValidation:
    """Validate drill event shape, references, enums and identity consistency."""
    file_hash = _event_hash(loaded)
    datasets = plan.dataset_map()
    backups_by_id = {item.backup_id: item for item in backups}
    findings = list(loaded.findings)
    events: list[DrillEvent] = []
    identities: dict[str, tuple[str, str]] = {}
    def issue(rule: str, object_id: str, message: str, line: int, **evidence: Any) -> None:
        findings.append(
            Finding(rule, "error", "drill_event", object_id, message, loaded.path, line, evidence, file_hash)
        )
    for line_no, raw in loaded.rows:
        drill_id = str(raw.get("drill_id", "")).strip() or f"line-{line_no}"
        missing = [name for name in _EVENT_FIELDS if name not in raw]
        if missing:
            issue("IN-002", drill_id, f"Missing required fields: {', '.join(missing)}.", line_no)
            continue
        if not _ID_RE.fullmatch(drill_id):
            issue("IN-003", drill_id, "drill_id is not a valid lowercase identifier.", line_no)
            continue
        dataset_id = str(raw.get("dataset_id", "")).strip()
        backup_id = str(raw.get("backup_id", "")).strip()
        step = str(raw.get("step", "")).strip()
        status = str(raw.get("status", "")).strip()
        if dataset_id not in datasets:
            issue("IN-006", drill_id, f"Unknown dataset_id {dataset_id!r}.", line_no)
            continue
        backup = backups_by_id.get(backup_id)
        if backup is None:
            issue("IN-007", drill_id, f"Unknown backup_id {backup_id!r}.", line_no)
            continue
        if backup.dataset_id != dataset_id:
            issue(
                "IN-014",
                drill_id,
                "Drill dataset does not own the referenced backup.",
                line_no,
                backup_id=backup_id,
                dataset_id=dataset_id,
            )
            continue
        if not _STEP_RE.fullmatch(step):
            issue("IN-003", drill_id, f"Invalid step identifier {step!r}.", line_no)
            continue
        if status not in _EVENT_STATUS:
            issue("IN-013", drill_id, f"Invalid drill status {status!r}.", line_no)
            continue
        attempt = _as_int(raw.get("attempt"), minimum=1)
        if attempt is None:
            issue("IN-003", drill_id, "attempt must be an integer greater than zero.", line_no)
            continue
        try:
            started = parse_utc(raw.get("started_at"))
            finished = parse_utc(raw.get("finished_at"))
        except TimestampError as exc:
            issue("IN-004", drill_id, f"Invalid drill timestamp: {exc}.", line_no)
            continue
        if finished < started:
            issue("IN-015", drill_id, "Drill step finished before it started.", line_no)
            continue
        evidence_raw = raw.get("evidence_ref")
        try:
            evidence_ref = normalize_relative(evidence_raw, field="evidence_ref")
            if not evidence_ref.startswith("evidence/"):
                raise UnsafePath("evidence_ref must point inside evidence/")
            resolve_under(fixtures_root, evidence_ref, field="evidence_ref")
        except UnsafePath as exc:
            code = "IN-009" if "traversal" in str(exc) or "absolute" in str(exc) else "IN-010"
            issue(code, drill_id, str(exc), line_no)
            continue
        rows_restored = raw.get("rows_restored")
        if rows_restored is not None:
            rows_restored = _as_int(rows_restored)
            if rows_restored is None:
                issue("IN-003", drill_id, "rows_restored must be null or a non-negative integer.", line_no)
                continue
        reported = raw.get("reported_sha256")
        if reported is not None:
            reported = str(reported).strip()
            if not _SHA_RE.fullmatch(reported):
                issue("IN-011", drill_id, "reported_sha256 must be null or 64 hex characters.", line_no)
                continue
            reported = reported.lower()
        detail = raw.get("detail")
        if not isinstance(detail, str):
            issue("IN-003", drill_id, "detail must be a string.", line_no)
            continue
        identity = identities.get(drill_id)
        if identity is None:
            identities[drill_id] = (dataset_id, backup_id)
        elif identity != (dataset_id, backup_id):
            issue("IN-014", drill_id, "Drill identity conflicts with earlier events.", line_no)
            continue
        events.append(
            DrillEvent(
                drill_id=drill_id,
                dataset_id=dataset_id,
                backup_id=backup_id,
                step=step,
                status=status,
                attempt=attempt,
                started_at=started,
                finished_at=finished,
                evidence_ref=evidence_ref,
                detail=detail,
                rows_restored=rows_restored,
                reported_sha256=reported,
                line_no=line_no,
            )
        )
    ordered = sorted(events, key=lambda item: (item.drill_id, item.started_at, item.step, item.attempt))
    return DrillValidation(
        tuple(ordered),
        tuple(sorted(findings, key=Finding.sort_key)),
        len(loaded.rows),
        len(loaded.rows) - len(events),
    )
