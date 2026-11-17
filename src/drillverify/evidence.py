"""Artifact, manifest and drill-evidence integrity checks."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .models import FileFingerprint, Finding, RecoveryPlan
from .paths import UnsafePath, resolve_under, safe_relative, sha256_file
from .records import ArtifactCheck, ArtifactManifest, BackupRecord, DrillEvent, EvidenceCheck
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
@dataclass(frozen=True)
class ArtifactAssessment:
    checks: tuple[ArtifactCheck, ...]
    manifests: dict[str, ArtifactManifest]
    findings: tuple[Finding, ...]
    files: tuple[FileFingerprint, ...]
    def ready_ids(self) -> set[str]:
        """Backup ids whose artifact passed every integrity check."""
        return {item.backup_id for item in self.checks if item.artifact_ready}
@dataclass(frozen=True)
class EvidenceAssessment:
    checks: tuple[EvidenceCheck, ...]
    findings: tuple[Finding, ...]
    files: tuple[FileFingerprint, ...]
    def ok_refs(self) -> set[str]:
        return {item.evidence_ref for item in self.checks if item.valid}
def _as_nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
def _artifact_finding(
    rule: str,
    severity: str,
    backup: BackupRecord,
    message: str,
    file: str,
    file_hash: str,
    **evidence: Any,
) -> Finding:
    return Finding(
        rule,
        severity,
        "backup",
        backup.backup_id,
        message,
        file,
        0,
        {"dataset_id": backup.dataset_id, **evidence},
        file_hash,
    )
def assess_artifacts(
    backups: tuple[BackupRecord, ...],
    plan: RecoveryPlan,
    fixtures_root: Path,
) -> ArtifactAssessment:
    """Verify catalog artifacts and their per-backup manifests."""
    root = fixtures_root.resolve()
    datasets = plan.dataset_map()
    checks: list[ArtifactCheck] = []
    manifests: dict[str, ArtifactManifest] = {}
    findings: list[Finding] = []
    files: list[FileFingerprint] = []
    for backup in sorted(backups, key=lambda item: (item.dataset_id, item.backup_id)):
        catalog_hash = ""
        failure_rules: list[str] = []
        artifact_path = ""
        try:
            artifact_abs = resolve_under(root, backup.artifact_path, field="artifact_path")
            artifact_path = safe_relative(root, artifact_abs)
        except UnsafePath:
            artifact_abs = Path()
        artifact_file_hash = ""
        if not artifact_abs.is_file():
            failure_rules.append("ART-003")
            findings.append(
                _artifact_finding(
                    "ART-003", "high", backup, "Artifact file is missing.", artifact_path, catalog_hash
                )
            )
        else:
            artifact_file_hash = sha256_file(artifact_abs)
            size = artifact_abs.stat().st_size
            files.append(
                FileFingerprint(artifact_path, artifact_file_hash, size)
            )
            if size != backup.artifact_size_bytes:
                failure_rules.append("ART-004")
                findings.append(
                    _artifact_finding(
                        "ART-004",
                        "high",
                        backup,
                        "Artifact size does not match the catalog.",
                        artifact_path,
                        artifact_file_hash,
                        expected=backup.artifact_size_bytes,
                        actual=size,
                    )
                )
            if artifact_file_hash != backup.sha256:
                failure_rules.append("ART-005")
                findings.append(
                    _artifact_finding(
                        "ART-005",
                        "critical",
                        backup,
                        "Artifact SHA-256 does not match the catalog.",
                        artifact_path,
                        artifact_file_hash,
                        expected=backup.sha256,
                        actual=artifact_file_hash,
                    )
                )
        manifest_dir_raw = datasets[backup.dataset_id].artifact_manifest_path
        try:
            manifest_dir = resolve_under(root, manifest_dir_raw, field="artifact_manifest_path")
            manifest_path = manifest_dir / f"manifest-{backup.backup_id}.json"
            manifest_rel = safe_relative(root, manifest_path)
        except UnsafePath:
            manifest_path = Path()
            manifest_rel = manifest_dir_raw
        manifest: ArtifactManifest | None = None
        manifest_hash = ""
        if not manifest_path.is_file():
            failure_rules.append("ART-001")
            findings.append(
                _artifact_finding(
                    "ART-001",
                    "high",
                    backup,
                    "Artifact manifest is missing.",
                    manifest_rel,
                    artifact_file_hash,
                )
            )
        else:
            manifest_hash = sha256_file(manifest_path)
            files.append(
                FileFingerprint(manifest_rel, manifest_hash, manifest_path.stat().st_size)
            )
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                raw = None
            manifest = _parse_manifest(raw, manifest_rel)
            if manifest is None:
                failure_rules.append("ART-002")
                findings.append(
                    _artifact_finding(
                        "ART-002",
                        "high",
                        backup,
                        "Artifact manifest is malformed or lacks required fields.",
                        manifest_rel,
                        manifest_hash,
                    )
                )
            else:
                manifests[backup.backup_id] = manifest
                disagreements = []
                if manifest.backup_id != backup.backup_id:
                    disagreements.append("backup_id")
                if manifest.row_count != backup.row_count:
                    disagreements.append("row_count")
                if manifest.schema_version != backup.schema_version:
                    disagreements.append("schema_version")
                if disagreements:
                    failure_rules.append("ART-006")
                    findings.append(
                        _artifact_finding(
                            "ART-006",
                            "high",
                            backup,
                            f"Manifest disagrees with catalog: {', '.join(disagreements)}.",
                            manifest_rel,
                            manifest_hash,
                            fields=disagreements,
                        )
                    )
        checks.append(
            ArtifactCheck(
                backup_id=backup.backup_id,
                artifact_ready=not failure_rules,
                manifest=manifest,
                failure_rules=tuple(sorted(set(failure_rules))),
            )
        )
    checks.sort(key=lambda item: item.backup_id)
    return ArtifactAssessment(
        tuple(checks),
        manifests,
        tuple(sorted(findings, key=Finding.sort_key)),
        tuple(sorted(files, key=lambda item: item.path)),
    )
def _parse_manifest(raw: object, rel_path: str) -> ArtifactManifest | None:
    if not isinstance(raw, dict):
        return None
    required = {"backup_id", "row_count", "data_sha256", "schema_version"}
    if any(name not in raw for name in required):
        return None
    backup_id = raw.get("backup_id")
    row_count = _as_nonnegative_int(raw.get("row_count"))
    digest = raw.get("data_sha256")
    schema_version = raw.get("schema_version")
    if not isinstance(backup_id, str) or not backup_id:
        return None
    if row_count is None:
        return None
    if not isinstance(digest, str) or not _SHA_RE.fullmatch(digest):
        return None
    if not isinstance(schema_version, str) or not schema_version:
        return None
    return ArtifactManifest(
        backup_id=backup_id,
        row_count=row_count,
        data_sha256=digest.lower(),
        schema_version=schema_version,
        path=rel_path,
    )
def assess_evidence(
    events: tuple[DrillEvent, ...],
    fixtures_root: Path,
) -> EvidenceAssessment:
    """Verify every distinct evidence reference once."""
    root = fixtures_root.resolve()
    refs: dict[str, int] = {}
    for event in events:
        refs.setdefault(event.evidence_ref, event.line_no)
    checks: list[EvidenceCheck] = []
    findings: list[Finding] = []
    files: list[FileFingerprint] = []
    for ref in sorted(refs):
        try:
            path = resolve_under(root, ref, field="evidence_ref")
        except UnsafePath as exc:
            checks.append(EvidenceCheck(ref, False, False, False, "", 0))
            findings.append(Finding("EVID-002", "high", "evidence", ref, str(exc), ref, refs[ref]))
            continue
        if not path.is_file():
            checks.append(EvidenceCheck(ref, False, False, False, "", 0))
            findings.append(
                Finding(
                    "EVID-001",
                    "high",
                    "evidence",
                    ref,
                    "Referenced evidence file does not exist.",
                    ref,
                    refs[ref],
                )
            )
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            checks.append(EvidenceCheck(ref, True, False, False, "", 0))
            findings.append(
                Finding(
                    "EVID-002", "high", "evidence", ref,
                    "Evidence file is unreadable.", ref, refs[ref],
                )
            )
            continue
        digest = sha256_file(path)
        valid = bool(payload.strip())
        detail = "Evidence file is empty."
        if valid and path.suffix.lower() == ".json":
            try:
                document = json.loads(payload.decode("utf-8"))
                valid = isinstance(document, dict) and isinstance(document.get("evidence_id"), str)
                detail = "JSON evidence must be an object with a string evidence_id."
            except (UnicodeError, json.JSONDecodeError):
                valid = False
                detail = "JSON evidence cannot be parsed."
        checks.append(EvidenceCheck(ref, True, True, valid, digest, len(payload)))
        files.append(FileFingerprint(ref, digest, len(payload)))
        if not valid:
            findings.append(
                Finding(
                    "EVID-002",
                    "high",
                    "evidence",
                    ref,
                    detail,
                    ref,
                    refs[ref],
                    {"size_bytes": len(payload)},
                    digest,
                )
            )
    return EvidenceAssessment(
        tuple(checks),
        tuple(sorted(findings, key=Finding.sort_key)),
        tuple(sorted(files, key=lambda item: item.path)),
    )
