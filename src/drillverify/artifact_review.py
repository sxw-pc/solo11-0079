"""Catalog artifact and versioned-manifest integrity review."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .models import FileFingerprint, Finding, RecoveryPlan
from .paths import UnsafePath, resolve_under, safe_relative, sha256_file
from .records import ArtifactCheck, ArtifactManifest, BackupRecord
from .shard_evidence import ShardBlockError, assess_shards, parse_sharding
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SHARDED_VERSIONS = {"2"}
@dataclass(frozen=True)
class ArtifactAssessment:
    checks: tuple[ArtifactCheck, ...]
    manifests: dict[str, ArtifactManifest]
    findings: tuple[Finding, ...]
    files: tuple[FileFingerprint, ...]
def _as_nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
def _finding(rule: str, severity: str, backup: BackupRecord, message: str,
             file: str, file_hash: str = "", **evidence: Any) -> Finding:
    return Finding(rule, severity, "backup", backup.backup_id, message, file, 0,
                   {"dataset_id": backup.dataset_id, **evidence}, file_hash)
def _parse_manifest(raw: object, rel_path: str) -> ArtifactManifest | None:
    if not isinstance(raw, dict):
        return None
    required = {"backup_id", "row_count", "data_sha256", "schema_version"}
    if any(name not in raw for name in required):
        return None
    backup_id, digest, schema = raw.get("backup_id"), raw.get("data_sha256"), raw.get("schema_version")
    row_count = _as_nonnegative_int(raw.get("row_count"))
    if not isinstance(backup_id, str) or not backup_id or row_count is None:
        return None
    if not isinstance(digest, str) or not _SHA_RE.fullmatch(digest):
        return None
    if not isinstance(schema, str) or not schema:
        return None
    version = raw.get("manifest_version", "1")
    if not isinstance(version, str) or version not in {"1", *_SHARDED_VERSIONS}:
        return None
    if version == "1":
        return ArtifactManifest(backup_id, row_count, digest.lower(), schema, rel_path)
    stripe_count, purpose, shards = parse_sharding(raw.get("sharding"))
    return ArtifactManifest(backup_id, row_count, digest.lower(), schema, rel_path,
                            version, stripe_count, purpose, shards)
def _check_catalog_artifact(root: Path, backup: BackupRecord, files: list,
                            findings: list, rules: list) -> str:
    try:
        absolute = resolve_under(root, backup.artifact_path, field="artifact_path")
        rel = safe_relative(root, absolute)
    except UnsafePath:
        absolute, rel = Path(), ""
    if not absolute.is_file():
        rules.append("ART-003")
        findings.append(_finding("ART-003", "high", backup, "Artifact file is missing.", rel))
        return ""
    digest = sha256_file(absolute)
    size = absolute.stat().st_size
    files.append(FileFingerprint(rel, digest, size))
    if size != backup.artifact_size_bytes:
        rules.append("ART-004")
        findings.append(_finding("ART-004", "high", backup,
                                 "Artifact size does not match the catalog.", rel, digest,
                                 expected=backup.artifact_size_bytes, actual=size))
    if digest != backup.sha256:
        rules.append("ART-005")
        findings.append(_finding("ART-005", "critical", backup,
                                 "Artifact SHA-256 does not match the catalog.", rel, digest,
                                 expected=backup.sha256, actual=digest))
    return digest
def assess_artifacts(
    backups: tuple[BackupRecord, ...],
    plan: RecoveryPlan,
    fixtures_root: Path,
) -> ArtifactAssessment:
    """Verify catalog artifacts, their manifests and optional shard proofs."""
    root = fixtures_root.resolve()
    datasets = plan.dataset_map()
    checks: list[ArtifactCheck] = []
    manifests: dict[str, ArtifactManifest] = {}
    findings: list[Finding] = []
    files: list[FileFingerprint] = []
    for backup in sorted(backups, key=lambda item: (item.dataset_id, item.backup_id)):
        rules: list[str] = []
        artifact_hash = _check_catalog_artifact(root, backup, files, findings, rules)
        manifest_dir_raw = datasets[backup.dataset_id].artifact_manifest_path
        try:
            manifest_dir = resolve_under(root, manifest_dir_raw, field="artifact_manifest_path")
            manifest_path = manifest_dir / f"manifest-{backup.backup_id}.json"
            manifest_rel = safe_relative(root, manifest_path)
        except UnsafePath:
            manifest_path, manifest_rel = Path(), manifest_dir_raw
        manifest: ArtifactManifest | None = None
        shard_review = None
        if not manifest_path.is_file():
            rules.append("ART-001")
            findings.append(_finding("ART-001", "high", backup,
                                     "Artifact manifest is missing.", manifest_rel, artifact_hash))
        else:
            manifest_hash = sha256_file(manifest_path)
            files.append(FileFingerprint(manifest_rel, manifest_hash,
                                         manifest_path.stat().st_size))
            try:
                raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                raw = None
            shard_error = False
            try:
                manifest = _parse_manifest(raw, manifest_rel)
            except ShardBlockError:
                manifest, shard_error = None, True
            if manifest is None:
                rule = "ART-007" if shard_error else "ART-002"
                rules.append(rule)
                findings.append(_finding(
                    rule, "high", backup,
                    "Sharded manifest block is malformed." if shard_error
                    else "Artifact manifest is malformed or lacks required fields.",
                    manifest_rel, manifest_hash))
            else:
                manifests[backup.backup_id] = manifest
                disagreements = [
                    name for name, match in (
                        ("backup_id", manifest.backup_id == backup.backup_id),
                        ("row_count", manifest.row_count == backup.row_count),
                        ("schema_version", manifest.schema_version == backup.schema_version),
                    ) if not match
                ]
                if disagreements:
                    rules.append("ART-006")
                    findings.append(_finding(
                        "ART-006", "high", backup,
                        f"Manifest disagrees with catalog: {', '.join(disagreements)}.",
                        manifest_rel, manifest_hash, fields=disagreements))
                if manifest.is_sharded:
                    shard_review = assess_shards(manifest, backup, root)
                    rules.extend(shard_review.failure_rules)
                    findings.extend(shard_review.findings)
                    files.extend(shard_review.files)
        checks.append(ArtifactCheck(
            backup.backup_id, not rules, manifest, tuple(sorted(set(rules))),
            shard_review.assessment if shard_review else None,
        ))
    checks.sort(key=lambda item: item.backup_id)
    return ArtifactAssessment(
        tuple(checks), manifests,
        tuple(sorted(findings, key=Finding.sort_key)),
        tuple(sorted(files, key=lambda item: item.path)),
    )
