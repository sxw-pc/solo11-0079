"""Parsing and static verification of versioned, sharded artifact manifests.
Only local fixture files are read, and only hashes and GF(2) linear algebra are
produced.  No shard content is reconstructed, exported or sent anywhere.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from .models import FileFingerprint, Finding
from .paths import UnsafePath, resolve_under, safe_relative, sha256_file
from .records import ArtifactManifest, BackupRecord, ShardAssessment, ShardProof, ShardSpec
from .sharding import domain_removal_proofs, eliminate, first_failing_domain
_SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
RECOVERY_PURPOSES = ("current", "single_fault_domain")
class ShardBlockError(ValueError):
    """Raised when the sharding block of a version-2 manifest is malformed."""
def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
def _parse_coefficients(raw: object, k: int) -> tuple[int, ...] | None:
    if not isinstance(raw, list) or len(raw) != k:
        return None
    if any(not isinstance(bit, int) or isinstance(bit, bool) or bit not in (0, 1) for bit in raw):
        return None
    return tuple(raw)
def parse_sharding(raw: object) -> tuple[int, str, tuple[ShardSpec, ...]]:
    """Validate the sharding block; raise ``ShardBlockError`` on any defect."""
    if not isinstance(raw, dict):
        raise ShardBlockError("sharding block must be an object")
    k = _as_int(raw.get("stripe_count"))
    if k is None or not 1 <= k <= 16:
        raise ShardBlockError("stripe_count must be an integer between 1 and 16")
    purpose = raw.get("recovery_purpose", "current")
    if not isinstance(purpose, str) or purpose not in RECOVERY_PURPOSES:
        raise ShardBlockError("recovery_purpose must be 'current' or 'single_fault_domain'")
    entries = raw.get("shards")
    if not isinstance(entries, list) or not entries:
        raise ShardBlockError("shards must be a non-empty list")
    shards: list[ShardSpec] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ShardBlockError("each shard entry must be an object")
        shard_id = entry.get("shard_id")
        if not isinstance(shard_id, str) or not shard_id or shard_id in seen:
            raise ShardBlockError("duplicate or invalid shard_id")
        seen.add(shard_id)
        vector = _parse_coefficients(entry.get("coefficients"), k)
        if vector is None:
            raise ShardBlockError("coefficients must be k GF(2) bits (0 or 1)")
        path, size, digest, domain = (entry.get("path"), _as_int(entry.get("size_bytes")),
                                      entry.get("sha256"), entry.get("fault_domain"))
        if not isinstance(path, str) or not path.strip():
            raise ShardBlockError("shard path must be a non-empty string")
        if size is None:
            raise ShardBlockError("shard size_bytes must be a non-negative integer")
        if not isinstance(digest, str) or not _SHA_RE.fullmatch(digest):
            raise ShardBlockError("shard sha256 must be 64 hexadecimal characters")
        if not isinstance(domain, str) or not domain.strip():
            raise ShardBlockError("fault_domain must be a non-empty string")
        shards.append(ShardSpec(shard_id, vector, path.strip(), size, digest.lower(), domain.strip()))
    return k, purpose, tuple(shards)
@dataclass(frozen=True)
class ShardReview:
    assessment: ShardAssessment
    findings: tuple[Finding, ...]
    files: tuple[FileFingerprint, ...]
    failure_rules: tuple[str, ...]
def _finding(rule: str, severity: str, backup: BackupRecord, message: str, file: str, **ev: Any) -> Finding:
    return Finding(rule, severity, "backup", backup.backup_id, message, file, 0,
                   {"dataset_id": backup.dataset_id, **ev})
def _verify_one(spec, backup: BackupRecord, root: Path, files: list, findings: list):
    """Verify one shard file; return (proof, usable)."""
    rules: list[str] = []
    try:
        absolute = resolve_under(root, spec.path, field="shard_path")
        rel = safe_relative(root, absolute)
    except UnsafePath as exc:
        absolute, rel = None, spec.path
        rules.append("ART-008")
        findings.append(_finding("ART-008", "high", backup, str(exc), rel, shard_id=spec.shard_id))
    actual_hash, actual_size = "", 0
    if absolute is not None and not absolute.is_file():
        rules.append("ART-008")
        findings.append(_finding("ART-008", "high", backup, "Shard file is missing.", rel,
                                 shard_id=spec.shard_id, fault_domain=spec.fault_domain))
    elif absolute is not None:
        actual_hash = sha256_file(absolute)
        actual_size = absolute.stat().st_size
        files.append(FileFingerprint(rel, actual_hash, actual_size))
        if actual_size != spec.size_bytes:
            rules.append("ART-009")
            findings.append(_finding("ART-009", "high", backup,
                                     "Shard size does not match the manifest.", rel,
                                     shard_id=spec.shard_id, expected=spec.size_bytes, actual=actual_size))
        if actual_hash != spec.sha256:
            rules.append("ART-009")
            findings.append(_finding("ART-009", "high", backup,
                                     "Shard SHA-256 does not match the manifest.", rel,
                                     shard_id=spec.shard_id, expected=spec.sha256, actual=actual_hash))
    proof = ShardProof(spec.shard_id, spec.fault_domain, spec.coefficients, rel,
                       spec.size_bytes, actual_size, spec.sha256, actual_hash,
                       not rules, tuple(sorted(set(rules))))
    return proof, rules
def assess_shards(manifest: ArtifactManifest, backup: BackupRecord, root: Path) -> ShardReview:
    """Verify every shard file, then prove rank and fault-domain tolerance."""
    k = manifest.stripe_count or 0
    findings: list[Finding] = []
    files: list[FileFingerprint] = []
    rules: list[str] = []
    proofs: list[ShardProof] = []
    usable_vectors: list[tuple[int, ...]] = []
    usable_domains: list[str] = []
    for spec in manifest.shards:
        proof, shard_rules = _verify_one(spec, backup, root, files, findings)
        proofs.append(proof)
        rules.extend(shard_rules)
        if not shard_rules:
            usable_vectors.append(spec.coefficients)
            usable_domains.append(spec.fault_domain)
    rank_proof = eliminate(tuple(usable_vectors), k)
    failed_domain = first_failing_domain(
        domain_removal_proofs(tuple(usable_vectors), tuple(usable_domains), k))
    if not rank_proof.full_rank:
        rules.append("ART-010")
        findings.append(_finding("ART-010", "high", backup,
                                 "Usable shard coefficient vectors do not span every source stripe.",
                                 manifest.path, rank=rank_proof.rank, stripe_count=k,
                                 usable_shard_count=len(usable_vectors),
                                 missing_dimensions=list(rank_proof.missing_dimensions),
                                 witness_vectors=[list(v) for v in rank_proof.witness_vectors()]))
    if manifest.recovery_purpose == "single_fault_domain" and failed_domain is not None:
        rules.append("ART-011")
        findings.append(_finding("ART-011", "high", backup,
                                 "Losing one fault domain leaves the source stripes unrecoverable.",
                                 manifest.path, fault_domain=failed_domain.fault_domain,
                                 remaining_rank=failed_domain.remaining_rank, stripe_count=k,
                                 missing_dimensions=list(failed_domain.missing_dimensions)))
    assessment = ShardAssessment(
        manifest.manifest_version, k, manifest.recovery_purpose or "current",
        len(manifest.shards), len(usable_vectors), rank_proof.rank,
        rank_proof.basis_vectors(), rank_proof.missing_dimensions, rank_proof.witness_vectors(),
        rank_proof.full_rank, failed_domain is None,
        failed_domain.fault_domain if failed_domain else None,
        failed_domain.remaining_rank if failed_domain else None, tuple(proofs))
    return ShardReview(assessment, tuple(sorted(findings, key=Finding.sort_key)),
                       tuple(sorted(files, key=lambda item: item.path)), tuple(sorted(set(rules))))
