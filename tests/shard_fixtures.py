"""Synthetic sharded-backup fixture construction for offline tests.
Everything is generated under a pytest tmp directory; nothing here touches
external storage and no data is ever reconstructed.
"""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from drillverify.artifact_review import assess_artifacts
from drillverify.records import BackupRecord
from drillverify.paths import sha256_bytes
def shard_blob(seed: str) -> bytes:
    return f"synthetic-shard::{seed}\n".encode("utf-8")
def write_shard(root: Path, rel: str, seed: str) -> tuple[int, str]:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = shard_blob(seed)
    path.write_bytes(payload)
    return len(payload), hashlib.sha256(payload).hexdigest()
def make_backup(backup_id: str = "bk-shard-001") -> BackupRecord:
    started = datetime(2026, 11, 5, tzinfo=timezone.utc)
    finished = datetime(2026, 11, 5, 0, 20, tzinfo=timezone.utc)
    blob = shard_blob(f"index-{backup_id}")
    return BackupRecord("ds-orders", backup_id, None, "full", started, finished,
                        f"artifacts/blobs/{backup_id}.bin", len(blob), sha256_bytes(blob),
                        12000, "3", 1)
def write_index(root: Path, backup: BackupRecord) -> None:
    path = root / backup.artifact_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(shard_blob(f"index-{backup.backup_id}"))
def write_manifest(root: Path, backup: BackupRecord, shards: list[dict], *,
                   stripe_count: int = 3, purpose: str = "current",
                   manifest_version: str = "2", extra: dict | None = None) -> Path:
    path = root / "artifacts" / f"manifest-{backup.backup_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "manifest_version": manifest_version,
        "backup_id": backup.backup_id,
        "row_count": backup.row_count,
        "data_sha256": "a" * 64,
        "schema_version": backup.schema_version,
        "sharding": {"stripe_count": stripe_count, "recovery_purpose": purpose, "shards": shards},
    }
    if extra:
        document.update(extra)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path
def build_shards(root: Path, backup: BackupRecord, vectors: dict[str, tuple[int, ...]],
                 domains: dict[str, str], *, tamper: set[str] | None = None,
                 missing: set[str] | None = None,
                 bad_paths: dict[str, str] | None = None) -> list[dict]:
    """Materialize shard files and return manifest shard entries.
    ``tamper`` shards keep their original digest in the manifest while the file
    on disk is modified, so hash verification genuinely fails.
    """
    tamper, missing, bad_paths = tamper or set(), missing or set(), bad_paths or {}
    entries = []
    for shard_id, vector in vectors.items():
        rel = f"artifacts/shards/{backup.backup_id}/{shard_id}.bin"
        if shard_id in missing:
            payload = shard_blob(shard_id)
            entries.append({"shard_id": shard_id, "coefficients": list(vector), "path": rel,
                            "size_bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "fault_domain": domains[shard_id]})
            continue
        size, digest = write_shard(root, rel, shard_id)
        if shard_id in tamper:
            (root / rel).write_bytes(shard_blob(shard_id) + b"tampered\n")
        entries.append({"shard_id": shard_id, "coefficients": list(vector),
                        "path": bad_paths.get(shard_id, rel), "size_bytes": size,
                        "sha256": digest, "fault_domain": domains[shard_id]})
    return entries
def run_assessment(root: Path, plan, backup: BackupRecord):
    return assess_artifacts((backup,), plan, root)
