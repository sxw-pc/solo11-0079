"""Deterministic offline fixture builders for same-generation drill tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

from drillverify.pipeline import run_pipeline
from drillverify.reporting import build_report

D1 = "a" * 64
D2 = "b" * 64
ROW_COUNT = 12000
STEPS = ["restore_base", "apply_incremental", "verify_rowcount",
         "verify_checksum", "publish_report"]


def _sha(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()


def _evidence(root: Path, ref: str, valid: bool = True) -> None:
    path = root / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix == ".json":
        payload = json.dumps({"evidence_id": ref, "note": "synthetic"})
    else:
        payload = ref + "\n"
    if not valid:
        payload = ""
    path.write_text(payload, encoding="utf-8")


def build_fixture(root: Path, events: list[dict], *, policy: str = "strict_replay",
                  manifest_digest: str = D1, rto_minutes: int = 90) -> Path:
    """Materialize a self-contained offline drill fixture and return its root."""
    (root / "plans").mkdir(parents=True)
    (root / "catalog").mkdir()
    (root / "artifacts" / "blobs").mkdir(parents=True)
    (root / "logs").mkdir()
    (root / "evidence").mkdir()
    plan = {
        "schema_version": 1,
        "as_of": "2026-11-10T00:00:00Z",
        "analysis_window_days": 7,
        "datasets": [{
            "dataset_id": "ds-demo", "display_name": "Demo Dataset",
            "rpo_minutes": 240, "rto_minutes": rto_minutes,
            "required_steps": STEPS, "checksum_required": True,
            "rowcount_required": True, "owner_team": "team-alpha",
            "maintenance_window": "sun:02:00-04:00Z",
            "artifact_manifest_path": "artifacts",
            "recovery_evidence_policy": policy,
        }],
    }
    (root / "plans" / "recovery_plan.yaml").write_text(yaml.safe_dump(plan, sort_keys=False))
    blob = b"synthetic backup blob\n"
    digest = _sha(blob)
    rows = [
        ("bk-base", "", "full", "2026-11-09T20:00:00Z", "2026-11-09T20:10:00Z"),
        ("bk-incr", "bk-base", "incremental", "2026-11-09T20:15:00Z", "2026-11-09T20:20:00Z"),
    ]
    header = ("dataset_id,backup_id,parent_backup_id,backup_type,started_at,finished_at,"
              "artifact_path,artifact_size_bytes,sha256,row_count,schema_version\n")
    lines = [header]
    for backup_id, parent, kind, started, finished in rows:
        rel = f"artifacts/blobs/{backup_id}.bin"
        (root / rel).write_bytes(blob)
        lines.append(
            f"ds-demo,{backup_id},{parent},{kind},{started},{finished},{rel},"
            f"{len(blob)},{digest},{ROW_COUNT},3\n"
        )
    (root / "catalog" / "backup_catalog.csv").write_text("".join(lines), encoding="utf-8")
    for backup_id, *_ in rows:
        (root / "artifacts" / f"manifest-{backup_id}.json").write_text(json.dumps({
            "backup_id": backup_id, "row_count": ROW_COUNT,
            "data_sha256": manifest_digest, "schema_version": "3",
        }), encoding="utf-8")
    refs = {event.get("evidence_ref") for event in events}
    for ref in sorted(ref for ref in refs if ref):
        _evidence(root, ref, valid=not ref.endswith("missing.txt"))
    payload = "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n"
    (root / "logs" / "restore_drill.jsonl").write_text(payload, encoding="utf-8")
    return root


def event(step: str, attempt: int, started: str, finished: str, status: str = "success",
          *, gen: str | None = None, digest: str | None = None,
          rows: int | None = None, sha: str | None = None,
          ref: str | None = None, drill: str = "drill-demo-1") -> dict:
    return {
        "drill_id": drill, "dataset_id": "ds-demo", "backup_id": "bk-incr",
        "step": step, "status": status, "attempt": attempt,
        "started_at": started, "finished_at": finished,
        "evidence_ref": ref or f"evidence/{step}-{attempt}.txt",
        "detail": f"{step} attempt {attempt}",
        "rows_restored": rows, "reported_sha256": sha,
        "recovery_generation": gen, "data_digest": digest,
    }


def run(root: Path):
    bundle = run_pipeline(root)
    return bundle, build_report(bundle)
