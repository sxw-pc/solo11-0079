"""Low-level, offline readers for catalog CSV and drill JSONL inputs."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FileFingerprint, Finding
from .paths import UnsafePath, resolve_under, safe_relative, sha256_file

CATALOG_COLUMNS = (
    "dataset_id",
    "backup_id",
    "parent_backup_id",
    "backup_type",
    "started_at",
    "finished_at",
    "artifact_path",
    "artifact_size_bytes",
    "sha256",
    "row_count",
    "schema_version",
)


@dataclass(frozen=True)
class LoadedRows:
    path: str
    rows: tuple[tuple[int, dict[str, Any]], ...]
    findings: tuple[Finding, ...]
    fingerprint: FileFingerprint | None
    fatal: bool


def _missing_file(rel_path: str, object_id: str) -> LoadedRows:
    finding = Finding(
        "IN-000",
        "error",
        "input",
        object_id,
        f"Required input file {rel_path} is missing.",
        rel_path,
    )
    return LoadedRows(rel_path, (), (finding,), None, True)


def _fingerprint(root: Path, path: Path) -> FileFingerprint:
    return FileFingerprint(
        path=safe_relative(root, path),
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
    )


def load_catalog(fixtures_root: Path, rel_path: str = "catalog/backup_catalog.csv") -> LoadedRows:
    """Read every CSV row, preserving physical line numbers."""
    root = fixtures_root.resolve()
    try:
        path = resolve_under(root, rel_path, field="catalog path")
    except UnsafePath as exc:
        return LoadedRows(rel_path, (), (Finding("IN-009", "error", "input", rel_path, str(exc)),), None, True)
    rel = safe_relative(root, path)
    if not path.is_file():
        return _missing_file(rel, "backup_catalog")
    fingerprint = _fingerprint(root, path)
    findings: list[Finding] = []
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            columns = tuple(reader.fieldnames or ())
            missing = [name for name in CATALOG_COLUMNS if name not in columns]
            if missing:
                findings.append(
                    Finding(
                        "IN-001",
                        "error",
                        "input",
                        rel,
                        f"Catalog is missing required columns: {', '.join(missing)}.",
                        rel,
                        1,
                        {"missing_columns": missing},
                        fingerprint.sha256,
                    )
                )
                return LoadedRows(rel, (), tuple(findings), fingerprint, True)
            rows: list[tuple[int, dict[str, Any]]] = []
            for raw in reader:
                line_no = reader.line_num
                if None in raw or any(value is None for value in raw.values()):
                    findings.append(
                        Finding(
                            "IN-001",
                            "error",
                            "input",
                            rel,
                            "Catalog row has more values than declared columns.",
                            rel,
                            line_no,
                            {},
                            fingerprint.sha256,
                        )
                    )
                    continue
                rows.append((line_no, dict(raw)))
    except (OSError, UnicodeError, csv.Error) as exc:
        findings.append(
            Finding(
                "IN-003",
                "error",
                "input",
                rel,
                f"Catalog cannot be read: {type(exc).__name__}.",
                rel,
                0,
                {},
                fingerprint.sha256,
            )
        )
        return LoadedRows(rel, (), tuple(findings), fingerprint, True)
    return LoadedRows(rel, tuple(rows), tuple(findings), fingerprint, False)


def _event_issue(
    rel: str,
    line_no: int,
    message: str,
    file_hash: str,
    *,
    rule: str = "IN-003",
    object_id: str = "",
) -> Finding:
    return Finding(
        rule,
        "error",
        "drill_event",
        object_id or f"line-{line_no}",
        message,
        rel,
        line_no,
        {},
        file_hash,
    )


def load_drills(fixtures_root: Path, rel_path: str = "logs/restore_drill.jsonl") -> LoadedRows:
    """Read every JSONL record and keep malformed-line diagnostics."""
    root = fixtures_root.resolve()
    try:
        path = resolve_under(root, rel_path, field="drill log path")
    except UnsafePath as exc:
        return LoadedRows(rel_path, (), (Finding("IN-009", "error", "input", rel_path, str(exc)),), None, True)
    rel = safe_relative(root, path)
    if not path.is_file():
        return _missing_file(rel, "restore_drill")
    fingerprint = _fingerprint(root, path)
    findings: list[Finding] = []
    rows: list[tuple[int, dict[str, Any]]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    findings.append(
                        _event_issue(
                            rel,
                            line_no,
                            f"Malformed JSON at column {exc.colno}; line rejected.",
                            fingerprint.sha256,
                            rule="IN-012",
                        )
                    )
                    continue
                if not isinstance(raw, dict):
                    findings.append(
                        _event_issue(
                            rel,
                            line_no,
                            "Drill event must be a JSON object.",
                            fingerprint.sha256,
                            rule="IN-012",
                        )
                    )
                    continue
                rows.append((line_no, raw))
    except (OSError, UnicodeError) as exc:
        findings.append(
            _event_issue(
                rel,
                0,
                f"Drill log cannot be read: {type(exc).__name__}.",
                fingerprint.sha256,
            )
        )
        return LoadedRows(rel, (), tuple(findings), fingerprint, True)
    return LoadedRows(rel, tuple(rows), tuple(findings), fingerprint, False)
