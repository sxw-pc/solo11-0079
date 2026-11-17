"""Append-only SQLite audit ledger with a read-only query surface."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .pipeline import RunBundle
from .reporting import SHARED_ARTIFACT_KIND
from .rules import category_for

SCHEMA_VERSION = 2
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  as_of TEXT NOT NULL,
  status TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_run_id ON runs(run_id);
CREATE TABLE IF NOT EXISTS input_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  UNIQUE(run_pk, path)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  sort_key TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  message TEXT NOT NULL,
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  input_sha256 TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_pk);
CREATE TABLE IF NOT EXISTS objectives (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  dataset_id TEXT NOT NULL,
  backup_id TEXT NOT NULL,
  restorable INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  drill_id TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  action_id TEXT NOT NULL,
  priority TEXT NOT NULL,
  owner_team TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL,
  rule_ids TEXT NOT NULL,
  due_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shared_releases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  contract TEXT NOT NULL,
  artifact_json TEXT NOT NULL,
  UNIQUE(run_pk, contract)
);
"""


def _write_connection(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(_SCHEMA)
    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return connection


def _read_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(f"ledger not found: {path}")
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def record_run(db_path: Path, bundle: RunBundle, report: dict[str, Any]) -> int:
    """Append one run and its normalized audit rows; return the ledger row ID."""
    connection = _write_connection(db_path)
    summary_json = json.dumps(bundle.summary, ensure_ascii=False, sort_keys=True)
    report_json = json.dumps(report, ensure_ascii=False, sort_keys=True)
    try:
        with connection:
            cursor = connection.execute(
                "INSERT INTO runs(run_id, as_of, status, summary_json, report_json) VALUES (?, ?, ?, ?, ?)",
                (bundle.run_id, report["as_of"], bundle.status, summary_json, report_json),
            )
            run_pk = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO input_files(run_pk, path, sha256, size_bytes) VALUES (?, ?, ?, ?)",
                [
                    (run_pk, item.path, item.sha256, item.size_bytes)
                    for item in bundle.inputs
                ],
            )
            connection.executemany(
                """INSERT INTO findings(run_pk, sort_key, rule_id, severity, category, object_type,
                   object_id, message, file, line, input_sha256, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        run_pk,
                        json.dumps(item.sort_key(), ensure_ascii=False),
                        item.rule_id,
                        item.severity,
                        category_for(item.rule_id),
                        item.object_type,
                        item.object_id,
                        item.message,
                        item.file,
                        item.line,
                        item.input_sha256,
                        json.dumps(item.evidence, ensure_ascii=False, sort_keys=True),
                    )
                    for item in bundle.findings
                ],
            )
            objective_rows = [
                (run_pk, "rpo", item.dataset_id, item.status,
                 json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
                for item in bundle.rpo
            ] + [
                (run_pk, "rto", item.drill_id, item.status,
                 json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
                for item in bundle.rto
            ]
            connection.executemany(
                "INSERT INTO objectives(run_pk, kind, object_id, status, payload_json) VALUES (?, ?, ?, ?, ?)",
                objective_rows,
            )
            connection.executemany(
                "INSERT INTO chains(run_pk, dataset_id, backup_id, restorable, payload_json) VALUES (?, ?, ?, ?, ?)",
                [
                    (run_pk, item.dataset_id, item.backup_id, int(item.restorable),
                     json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
                    for item in bundle.chains
                ],
            )
            connection.executemany(
                "INSERT INTO drills(run_pk, drill_id, status, payload_json) VALUES (?, ?, ?, ?)",
                [
                    (run_pk, item.drill_id, item.status,
                     json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
                    for item in bundle.drills
                ],
            )
            connection.executemany(
                """INSERT INTO actions(run_pk, action_id, priority, owner_team, object_type,
                   object_id, rule_ids, due_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (run_pk, item.action_id, item.priority, item.owner_team, item.object_type,
                     item.object_id, ",".join(item.rule_ids), item.due_at,
                     json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
                    for item in bundle.actions
                ],
            )
        return run_pk
    finally:
        connection.close()


def record_shared_releases(
    db_path: Path, run_pk: int, artifacts: tuple[dict[str, Any], ...]
) -> None:
    """Attach certified shared statistics cubes to an existing ledger run.

    Only artifacts carrying an optimal disclosure certificate are accepted;
    an unproven or infeasible candidate table never enters the ledger.
    """
    connection = _write_connection(db_path)
    try:
        with connection:
            for artifact in artifacts:
                if artifact.get("artifact_kind") != SHARED_ARTIFACT_KIND:
                    raise ValueError(f"not a shared statistics release: {artifact.get('artifact_kind')!r}")
                certificate = artifact.get("certificate") or {}
                if certificate.get("status") != "optimal":
                    raise ValueError("shared statistics release without an optimal certificate")
                connection.execute(
                    "INSERT INTO shared_releases(run_pk, contract, artifact_json) VALUES (?, ?, ?)",
                    (
                        run_pk,
                        artifact["contract"]["name"],
                        json.dumps(artifact, ensure_ascii=False, sort_keys=True),
                    ),
                )
    finally:
        connection.close()


def list_runs(db_path: Path) -> list[dict[str, Any]]:
    connection = _read_connection(db_path)
    try:
        rows = connection.execute(
            "SELECT id, run_id, as_of, status, summary_json FROM runs ORDER BY id DESC"
        ).fetchall()
        return [
            {
                "id": row["id"],
                "run_id": row["run_id"],
                "as_of": row["as_of"],
                "status": row["status"],
                "summary": json.loads(row["summary_json"]),
            }
            for row in rows
        ]
    finally:
        connection.close()


def get_run(db_path: Path, run_pk: int) -> dict[str, Any] | None:
    connection = _read_connection(db_path)
    try:
        row = connection.execute(
            "SELECT id, run_id, as_of, status, report_json FROM runs WHERE id = ?",
            (run_pk,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "as_of": row["as_of"],
            "status": row["status"],
            "report": json.loads(row["report_json"]),
        }
    finally:
        connection.close()


def get_findings(
    db_path: Path,
    run_pk: int,
    severity: str | None = None,
    query: str | None = None,
) -> list[dict[str, Any]]:
    connection = _read_connection(db_path)
    try:
        sql = "SELECT * FROM findings WHERE run_pk = ?"
        params: list[Any] = [run_pk]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if query:
            sql += " AND (object_id LIKE ? OR rule_id LIKE ? OR message LIKE ? OR evidence_json LIKE ?)"
            like = f"%{query}%"
            params.extend([like, like, like, like])
        sql += " ORDER BY id ASC"
        rows = connection.execute(sql, params).fetchall()
        return [
            {
                "rule_id": row["rule_id"],
                "severity": row["severity"],
                "category": row["category"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "message": row["message"],
                "file": row["file"],
                "line": row["line"],
                "input_sha256": row["input_sha256"],
                "evidence": json.loads(row["evidence_json"]),
            }
            for row in rows
        ]
    finally:
        connection.close()


def get_actions(db_path: Path, run_pk: int) -> list[dict[str, Any]]:
    connection = _read_connection(db_path)
    try:
        rows = connection.execute(
            "SELECT payload_json FROM actions WHERE run_pk = ? ORDER BY id ASC",
            (run_pk,),
        ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]
    finally:
        connection.close()


def get_shared_releases(db_path: Path, run_pk: int) -> list[dict[str, Any]]:
    """Frozen shared statistics cubes for one run; [] on pre-shared ledgers."""
    connection = _read_connection(db_path)
    try:
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'shared_releases'"
        ).fetchone()
        if exists is None:
            return []
        rows = connection.execute(
            "SELECT artifact_json FROM shared_releases WHERE run_pk = ? ORDER BY contract ASC",
            (run_pk,),
        ).fetchall()
        return [json.loads(row["artifact_json"]) for row in rows]
    finally:
        connection.close()
