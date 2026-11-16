"""Normalized SQLite rows for the remediation schedule."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  objective TEXT NOT NULL,
  action_id TEXT NOT NULL,
  owner_team TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  priority TEXT NOT NULL,
  start_slot INTEGER NOT NULL,
  end_slot INTEGER NOT NULL,
  start_at TEXT NOT NULL,
  end_at TEXT NOT NULL,
  overdue INTEGER NOT NULL,
  impact_minutes INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scheduled_run ON scheduled_actions(run_pk);
CREATE TABLE IF NOT EXISTS unscheduled_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  objective TEXT NOT NULL,
  action_id TEXT NOT NULL,
  owner_team TEXT NOT NULL,
  dataset_id TEXT NOT NULL,
  priority TEXT NOT NULL,
  reason TEXT NOT NULL,
  before_due_possible INTEGER NOT NULL,
  detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_unscheduled_run ON unscheduled_actions(run_pk);
"""


def create_schedule_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(_SCHEMA)


def write_schedule(
    connection: sqlite3.Connection, run_pk: int, schedule: Any
) -> None:
    """Persist every objective's scheduled and unscheduled actions."""
    scheduled_rows: list[tuple[Any, ...]] = []
    unscheduled_rows: list[tuple[Any, ...]] = []
    for outcome in schedule.outcomes:
        for item in outcome.scheduled:
            scheduled_rows.append(
                (
                    run_pk,
                    outcome.objective,
                    item.action_id,
                    item.owner_team,
                    item.dataset_id,
                    item.priority,
                    item.start_slot,
                    item.end_slot,
                    item.start_at,
                    item.end_at,
                    int(item.overdue),
                    item.impact_minutes,
                    json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True),
                )
            )
        for item in outcome.unscheduled:
            unscheduled_rows.append(
                (
                    run_pk,
                    outcome.objective,
                    item.action_id,
                    item.owner_team,
                    item.dataset_id,
                    item.priority,
                    item.reason,
                    int(item.before_due_possible),
                    item.detail,
                )
            )
    connection.executemany(
        """INSERT INTO scheduled_actions(run_pk, objective, action_id, owner_team,
           dataset_id, priority, start_slot, end_slot, start_at, end_at, overdue,
           impact_minutes, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        scheduled_rows,
    )
    connection.executemany(
        """INSERT INTO unscheduled_actions(run_pk, objective, action_id, owner_team,
           dataset_id, priority, reason, before_due_possible, detail)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        unscheduled_rows,
    )


def get_schedule(
    db_path: Path, run_pk: int, objective: str | None = None
) -> dict[str, Any]:
    """Read normalized schedule rows for one ledger run."""
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    try:
        sql = "SELECT objective, payload_json FROM scheduled_actions WHERE run_pk = ?"
        params: list[Any] = [run_pk]
        if objective:
            sql += " AND objective = ?"
            params.append(objective)
        scheduled = [
            json.loads(row["payload_json"])
            for row in connection.execute(sql + " ORDER BY id ASC", params).fetchall()
        ]
        sql = (
            "SELECT objective, action_id, owner_team, dataset_id, priority, reason, "
            "before_due_possible, detail FROM unscheduled_actions WHERE run_pk = ?"
        )
        if objective:
            sql += " AND objective = ?"
        unscheduled = [dict(row) for row in connection.execute(sql + " ORDER BY id ASC", params).fetchall()]
    finally:
        connection.close()
    return {"scheduled": scheduled, "unscheduled": unscheduled}
