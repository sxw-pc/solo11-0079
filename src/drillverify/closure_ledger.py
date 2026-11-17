"""Ledger persistence for closure reviews.

Kept separate from ``ledger.py`` so that module stays focused on run and action
rows. The review is stored as a full JSON payload plus normalized rows for
filtering; the console reads only SQLite.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

CLOSURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS closure_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  availability TEXT NOT NULL,
  book_sha256 TEXT NOT NULL,
  summary_json TEXT NOT NULL,
  issues_json TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS closure_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_pk INTEGER NOT NULL REFERENCES runs(id),
  action_id TEXT NOT NULL,
  status TEXT NOT NULL,
  action_revision TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_closure_decisions_run ON closure_decisions(run_pk);
"""


def record_closures(
    connection: sqlite3.Connection, run_pk: int, review: dict[str, Any]
) -> None:
    """Append the closure verdict for one run."""
    book = review.get("book") or {}
    connection.execute(
        """INSERT INTO closure_reviews(run_pk, availability, book_sha256, summary_json,
           issues_json, payload_json) VALUES (?, ?, ?, ?, ?, ?)""",
        (
            run_pk,
            review.get("availability", "no_approval_book"),
            book.get("sha256", ""),
            json.dumps(review.get("summary", {}), ensure_ascii=False, sort_keys=True),
            json.dumps(review.get("issues", []), ensure_ascii=False, sort_keys=True),
            json.dumps(review, ensure_ascii=False, sort_keys=True),
        ),
    )
    connection.executemany(
        """INSERT INTO closure_decisions(run_pk, action_id, status, action_revision,
           event_count, payload_json) VALUES (?, ?, ?, ?, ?, ?)""",
        [
            (
                run_pk, item["action_id"], item["status"], item.get("action_revision", ""),
                int(item.get("event_count", 0)),
                json.dumps(item, ensure_ascii=False, sort_keys=True),
            )
            for item in review.get("decisions", [])
        ],
    )


def read_closures(connection: sqlite3.Connection, run_pk: int) -> dict[str, Any]:
    """Return a stored review; old ledgers report it as not recorded."""
    try:
        row = connection.execute(
            "SELECT payload_json FROM closure_reviews WHERE run_pk = ? ORDER BY id DESC LIMIT 1",
            (run_pk,),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row is None:
        return {
            "availability": "not_recorded",
            "book": None,
            "issues": [],
            "summary": {},
            "decisions": [],
        }
    return json.loads(row["payload_json"])


def get_closure_review(db_path: Path, run_pk: int) -> dict[str, Any]:
    """Open a query-only connection and read one run's closure review."""
    if not db_path.is_file():
        raise FileNotFoundError(f"ledger not found: {db_path}")
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    try:
        return read_closures(connection, run_pk)
    finally:
        connection.close()
