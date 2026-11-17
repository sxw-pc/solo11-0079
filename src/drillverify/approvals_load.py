"""Strict loading of approval-book JSON."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .approvals import (
    EVENT_KINDS, ROLES, ActionEntry, Approval, Book, Completion, Event, Grant, Person,
    Revocation, RoleHolder,
)
from .paths import sha256_file
from .timeutil import TimestampError, parse_utc


def issue(code: str, detail: str, source: str = "") -> dict[str, str]:
    return {"code": code, "detail": detail, "source": source}


def _ts(value: object) -> datetime | None:
    try:
        return parse_utc(value)
    except (TimestampError, TypeError):
        return None


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _items(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _person(raw: dict[str, Any], index: int, issues: list[dict[str, str]]) -> Person | None:
    source = _text(raw.get("source")) or f"people[{index}]"
    person_id = _text(raw.get("person_id"))
    if not person_id:
        issues.append(issue("person_id_missing", "person has no id", source))
        return None
    identity = _text(raw.get("identity_id"))
    return Person(person_id, _text(raw.get("display_name")) or person_id,
                  _text(raw.get("team")), identity, source)


def _grant(raw: dict[str, Any], index: int, issues: list[dict[str, str]]) -> Grant | None:
    source = _text(raw.get("source")) or f"delegations[{index}]"
    grant_id, role = _text(raw.get("grant_id")), _text(raw.get("role"))
    if not grant_id or not role:
        issues.append(issue("grant_malformed", "delegation lacks grant_id or role", source))
        return None
    granted, expires = _ts(raw.get("granted_at")), _ts(raw.get("expires_at"))
    problem = ""
    if granted is None:
        problem = "granted_at invalid"
    elif raw.get("expires_at") is not None and expires is None:
        problem = "expires_at invalid"
    elif expires is not None and expires <= granted:
        problem = "expires_at not after granted_at"
    return Grant(grant_id, role, _text(raw.get("from_person_id")),
                 _text(raw.get("to_person_id")), granted, expires, source, problem)


def _approval(raw: dict[str, Any], index: int, source: str) -> Approval:
    at, role, person_id = _ts(raw.get("at")), _text(raw.get("role")), _text(raw.get("person_id"))
    problem = ""
    if at is None:
        problem = "approval time invalid"
    elif role not in ROLES:
        problem = "role is not one of the two required roles"
    elif not person_id:
        problem = "person_id missing"
    elif not _text(raw.get("evidence_version")):
        problem = "evidence_version missing"
    return Approval(_text(raw.get("approval_id")) or f"approval[{index}]",
                    _text(raw.get("action_id")), role, person_id,
                    _text(raw.get("via_grant_id")) or None,
                    _text(raw.get("evidence_version")), at,
                    _text(raw.get("source")) or source, problem)


def _event(raw: dict[str, Any], source: str) -> Event:
    kind, at = _text(raw.get("event")), _ts(raw.get("at"))
    problem = ""
    if at is None:
        problem = "event time invalid"
    elif kind not in EVENT_KINDS:
        problem = "event is not a withdrawal or evidence replacement"
    return Event(kind, at, _text(raw.get("approval_id")), _text(raw.get("from_version")),
                 _text(raw.get("to_version")), _text(raw.get("to_path")),
                 _text(raw.get("to_sha256")), _text(raw.get("reason")),
                 _text(raw.get("source")) or source, problem)


def _completion(raw: object, source: str) -> Completion | None:
    if not isinstance(raw, dict):
        return None
    return Completion(_text(raw.get("declared_by")), _text(raw.get("evidence_path")),
                      _text(raw.get("evidence_sha256")), _text(raw.get("evidence_version")),
                      _text(raw.get("source")) or source, _ts(raw.get("declared_at")))


def _entry(raw: dict[str, Any], index: int, issues: list[dict[str, str]]) -> ActionEntry | None:
    source = _text(raw.get("source")) or f"actions[{index}]"
    action_id = _text(raw.get("action_id"))
    if not action_id:
        issues.append(issue("action_id_missing", "approval entry has no action_id", source))
        return None
    approvals = tuple(_approval(item, pos, source) for pos, item in
                      enumerate(_items(raw.get("approvals"))) if isinstance(item, dict))
    events = tuple(_event(item, source) for item in _items(raw.get("events"))
                   if isinstance(item, dict))
    summary = raw.get("revision_summary")
    return ActionEntry(action_id, _text(raw.get("action_revision")),
                       _completion(raw.get("completion"), source), approvals, events, source,
                       _text(raw.get("owner_person_id")),
                       summary if isinstance(summary, dict) else None)


def load_book(raw: object, path: str, digest: str = "") -> Book:
    """Parse one book. Structural problems make the whole book invalid."""
    issues: list[dict[str, str]] = []
    if not isinstance(raw, dict):
        return Book(None, 8, {}, (), {}, (), {},
                    (issue("book_malformed", "approval book root must be an object", path),),
                    False, path, digest)
    decided_at = _ts(raw.get("decided_at"))
    if decided_at is None:
        issues.append(issue("decided_at_invalid", "decided_at must be an ISO 8601 timestamp", path))
    budget = raw.get("event_budget", 8)
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
        issues.append(issue("event_budget_invalid", "event_budget must be a positive integer", path))
        budget = 8
    people: dict[str, Person] = {}
    for index, item in enumerate(_items(raw.get("people"))):
        person = _person(item, index, issues) if isinstance(item, dict) else None
        if person is None:
            continue
        if person.person_id in people:
            issues.append(issue("person_duplicate",
                                f"person {person.person_id} declared twice", person.source))
            continue
        people[person.person_id] = person
    holders: list[RoleHolder] = []
    for index, item in enumerate(_items(raw.get("role_holders"))):
        entry = item if isinstance(item, dict) else {}
        role, person_id = _text(entry.get("role")), _text(entry.get("person_id"))
        source = _text(entry.get("source")) or f"role_holders[{index}]"
        if role not in ROLES or not person_id:
            issues.append(issue("role_holder_malformed", "role holder needs a known role and person_id", source))
            continue
        holders.append(RoleHolder(role, person_id, source))
    grants: dict[str, Grant] = {}
    for index, item in enumerate(_items(raw.get("delegations"))):
        grant = _grant(item, index, issues) if isinstance(item, dict) else None
        if grant is None:
            continue
        if grant.grant_id in grants:
            issues.append(issue("grant_duplicate",
                                f"grant {grant.grant_id} declared twice", grant.source))
            continue
        grants[grant.grant_id] = grant
    revocations: list[Revocation] = []
    for index, item in enumerate(_items(raw.get("delegation_events"))):
        if not isinstance(item, dict):
            continue
        source = _text(item.get("source")) or f"delegation_events[{index}]"
        grant_id, at = _text(item.get("grant_id")), _ts(item.get("at"))
        if not grant_id or at is None:
            issues.append(issue("revocation_malformed", "revocation lacks grant_id or valid at", source))
            continue
        revocations.append(Revocation(grant_id, at, _text(item.get("reason")), source))
    entries: dict[str, ActionEntry] = {}
    for index, item in enumerate(_items(raw.get("actions"))):
        entry = _entry(item, index, issues) if isinstance(item, dict) else None
        if entry is None:
            continue
        if entry.action_id in entries:
            issues.append(issue("action_entry_duplicate",
                                f"action {entry.action_id} has two entries", entry.source))
            entry = ActionEntry(entry.action_id, entry.action_revision, entry.completion,
                                entry.approvals, entry.events, entry.source,
                                entry.owner_person_id, entry.revision_summary,
                                "duplicate action entry")
        entries[entry.action_id] = entry
    return Book(decided_at, budget, people, tuple(holders), grants, tuple(revocations),
                entries, tuple(issues), not issues, path, digest)


def load_book_file(path: Path) -> Book | None:
    """Load a book from disk; a missing file means no approval book."""
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return Book(None, 8, {}, (), {}, (), {}, (issue(
            "book_unreadable", type(exc).__name__, path.name),), False, path.name, "")
    return load_book(raw, path.name, sha256_file(path))
