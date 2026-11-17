"""Approval-book records and strict loading.

Every record keeps its physical ``source`` so a closure decision can name the
exact input that broke it. Structural problems invalidate the whole book.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

ROLES = ("compliance", "independent_verifier")
STATUS_OPEN, STATUS_CLOSED = "open", "closed"
STATUS_PENDING, STATUS_REOPENED, STATUS_UNPROVEN = (
    "pending_reapproval", "reopened", "unproven")
EVENT_KINDS = {"approval_withdrawn", "evidence_replaced"}


@dataclass(frozen=True)
class Person:
    person_id: str
    display_name: str
    team: str
    identity_id: str
    source: str = ""


@dataclass(frozen=True)
class RoleHolder:
    role: str
    person_id: str
    source: str


@dataclass(frozen=True)
class Grant:
    grant_id: str
    role: str
    from_person_id: str
    to_person_id: str
    granted_at: datetime | None
    expires_at: datetime | None
    source: str
    problem: str = ""


@dataclass(frozen=True)
class Revocation:
    grant_id: str
    at: datetime | None
    reason: str
    source: str


@dataclass(frozen=True)
class Approval:
    approval_id: str
    action_id: str
    role: str
    person_id: str
    via_grant_id: str | None
    evidence_version: str
    at: datetime | None
    source: str
    problem: str = ""


@dataclass(frozen=True)
class Event:
    kind: str
    at: datetime | None
    approval_id: str
    from_version: str
    to_version: str
    to_path: str
    to_sha256: str
    reason: str
    source: str
    problem: str = ""


@dataclass(frozen=True)
class Completion:
    declared_by: str
    evidence_path: str
    evidence_sha256: str
    evidence_version: str
    source: str
    declared_at: datetime | None


@dataclass(frozen=True)
class ActionEntry:
    action_id: str
    action_revision: str
    completion: Completion | None
    approvals: tuple[Approval, ...]
    events: tuple[Event, ...]
    source: str
    owner_person_id: str = ""
    revision_summary: dict[str, Any] | None = None
    problem: str = ""


@dataclass(frozen=True)
class Book:
    decided_at: datetime | None
    event_budget: int
    people: dict[str, Person]
    role_holders: tuple[RoleHolder, ...]
    grants: dict[str, Grant]
    revocations: tuple[Revocation, ...]
    actions: dict[str, ActionEntry]
    issues: tuple[dict[str, str], ...]
    valid: bool
    path: str
    sha256: str


def review_book_file(actions: Any, book_path: Any, evidence_root: Any) -> dict[str, Any]:
    """Review actions against an optional approval book on disk.

    Imported lazily so the record types stay independent of the verdict layer.
    """
    from .approvals_verdict import review_book_file as _review

    return _review(actions, book_path, evidence_root)


def review_actions(actions: Any, book: Book, evidence_root: Any) -> dict[str, Any]:
    """Review actions against an already loaded approval book."""
    from .approvals_verdict import review_actions as _review

    return _review(actions, book, evidence_root)


def no_book_review(actions: Any) -> dict[str, Any]:
    """Every action stays open when no approval book was supplied."""
    from .approvals_verdict import no_book_review as _review

    return _review(actions)
