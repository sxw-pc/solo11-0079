"""Authorization-path resolution and completion-evidence binding.

Every approval must resolve to a direct role, or to a time-bounded delegation
chain that ends at a direct role holder. Chains are walked from the cited grant
upward; cycles, expired grants, revocations, role mismatches and unauthorized
grantors each yield a named break rather than a silent pass.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .approvals import Book, Approval, Event, Grant

ROLE_LABELS = {"compliance": "compliance approval",
               "independent_verifier": "independent verification"}
from .paths import UnsafePath, resolve_under, sha256_file
from .timeutil import format_utc

HEX64_LENGTH = 64


def break_witness(
    code: str,
    detail: str,
    *,
    source: str = "",
    role: str = "",
    approval_id: str = "",
    grant_id: str = "",
) -> dict[str, str]:
    return {
        "code": code,
        "detail": detail,
        "source": source,
        "role": role,
        "approval_id": approval_id,
        "grant_id": grant_id,
    }


def direct_source(book: Book, role: str, person_id: str) -> str:
    for holder in book.role_holders:
        if holder.role == role and holder.person_id == person_id:
            return holder.source
    return ""


def grant_problem(book: Book, grant: Grant, at: datetime) -> dict[str, str] | None:
    if grant.problem:
        return break_witness("grant_malformed", grant.problem, source=grant.source, grant_id=grant.grant_id)
    if grant.expires_at is None:
        return break_witness("grant_no_expiry", "delegation is not time-bounded", source=grant.source, grant_id=grant.grant_id)
    if grant.granted_at is None or at < grant.granted_at:
        return break_witness("grant_not_yet_valid", "delegation was not granted yet", source=grant.source, grant_id=grant.grant_id)
    if at >= grant.expires_at:
        return break_witness("grant_expired", "delegation expired", source=grant.source, grant_id=grant.grant_id)
    for revocation in book.revocations:
        if revocation.grant_id == grant.grant_id and revocation.at is not None and revocation.at <= at:
            return break_witness(
                "grant_revoked",
                f"delegation revoked: {revocation.reason or 'no reason recorded'}",
                source=revocation.source,
                grant_id=grant.grant_id,
            )
    return None


def grant_chain(
    book: Book, grant_id: str, at: datetime, seen: tuple[str, ...] = ()
) -> tuple[list[str], list[dict[str, str]]]:
    """Return a valid path (cited grant first) or the witnessed breaks."""
    grant = book.grants.get(grant_id)
    if grant is None:
        return [], [break_witness("grant_unknown", f"delegation {grant_id} is not recorded", grant_id=grant_id)]
    problem = grant_problem(book, grant, at)
    if problem:
        return [], [problem]
    if grant_id in seen:
        return [], [break_witness("grant_cycle", "delegation chain contains a cycle", source=grant.source, grant_id=grant_id)]
    if direct_source(book, grant.role, grant.from_person_id):
        return [grant_id], []
    parents = sorted(
        item.grant_id for item in book.grants.values()
        if item.to_person_id == grant.from_person_id and item.role == grant.role
    )
    if not parents:
        other = next(
            (holder.role for holder in book.role_holders
             if holder.person_id == grant.from_person_id and holder.role != grant.role),
            "",
        )
        if other:
            return [], [break_witness(
                "role_boundary_crossed",
                f"{grant.from_person_id} holds {other}, not {grant.role}",
                source=grant.source, grant_id=grant.grant_id,
            )]
        return [], [break_witness(
            "grantor_unauthorized",
            f"{grant.from_person_id} holds no {grant.role} authority",
            source=grant.source, grant_id=grant.grant_id,
        )]
    breaks: list[dict[str, str]] = []
    for parent_id in parents:
        parent = book.grants[parent_id]
        if parent.granted_at is None or (grant.granted_at is not None and parent.granted_at > grant.granted_at):
            breaks.append(break_witness(
                "grant_chain_order", "parent delegation was granted after the child",
                source=grant.source, grant_id=grant.grant_id,
            ))
            continue
        path, deeper = grant_chain(book, parent_id, at, seen + (grant_id,))
        if not deeper:
            return [grant_id] + path, []
        breaks.extend(deeper)
    return [], breaks


def authorize(book: Book, approval: Approval, at: datetime) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Resolve one approval to a person and an authorization path at ``at``."""
    person = book.people.get(approval.person_id)
    if person is None:
        return None, [break_witness("person_unknown", "approval person is not declared", source=approval.source, role=approval.role, approval_id=approval.approval_id)]
    base = {
        "approval_id": approval.approval_id,
        "role": approval.role,
        "role_label": ROLE_LABELS.get(approval.role, approval.role),
        "person_id": person.person_id,
        "display_name": person.display_name,
        "identity_id": person.identity_id,
        "team": person.team,
        "signed_at": format_utc(approval.at) if approval.at else None,
        "evidence_version": approval.evidence_version,
        "source": approval.source,
    }
    if direct_source(book, approval.role, approval.person_id):
        return dict(base, authorization="direct", grant_ids=[],
                    authorization_path=[person.person_id]), []
    if not approval.via_grant_id:
        return None, [break_witness("authorization_missing", "no direct role and no delegation cited", source=approval.source, role=approval.role, approval_id=approval.approval_id)]
    grant = book.grants.get(approval.via_grant_id)
    if grant is None:
        return None, [break_witness("grant_unknown", "cited delegation is not recorded", source=approval.source, role=approval.role, approval_id=approval.approval_id, grant_id=approval.via_grant_id)]
    if grant.role != approval.role:
        return None, [break_witness("role_boundary_crossed", "delegation is for a different role", source=grant.source, role=approval.role, approval_id=approval.approval_id, grant_id=grant.grant_id)]
    if grant.to_person_id != approval.person_id:
        return None, [break_witness("grant_person_mismatch", "delegation was issued to another person", source=grant.source, role=approval.role, approval_id=approval.approval_id, grant_id=grant.grant_id)]
    chain, breaks = grant_chain(book, grant.grant_id, at)
    if breaks:
        for item in breaks:
            item["role"] = item.get("role") or approval.role
            item["approval_id"] = item.get("approval_id") or approval.approval_id
        return None, breaks
    people: list[str] = []
    for grant_id in reversed(chain):
        item = book.grants[grant_id]
        if not people:
            people.append(item.from_person_id)
        people.append(item.to_person_id)
    return dict(base, authorization="delegated", grant_ids=chain,
                authorization_path=people), []


def applied_events(events: Iterable[Event], decided_at: datetime) -> list[Event]:
    return sorted(
        (item for item in events if item.at is not None and item.at <= decided_at and not item.problem),
        key=lambda item: (item.at, item.source, item.kind),
    )


def evidence_state(
    entry: Any, evidence_root: Path, decided_at: datetime
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Resolve the effective completion-evidence version and verify its bytes."""
    completion = entry.completion
    if completion is None:
        return {}, [break_witness("completion_missing", "no completion declaration is recorded", source=entry.source)]
    path, digest = completion.evidence_path, completion.evidence_sha256
    version = completion.evidence_version
    if not version:
        return {}, [break_witness("evidence_version_missing", "completion has no evidence version", source=completion.source)]
    if not completion.declared_by:
        return {}, [break_witness("declarer_missing", "completion has no declaring person", source=completion.source)]
    for event in applied_events(entry.events, decided_at):
        if event.kind != "evidence_replaced":
            continue
        if not event.to_version:
            return {}, [break_witness("evidence_replacement_malformed", "replacement event has no to_version", source=event.source)]
        version = event.to_version
        if event.to_path:
            path = event.to_path
        if event.to_sha256:
            digest = event.to_sha256
    evidence = {
        "path": path, "sha256": digest, "version": version, "verified": False,
        "declared_by": completion.declared_by,
        "declared_at": format_utc(completion.declared_at) if completion.declared_at else None,
        "source": completion.source,
    }
    if not path:
        return evidence, [break_witness("evidence_path_missing", "completion evidence path missing", source=completion.source)]
    if not _is_hex64(digest):
        return evidence, [break_witness("evidence_digest_invalid", "evidence SHA-256 is not 64 lowercase hex", source=completion.source)]
    try:
        resolved = resolve_under(evidence_root, path, field="evidence_path")
    except UnsafePath as exc:
        return evidence, [break_witness("evidence_path_unsafe", str(exc), source=completion.source)]
    if not resolved.is_file():
        return evidence, [break_witness("evidence_file_missing", "completion evidence file is absent", source=path)]
    actual = sha256_file(resolved)
    if actual != digest:
        return dict(evidence, actual_sha256=actual), [break_witness("evidence_digest_mismatch", "completion evidence digest does not match the file", source=path)]
    return dict(evidence, verified=True), []


def _is_hex64(value: str) -> bool:
    return len(value) == HEX64_LENGTH and all(char in "0123456789abcdef" for char in value)
