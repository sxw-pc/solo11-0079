"""Closure verdict assembly for remediation actions.

A verdict answers one narrow question: may the *process* around an action be
recorded as closed? It never asserts that remediation succeeded, and it never
rewrites backup chains, RPO/RTO results or action schedules.

Two authorization contracts are evaluated side by side:

* ``historical`` — two independent approvers were authorized when they signed,
  even if a delegation was revoked later;
* ``current`` — the delegation chain must also still be valid at the decision.

Counting ``approved`` events is never sufficient: each approval must bind to the
action revision and evidence version, and identities must be truly distinct.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .actions import action_revision
from .approvals import ROLES, STATUS_CLOSED, STATUS_PENDING, ActionEntry, Book
from .approvals_auth import applied_events, authorize, break_witness, evidence_state


def _dedupe(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    for item in items:
        key = (item.get("code"), item.get("role"), item.get("approval_id"),
               item.get("grant_id"), item.get("source"))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _candidate(book: Book, approval: Any, entry: ActionEntry, evidence: dict[str, Any],
               decided_at: datetime, strict: bool) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    """Check one approval's binding; return its approver record or breaks."""
    if approval.at is None or approval.at > decided_at:
        return None, [break_witness("approval_after_decision",
                                    "approval signed after the closure decision",
                                    source=approval.source, role=approval.role,
                                    approval_id=approval.approval_id)]
    if not approval.action_id:
        return None, [break_witness("approval_action_missing",
                                    "approval does not cite an action_id",
                                    source=approval.source, role=approval.role,
                                    approval_id=approval.approval_id)]
    if approval.action_id != entry.action_id:
        return None, [break_witness("approval_reused", "approval belongs to another action",
                                    source=approval.source, role=approval.role,
                                    approval_id=approval.approval_id)]
    if approval.evidence_version != evidence.get("version"):
        return None, [break_witness("evidence_version_mismatch",
                                    "approval is bound to a different evidence version",
                                    source=approval.source, role=approval.role,
                                    approval_id=approval.approval_id)]
    signer, sign_breaks = authorize(book, approval, approval.at)
    if sign_breaks:
        return None, [dict(item, role=item.get("role") or approval.role,
                           approval_id=item.get("approval_id") or approval.approval_id)
                      for item in sign_breaks]
    _, now_breaks = authorize(book, approval, decided_at)
    approver = dict(signer or {}, valid_at_decision=not now_breaks)
    if now_breaks:
        approver["decision_breaks"] = now_breaks
        if strict:
            return None, [dict(item, role=item.get("role") or approval.role,
                               approval_id=item.get("approval_id") or approval.approval_id)
                          for item in now_breaks]
    return approver, []


def _duties(book: Book, entry: ActionEntry, approvers: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Independence checks that a mere event count would miss."""
    breaks: list[dict[str, str]] = []
    if len(approvers) != 2:
        return breaks
    first, second = approvers
    if not first["identity_id"] or not second["identity_id"]:
        return [break_witness("identity_missing",
                              "one or more approvers has no actual person identity")]
    if first["identity_id"] == second["identity_id"]:
        breaks.append(break_witness(
            "separation_of_duties",
            f"{first['identity_id']} filled both approval roles; aliases do not create independence"))
    forbidden: dict[str, str] = {}
    declarer = entry.completion.declared_by if entry.completion else ""
    if declarer in book.people:
        forbidden[book.people[declarer].identity_id] = "declared completion"
    if entry.owner_person_id in book.people:
        forbidden[book.people[entry.owner_person_id].identity_id] = "owns the action"
    for approver in approvers:
        relation = forbidden.get(approver["identity_id"], "")
        if relation:
            breaks.append(break_witness(
                "self_approval",
                f"{approver['identity_id']} {relation} and also approved through "
                f"{approver['role']}",
                source=approver.get("source", ""), role=approver["role"],
                approval_id=approver["approval_id"]))
    return breaks


def _evaluate(book: Book, entry: ActionEntry, evidence: dict[str, Any], revision: str,
              decided_at: datetime, strict: bool) -> dict[str, Any]:
    breaks: list[dict[str, str]] = []
    if entry.action_revision != revision:
        detail = "approval is bound to a stale action revision and is not inherited"
        summary = entry.revision_summary or {}
        if summary:
            detail += f" (book attests priority={summary.get('priority', '?')}, " \
                      f"rules={','.join(summary.get('rule_ids', [])) or '?'})"
        breaks.append(break_witness("action_revision_changed", detail, source=entry.source))
    withdrawn = {event.approval_id: event for event in applied_events(entry.events, decided_at)
                 if event.kind == "approval_withdrawn" and event.approval_id}
    candidates: dict[str, list[tuple[Any, dict[str, Any]]]] = {role: [] for role in ROLES}
    role_breaks: dict[str, list[dict[str, str]]] = {role: [] for role in ROLES}
    for approval in entry.approvals:
        role = approval.role if approval.role in ROLES else ""
        if approval.problem:
            breaks.append(break_witness("approval_malformed", approval.problem,
                                        source=approval.source, role=role,
                                        approval_id=approval.approval_id))
            continue
        if approval.approval_id in withdrawn:
            event = withdrawn[approval.approval_id]
            role_breaks[role].append(break_witness(
                "approval_withdrawn",
                f"approval withdrawn: {event.reason or 'no reason recorded'}",
                source=event.source, role=role, approval_id=approval.approval_id))
            continue
        approver, approval_breaks = _candidate(book, approval, entry, evidence, decided_at, strict)
        if approval_breaks:
            role_breaks[role].extend(approval_breaks)
        elif approver is not None:
            candidates[role].append((approval, approver))
    chosen: dict[str, dict[str, Any]] = {}
    for role in ROLES:
        ranked = sorted(candidates[role],
                        key=lambda item: (item[0].at, item[0].source, item[0].approval_id))
        if ranked:
            chosen[role] = ranked[0][1]
        else:
            breaks.extend(role_breaks[role])
            if not role_breaks[role]:
                breaks.append(break_witness("role_unfilled", f"no active {role} approval", role=role))
    approvers = list(chosen.values())
    breaks.extend(_duties(book, entry, approvers))
    closed = len(approvers) == 2 and not breaks
    return {"status": STATUS_CLOSED if closed else STATUS_PENDING,
            "approvers": approvers, "breaks": _dedupe(breaks), "closed": closed}


def _base_breaks(book: Book, entry: ActionEntry, evidence_root: Path) -> tuple[
        dict[str, Any], list[dict[str, str]]]:
    """Book-level, identity and evidence breaks that taint both contracts."""
    evidence: dict[str, Any] = {}
    breaks: list[dict[str, str]] = []
    if not book.valid:
        breaks.append(break_witness("book_invalid",
                                    "approval book has structural issues; closure is unproven",
                                    source=book.path))
    if entry.problem:
        breaks.append(break_witness("action_entry_malformed", entry.problem, source=entry.source))
    summary = entry.revision_summary
    if summary is not None:
        try:
            recomputed = action_revision(
                str(summary.get("priority", "")),
                tuple(summary.get("rule_ids") or ()),
                tuple(summary.get("probes") or ()),
                tuple(summary.get("source_inputs") or ()),
            )
        except (TypeError, ValueError):
            recomputed = ""
        if recomputed != entry.action_revision:
            breaks.append(break_witness(
                "revision_summary_inconsistent",
                "book revision summary does not hash to the recorded revision",
                source=entry.source))
    count = len(entry.approvals) + len(entry.events)
    if count > book.event_budget:
        breaks.append(break_witness(
            "event_budget_exceeded",
            f"{count} approval/withdrawal events exceed budget {book.event_budget}; "
            "closure is not inferred from event count", source=entry.source))
    if book.decided_at is None:
        breaks.append(break_witness("decided_at_invalid",
                                    "closure decision time is not valid", source=book.path))
    else:
        evidence, evidence_breaks = evidence_state(entry, evidence_root, book.decided_at)
        breaks.extend(evidence_breaks)
    for approval in entry.approvals:
        if approval.problem:
            breaks.append(break_witness("approval_malformed", approval.problem,
                                        source=approval.source, role=approval.role,
                                        approval_id=approval.approval_id))
    for event in entry.events:
        if event.problem:
            breaks.append(break_witness("event_malformed", event.problem, source=event.source))
    if not entry.owner_person_id:
        breaks.append(break_witness("owner_identity_missing",
                                    "action owner has no declared actual person",
                                    source=entry.source))
    referenced = {item.person_id for item in entry.approvals}
    referenced.add(entry.owner_person_id)
    if entry.completion:
        referenced.add(entry.completion.declared_by)
    referenced.discard("")
    for person_id in sorted(referenced):
        person = book.people.get(person_id)
        if person is None:
            breaks.append(break_witness("person_unknown",
                                        f"person {person_id or '(blank)'} is not declared",
                                        source=entry.source))
        elif not person.identity_id:
            breaks.append(break_witness(
                "identity_missing",
                f"person {person_id} has no actual identity; aliases cannot substitute",
                source=person.source))
    seen: set[str] = set()
    for approval in entry.approvals:
        if approval.approval_id in seen:
            breaks.append(break_witness("approval_duplicate",
                                        f"approval {approval.approval_id} is recorded twice",
                                        source=entry.source))
        seen.add(approval.approval_id)
    return evidence, _dedupe(breaks)
