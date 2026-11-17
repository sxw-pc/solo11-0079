"""Closure decisions, reason text and the aggregate review document."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .actions import revision_for
from .approvals import STATUS_CLOSED, STATUS_OPEN, STATUS_PENDING, STATUS_REOPENED, STATUS_UNPROVEN, ActionEntry, Book
from .approvals_auth import applied_events
from .approvals_load import load_book_file
from .approvals_review import _base_breaks, _dedupe, _evaluate
from .timeutil import format_utc


def _open_decision(action: Any, note: str) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "action_revision": revision_for(action),
        "revision_matches": True,
        "title": action.title,
        "owner_team": action.owner_team,
        "status": STATUS_OPEN,
        "closure_claimed": False,
        "evidence": None,
        "declared_by": None,
        "approvers": [],
        "contracts": {"historical": {"status": STATUS_OPEN, "approvers": [], "breaks": []},
                      "current": {"status": STATUS_OPEN, "approvers": [], "breaks": []}},
        "withdrawals": [],
        "events": [],
        "witness": [],
        "reason": note,
        "event_count": 0,
        "event_budget": 0,
        "claims_recovery_success": False,
    }


def _reason(status: str, witness: list[dict[str, str]], withdrawn: list[dict[str, Any]],
            replacements: list[dict[str, Any]] | None = None) -> str:
    if status == STATUS_CLOSED:
        return ("process closure recorded under both authorization contracts; "
                "technical recovery is not asserted")
    if status == STATUS_REOPENED:
        if withdrawn:
            return (f"reopened: approval {withdrawn[0]['approval_id']} was withdrawn "
                    f"({withdrawn[0]['reason'] or 'no reason recorded'})")
        if replacements:
            return (f"reopened: evidence {replacements[0]['from_version']} was replaced by "
                    f"{replacements[0]['to_version']} ({replacements[0]['source']})")
        return "reopened: an evidence replacement or withdrawal invalidated the prior closure"
    head = witness[0] if witness else None
    if status == STATUS_PENDING:
        return (f"pending re-approval: {head['code']} - {head['detail']}" if head
                else "pending re-approval: two independent approvals are not satisfied")
    return (f"unproven: {head['code']} - {head['detail']}" if head
            else "unproven: required identity, evidence or budget is missing")


def _decision(book: Book, action: Any, entry: ActionEntry, evidence_root: Path) -> dict[str, Any]:
    if book.decided_at is None:
        decision = _open_decision(
            action, "unproven: closure decision time is invalid; no closure was evaluated")
        decision["status"] = STATUS_UNPROVEN
        decision["witness"] = [{"code": "decided_at_invalid",
                                "detail": "closure decision time is not valid",
                                "source": book.path, "role": "", "approval_id": "",
                                "grant_id": ""}]
        decision["contracts"] = {
            "historical": {"status": STATUS_UNPROVEN, "approvers": [], "breaks": decision["witness"]},
            "current": {"status": STATUS_UNPROVEN, "approvers": [], "breaks": decision["witness"]},
        }
        return decision
    revision = revision_for(action)
    evidence, base_breaks = _base_breaks(book, entry, evidence_root)
    historical = _evaluate(book, entry, evidence, revision, book.decided_at, False)
    current = _evaluate(book, entry, evidence, revision, book.decided_at, True)
    applied = applied_events(entry.events, book.decided_at)
    withdrawn = [item for item in applied if item.kind == "approval_withdrawn"]
    replacements = [item for item in applied if item.kind == "evidence_replaced"]
    prior = [item for item in entry.approvals if item.at is not None and any(
        event.at is not None and item.at <= event.at for event in applied)]
    invalidated = (bool(prior) and bool(replacements or withdrawn)
                   and not (historical["closed"] and current["closed"]))
    if base_breaks:
        for contract in (historical, current):
            contract["status"] = STATUS_UNPROVEN
        status = STATUS_UNPROVEN
    elif invalidated:
        for contract in (historical, current):
            if not contract["closed"]:
                contract["status"] = STATUS_REOPENED
        status = STATUS_REOPENED
    elif current["closed"]:
        status = STATUS_CLOSED
    else:
        status = STATUS_PENDING
    witness = _dedupe(base_breaks + historical["breaks"] + current["breaks"])
    completion = entry.completion
    declarer = book.people.get(completion.declared_by) if completion else None
    if declarer is not None:
        declared_by = {"person_id": declarer.person_id, "display_name": declarer.display_name,
                       "identity_id": declarer.identity_id, "team": declarer.team}
    else:
        declared_by = {"person_id": completion.declared_by} if completion else None
    withdrawals = [{"approval_id": item.approval_id, "reason": item.reason,
                    "at": format_utc(item.at) if item.at else None, "source": item.source}
                   for item in withdrawn]
    return {
        "action_id": action.action_id,
        "action_revision": revision,
        "revision_matches": entry.action_revision == revision,
        "title": action.title,
        "owner_team": action.owner_team,
        "status": status,
        "closure_claimed": status == STATUS_CLOSED,
        "evidence": evidence,
        "declared_by": declared_by,
        "approvers": current["approvers"] or historical["approvers"],
        "contracts": {
            "historical": {"status": historical["status"],
                           "approvers": historical["approvers"],
                           "breaks": historical["breaks"]},
            "current": {"status": current["status"], "approvers": current["approvers"],
                        "breaks": current["breaks"]},
        },
        "withdrawals": withdrawals,
        "events": [{"event": item.kind, "at": format_utc(item.at) if item.at else None,
                    "approval_id": item.approval_id, "from_version": item.from_version,
                    "to_version": item.to_version, "reason": item.reason,
                    "source": item.source} for item in applied],
        "witness": witness,
        "reason": _reason(status, witness, withdrawals, [
            {"from_version": item.from_version, "to_version": item.to_version,
             "source": item.source} for item in replacements]),
        "event_count": len(entry.approvals) + len(entry.events),
        "event_budget": book.event_budget,
        "claims_recovery_success": False,
    }


def _summary(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {status: 0 for status in (
        STATUS_CLOSED, STATUS_PENDING, STATUS_REOPENED, STATUS_UNPROVEN, STATUS_OPEN)}
    for decision in decisions:
        counts[decision["status"]] += 1
    return {
        "action_count": len(decisions),
        "closed": counts[STATUS_CLOSED],
        "pending_reapproval": counts[STATUS_PENDING],
        "reopened": counts[STATUS_REOPENED],
        "unproven": counts[STATUS_UNPROVEN],
        "open": counts[STATUS_OPEN],
        "claims_recovery_success": False,
    }


def review_actions(actions: Any, book: Book, evidence_root: Path) -> dict[str, Any]:
    owners: dict[str, list[str]] = {}
    for action_id, entry in book.actions.items():
        for approval in entry.approvals:
            owners.setdefault(approval.approval_id, []).append(action_id)
    decisions = []
    for action in actions:
        entry = book.actions.get(action.action_id)
        if entry is None:
            decisions.append(_open_decision(
                action, "no approval record for this action; the original plan entry is unchanged"))
            continue
        decision = _decision(book, action, entry, evidence_root)
        reused = [item.approval_id for item in entry.approvals
                  if len(set(owners.get(item.approval_id, []))) > 1]
        if reused:
            decision["witness"].append({
                "code": "approval_reused_across_actions",
                "detail": "approval id is recorded under more than one action",
                "source": entry.source, "role": "", "approval_id": reused[0], "grant_id": "",
            })
            decision["status"] = STATUS_PENDING
            decision["closure_claimed"] = False
            for contract in decision["contracts"].values():
                if contract["status"] == STATUS_CLOSED:
                    contract["status"] = STATUS_PENDING
        decisions.append(decision)
    return {
        "availability": "approval_book" if book.valid else "invalid_approval_book",
        "book": {"path": book.path, "sha256": book.sha256,
                 "decided_at": format_utc(book.decided_at) if book.decided_at else None},
        "issues": list(book.issues),
        "summary": _summary(decisions),
        "decisions": decisions,
    }


def no_book_review(actions: Any) -> dict[str, Any]:
    decisions = [_open_decision(
        action, "no approval book; the original plan entry is shown without a closure claim")
        for action in actions]
    return {"availability": "no_approval_book", "book": None, "issues": [],
            "summary": _summary(decisions), "decisions": decisions}


def review_book_file(actions: Any, book_path: Path, evidence_root: Path) -> dict[str, Any]:
    """Review actions against an optional approval book on disk."""
    book = load_book_file(book_path)
    return no_book_review(actions) if book is None else review_actions(actions, book, evidence_root)
