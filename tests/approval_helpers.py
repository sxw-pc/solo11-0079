"""Shared synthetic approval-book builders for the closure-review tests."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any

from drillverify.actions import PlanAction

E1 = "evidence/completion-e1.txt"
E2 = "evidence/completion-e2.txt"


def action(action_id: str = "act-alpha", revision: str = "rev-1", owner: str = "team-alpha") -> PlanAction:
    return PlanAction(
        action_id=action_id,
        priority="high",
        category="chain_integrity",
        owner_team=owner,
        dataset_id="ds-orders",
        object_type="backup",
        object_id="bk-orders-030",
        rule_id="CHAIN-001",
        rule_ids=("CHAIN-001",),
        title="Backup parent is missing: backup bk-orders-030",
        rationale="Incremental parent is absent.",
        instruction="Rebuild a complete chain rooted at a full backup.",
        due_at="2026-11-13",
        probes=({"rule_id": "CHAIN-001", "file": "catalog/backup_catalog.csv",
                 "line": 12, "input_sha256": "a" * 64},),
        revision=revision,
        source_inputs=("a" * 64,),
    )


def evidence_root(tmp_path: Path) -> Path:
    root = tmp_path / "fixtures"
    (root / "evidence").mkdir(parents=True)
    (root / E1).write_text("E1 restore evidence\n", encoding="utf-8")
    (root / E2).write_text("E2 replacement evidence\n", encoding="utf-8")
    return root


def digest(root: Path, ref: str) -> str:
    return hashlib.sha256((root / ref).read_bytes()).hexdigest()


def base_book(root: Path, target: PlanAction | None = None) -> dict[str, Any]:
    """A fully valid book: Alice declares, Bob (via Clara) and Dave approve E1."""
    target = target or action()
    return {
        "schema": 1,
        "decided_at": "2026-11-12T00:00:00Z",
        "event_budget": 8,
        "people": [
            {"person_id": "alice", "display_name": "Alice", "team": "team-alpha",
             "identity_id": "person-alice", "source": "roster:alice"},
            {"person_id": "bob", "display_name": "Bob", "team": "team-beta",
             "identity_id": "person-bob", "source": "roster:bob"},
            {"person_id": "dave", "display_name": "Dave", "team": "team-gamma",
             "identity_id": "person-dave", "source": "roster:dave"},
            {"person_id": "clara", "display_name": "Clara", "team": "compliance",
             "identity_id": "person-clara", "source": "roster:clara"},
        ],
        "role_holders": [
            {"role": "compliance", "person_id": "clara", "source": "roster:compliance"},
            {"role": "independent_verifier", "person_id": "dave", "source": "roster:iv"},
        ],
        "delegations": [
            {"grant_id": "g-clara-bob", "role": "compliance", "from_person_id": "clara",
             "to_person_id": "bob", "granted_at": "2026-11-01T00:00:00Z",
             "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g-clara-bob"},
        ],
        "delegation_events": [],
        "actions": [{
            "action_id": target.action_id,
            "action_revision": target.revision,
            "owner_person_id": "alice",
            "source": "book:act-alpha",
            "completion": {
                "declared_by": "alice", "evidence_path": E1,
                "evidence_sha256": digest(root, E1), "evidence_version": "E1",
                "declared_at": "2026-11-05T00:00:00Z", "source": "completion:act-alpha",
            },
            "approvals": [
                {"approval_id": "a-bob", "action_id": target.action_id, "role": "compliance",
                 "person_id": "bob", "via_grant_id": "g-clara-bob", "evidence_version": "E1",
                 "at": "2026-11-06T00:00:00Z", "source": "approval:a-bob"},
                {"approval_id": "a-dave", "action_id": target.action_id,
                 "role": "independent_verifier", "person_id": "dave",
                 "via_grant_id": "", "evidence_version": "E1",
                 "at": "2026-11-07T00:00:00Z", "source": "approval:a-dave"},
            ],
            "events": [],
        }],
    }


def clone(raw: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(raw)


def entry(raw: dict[str, Any]) -> dict[str, Any]:
    return raw["actions"][0]


def person(raw: dict[str, Any], person_id: str) -> dict[str, Any]:
    return next(item for item in raw["people"] if item["person_id"] == person_id)


def approval(raw: dict[str, Any], approval_id: str) -> dict[str, Any]:
    return next(item for item in entry(raw)["approvals"] if item["approval_id"] == approval_id)


def revoked_before_decision(raw: dict[str, Any]) -> dict[str, Any]:
    raw["delegation_events"].append({
        "grant_id": "g-clara-bob", "at": "2026-11-11T00:00:00Z",
        "reason": "Clara revoked the compliance delegation to Bob",
        "source": "delegation_event:revoke-g-clara-bob",
    })
    return raw
