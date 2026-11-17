"""Two authorization contracts and separation-of-duties regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from approval_helpers import (
    action, approval, base_book, entry, evidence_root, person, revoked_before_decision,
)
from drillverify.approvals_load import load_book
from drillverify.approvals_verdict import review_actions


def review(raw, root: Path, actions=None):
    book = load_book(raw, "approval-book.json", "f" * 64)
    return review_actions(actions or [action()], book, root)


def decision(raw, root: Path, actions=None):
    return review(raw, root, actions)["decisions"][0]


def test_historical_and_current_contracts_are_reported_side_by_side(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = revoked_before_decision(base_book(root))
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert result["contracts"]["historical"]["status"] == "closed"
    assert result["contracts"]["current"]["status"] == "pending_reapproval"
    codes = {item["code"] for item in result["contracts"]["current"]["breaks"]}
    assert "grant_revoked" in codes
    assert result["claims_recovery_success"] is False
    assert "grant_revoked" in {item["code"] for item in result["witness"]}


def test_valid_book_closes_both_contracts_without_claiming_recovery(tmp_path: Path):
    root = evidence_root(tmp_path)
    result = decision(base_book(root), root)
    assert result["status"] == "closed"
    assert result["contracts"]["historical"]["status"] == "closed"
    assert result["contracts"]["current"]["status"] == "closed"
    assert result["evidence"]["version"] == "E1"
    assert result["evidence"]["verified"] is True
    assert result["declared_by"]["identity_id"] == "person-alice"
    roles = {item["role"] for item in result["approvers"]}
    assert roles == {"compliance", "independent_verifier"}
    bob = next(item for item in result["approvers"] if item["person_id"] == "bob")
    assert bob["authorization"] == "delegated"
    assert bob["authorization_path"] == ["person-clara", "person-bob"] or \
        bob["authorization_path"] == ["clara", "bob"]
    assert result["claims_recovery_success"] is False


def test_same_actual_person_in_two_roles_never_closes(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    person(raw, "bob")["identity_id"] = "person-alice"
    person(raw, "dave")["alias_of"] = "bob"
    person(raw, "dave")["identity_id"] = "person-alice"
    result = decision(raw, root)
    assert result["contracts"]["historical"]["status"] != "closed"
    assert result["contracts"]["current"]["status"] != "closed"
    codes = {item["code"] for item in result["witness"]}
    assert "separation_of_duties" in codes


def test_alias_identities_do_not_satisfy_two_person_control(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    person(raw, "bob")["identity_id"] = "person-bob"
    person(raw, "dave")["identity_id"] = ""  # alias-only identity
    result = decision(raw, root)
    assert result["status"] == "unproven"
    codes = {item["code"] for item in result["witness"]}
    assert "identity_missing" in codes


def test_owner_cannot_self_approve_through_delegated_role(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["owner_person_id"] = "bob"  # Bob is the delegated compliance approver
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    codes = {item["code"] for item in result["witness"]}
    assert "self_approval" in codes


def test_declarer_cannot_approve_their_own_completion(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["delegations"].append({
        "grant_id": "g-dave-alice", "role": "independent_verifier",
        "from_person_id": "dave", "to_person_id": "alice",
        "granted_at": "2026-11-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z",
        "source": "delegation:g-dave-alice",
    })
    approval(raw, "a-dave").update(person_id="alice", via_grant_id="g-dave-alice")
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    codes = {item["code"] for item in result["witness"]}
    assert "self_approval" in codes


@pytest.mark.parametrize("mutate, code", [
    (lambda raw: raw["delegations"][0].update(expires_at="2026-11-05T00:00:00Z"), "grant_expired"),
    (lambda raw: raw["delegations"][0].update(expires_at=None), "grant_no_expiry"),
    (lambda raw: raw["delegations"][0].update(expires_at="2026-11-01T00:00:00Z"), "grant_malformed"),
    (lambda raw: raw["delegations"][0].update(granted_at="2026-11-06T12:00:00Z"), "grant_not_yet_valid"),
])
def test_delegation_time_bounds_are_enforced(tmp_path: Path, mutate, code):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    mutate(raw)
    result = decision(raw, root)
    assert result["contracts"]["historical"]["status"] != "closed"
    assert code in {item["code"] for item in result["witness"]}


def test_delegation_chain_cycle_is_detected(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["delegations"] = [
        {"grant_id": "g1", "role": "compliance", "from_person_id": "clara",
         "to_person_id": "bob", "granted_at": "2026-11-01T00:00:00Z",
         "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g1"},
        {"grant_id": "g2", "role": "compliance", "from_person_id": "bob",
         "to_person_id": "clara", "granted_at": "2026-11-01T00:00:00Z",
         "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g2"},
    ]
    raw["role_holders"] = [
        {"role": "compliance", "person_id": "erin", "source": "roster:compliance"},
        {"role": "independent_verifier", "person_id": "dave", "source": "roster:iv"},
    ]
    raw["people"].append({"person_id": "erin", "display_name": "Erin",
                          "team": "compliance", "identity_id": "person-erin"})
    raw["delegations"] = [
        {"grant_id": "g-a", "role": "compliance", "from_person_id": "clara",
         "to_person_id": "bob", "granted_at": "2026-11-01T00:00:00Z",
         "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g-a"},
        {"grant_id": "g-b", "role": "compliance", "from_person_id": "bob",
         "to_person_id": "clara", "granted_at": "2026-11-01T00:00:00Z",
         "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g-b"},
    ]
    approval(raw, "a-bob")["via_grant_id"] = "g-a"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "grant_cycle" in {item["code"] for item in result["witness"]}


def test_role_boundary_prevents_compliance_grant_to_iv_holder(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    approval(raw, "a-bob")["via_grant_id"] = "g-dave-iv"
    raw["delegations"].append({
        "grant_id": "g-dave-iv", "role": "independent_verifier", "from_person_id": "dave",
        "to_person_id": "bob", "granted_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g-dave-iv",
    })
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "role_boundary_crossed" in {item["code"] for item in result["witness"]}


def test_grant_from_unauthorized_grantor_is_rejected(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["delegations"].append({
        "grant_id": "g-alice-bob", "role": "compliance", "from_person_id": "alice",
        "to_person_id": "bob", "granted_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z", "source": "delegation:g-alice-bob",
    })
    approval(raw, "a-bob")["via_grant_id"] = "g-alice-bob"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "grantor_unauthorized" in {item["code"] for item in result["witness"]}


def test_event_order_matters_approval_after_decision_is_ignored(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    approval(raw, "a-dave")["at"] = "2026-11-13T00:00:00Z"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "approval_after_decision" in {item["code"] for item in result["witness"]}
    assert result["contracts"]["historical"]["status"] == "pending_reapproval"


def test_grant_not_yet_valid_when_signed_before_grant(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["delegations"][0]["granted_at"] = "2026-11-07T00:00:00Z"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "grant_not_yet_valid" in {item["code"] for item in result["witness"]}


def test_grant_expiring_exactly_at_signature_does_not_authorize(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["delegations"][0]["expires_at"] = "2026-11-06T00:00:00Z"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "grant_expired" in {item["code"] for item in result["witness"]}
