"""Revision binding, evidence replacement, withdrawal, budget and order cases."""

from __future__ import annotations

from pathlib import Path

from approval_helpers import (
    E2, action, approval, base_book, clone, digest, entry, evidence_root,
)
from drillverify.actions import action_revision
from drillverify.approvals_load import load_book
from drillverify.approvals_verdict import review_actions
from drillverify.planner import build_plan


def decision(raw, root: Path, actions=None):
    book = load_book(raw, "approval-book.json", "f" * 64)
    return review_actions(actions or [action()], book, root)["decisions"][0]


def test_approval_does_not_inherit_across_action_revisions(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    result = decision(raw, root, [action(revision="rev-2")])
    assert result["status"] == "pending_reapproval"
    assert result["revision_matches"] is False
    codes = {item["code"] for item in result["witness"]}
    assert "action_revision_changed" in codes


def test_planner_revision_changes_with_priority_rules_probes_or_inputs(tmp_path: Path):
    base = ("high", ("CHAIN-001",), ({"rule_id": "CHAIN-001", "file": "c",
                                       "line": 1, "input_sha256": "a" * 64},), ("a" * 64,))
    original = action_revision(*base)
    assert action_revision("critical", *base[1:]) != original
    assert action_revision(base[0], ("CHAIN-001", "CHAIN-002"), *base[2:]) != original
    moved = ({"rule_id": "CHAIN-001", "file": "c", "line": 2, "input_sha256": "a" * 64},)
    assert action_revision(base[0], base[1], moved, base[3]) != original
    assert action_revision(base[0], base[1], base[2], ("b" * 64,)) != original
    assert action_revision(*base) == original


def test_plan_actions_carry_revision_and_source_inputs(bundle):
    assert bundle.actions
    for item in bundle.actions:
        assert len(item.revision) == 16
        assert item.source_inputs == tuple(sorted(item.source_inputs))
        assert item.revision == action_revision(
            item.priority, item.rule_ids, item.probes, item.source_inputs)


def test_build_plan_is_stable_with_revisions(bundle):
    actions, summary = build_plan(bundle.plan, bundle.findings, bundle.backups, bundle.events)
    assert [item.to_dict() for item in actions] == [item.to_dict() for item in bundle.actions]
    assert summary == bundle.plan_summary


def test_approval_cannot_be_reused_for_another_action(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    other = action(action_id="act-beta", revision="rev-1")
    result = decision(raw, root, [other])
    assert result["status"] == "open"
    raw["actions"].append({**clone(entry(raw)), "action_id": "act-beta",
                           "owner_person_id": "alice"})
    raw["actions"][1]["approvals"] = clone(entry(raw)["approvals"])
    raw["actions"][1]["completion"] = {**entry(raw)["completion"]}
    book = load_book(raw, "b", "f" * 64)
    decisions = review_actions([action(), other], book, root)["decisions"]
    ids = {item["action_id"]: item for item in decisions}
    assert ids["act-beta"]["status"] in {"pending_reapproval", "unproven"}
    assert any(item["code"] == "approval_reused_across_actions"
               for item in ids["act-beta"]["witness"])


def test_evidence_replacement_reopens_with_witness(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["events"].append({
        "event": "evidence_replaced", "at": "2026-11-11T00:00:00Z",
        "approval_id": "", "from_version": "E1", "to_version": "E2",
        "to_path": E2, "to_sha256": digest(root, E2),
        "reason": "A new restore log replaced E1", "source": "event:replace-e1",
    })
    result = decision(raw, root)
    assert result["status"] == "reopened"
    assert result["evidence"]["version"] == "E2"
    codes = {item["code"] for item in result["witness"]}
    assert "evidence_version_mismatch" in codes


def test_evidence_digest_mismatch_is_unproven(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["completion"]["evidence_sha256"] = "0" * 64
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "evidence_digest_mismatch" in {item["code"] for item in result["witness"]}


def test_evidence_path_escape_is_unproven(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["completion"]["evidence_path"] = "../outside.txt"
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "evidence_path_unsafe" in {item["code"] for item in result["witness"]}


def test_approval_withdrawal_reopens_and_records_reason(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["events"].append({
        "event": "approval_withdrawn", "at": "2026-11-11T00:00:00Z",
        "approval_id": "a-bob", "reason": "Bob found an unresolved row-count gap",
        "source": "event:withdraw-a-bob",
    })
    result = decision(raw, root)
    assert result["status"] == "reopened"
    assert result["withdrawals"][0]["approval_id"] == "a-bob"
    assert "row-count gap" in result["withdrawals"][0]["reason"]
    assert "approval_withdrawn" in {item["code"] for item in result["witness"]}


def test_approval_withdrawn_and_replaced_reapproval_can_reclose(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["events"].append({
        "event": "approval_withdrawn", "at": "2026-11-11T00:00:00Z",
        "approval_id": "a-bob", "reason": "Old signature superseded",
        "source": "event:withdraw-a-bob",
    })
    entry(raw)["approvals"].append({
        "approval_id": "a-bob-2", "action_id": "act-alpha", "role": "compliance",
        "person_id": "bob", "via_grant_id": "g-clara-bob", "evidence_version": "E1",
        "at": "2026-11-11T12:00:00Z", "source": "approval:a-bob-2",
    })
    result = decision(raw, root)
    assert result["status"] == "closed"
    assert result["contracts"]["current"]["status"] == "closed"


def test_event_budget_blocks_inference_from_many_events(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["event_budget"] = 2
    entry(raw)["events"].append({
        "event": "approval_withdrawn", "at": "2026-11-11T00:00:00Z",
        "approval_id": "a-bob", "reason": "Test withdrawal", "source": "event:w",
    })
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "event_budget_exceeded" in {item["code"] for item in result["witness"]}
    assert result["claims_recovery_success"] is False


def test_many_approved_events_without_roles_do_not_close(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["event_budget"] = 20
    fillers = [
        {"approval_id": f"a-extra-{i}", "action_id": "act-alpha", "role": "compliance",
         "person_id": "bob", "via_grant_id": "g-clara-bob", "evidence_version": "E1",
         "at": f"2026-11-{7 + i:02d}T00:00:00Z", "source": f"approval:a-extra-{i}"}
        for i in range(1, 4)
    ]
    entry(raw)["approvals"].extend(fillers)
    entry(raw)["approvals"] = [item for item in entry(raw)["approvals"]
                               if item["role"] != "independent_verifier"]
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "role_unfilled" in {item["code"] for item in result["witness"]}


def test_event_after_decision_is_not_applied(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["events"].append({
        "event": "approval_withdrawn", "at": "2026-11-13T00:00:00Z",
        "approval_id": "a-bob", "reason": "Later withdrawal",
        "source": "event:late-withdraw",
    })
    result = decision(raw, root)
    assert result["status"] == "closed"
    assert result["withdrawals"] == []


def test_invalid_book_never_closes(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["decided_at"] = "not-a-timestamp"
    result = decision(raw, root)
    assert result["status"] == "unproven"
    book = load_book(raw, "b", "f" * 64)
    assert book.valid is False


def test_approval_bound_to_different_evidence_version_is_not_reused(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    approval(raw, "a-bob")["evidence_version"] = "E0"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    codes = {item["code"] for item in result["witness"]}
    assert "evidence_version_mismatch" in codes


def test_duplicate_approval_id_is_malformed(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["approvals"].append(clone(approval(raw, "a-bob")))
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "approval_duplicate" in {item["code"] for item in result["witness"]}


def test_invalid_book_structure_marks_actions_unproven(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    raw["people"].append(clone(raw["people"][0]))  # duplicate person id
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "book_invalid" in {item["code"] for item in result["witness"]}


def test_approval_citing_another_action_is_reused_not_counted(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    approval(raw, "a-bob")["action_id"] = "act-somewhere-else"
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "approval_reused" in {item["code"] for item in result["witness"]}


def test_approval_without_action_reference_is_not_counted(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    approval(raw, "a-dave")["action_id"] = ""
    result = decision(raw, root)
    assert result["status"] == "pending_reapproval"
    assert "approval_action_missing" in {item["code"] for item in result["witness"]}


def test_replacement_evidence_must_hash_match(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["events"].append({
        "event": "evidence_replaced", "at": "2026-11-11T00:00:00Z",
        "from_version": "E1", "to_version": "E2", "to_path": E2,
        "to_sha256": "f" * 64, "reason": "Replacement", "source": "event:replace",
    })
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "evidence_digest_mismatch" in {item["code"] for item in result["witness"]}


def test_book_revision_summary_must_match_recorded_revision(tmp_path: Path):
    root = evidence_root(tmp_path)
    raw = base_book(root)
    entry(raw)["revision_summary"] = {
        "priority": "critical", "rule_ids": ["CHAIN-001"],
        "probes": [{"rule_id": "CHAIN-001", "file": "catalog/backup_catalog.csv",
                    "line": 12, "input_sha256": "a" * 64}],
        "source_inputs": ["a" * 64],
    }
    result = decision(raw, root)
    assert result["status"] == "unproven"
    assert "revision_summary_inconsistent" in {item["code"] for item in result["witness"]}


def test_book_revision_summary_matching_revision_is_accepted(tmp_path: Path):
    root = evidence_root(tmp_path)
    target = action(revision="")
    revision = action_revision(target.priority, target.rule_ids,
                               target.probes, target.source_inputs)
    target = action(revision=revision)
    raw = base_book(root, target)
    entry(raw)["revision_summary"] = {
        "priority": target.priority, "rule_ids": list(target.rule_ids),
        "probes": list(target.probes), "source_inputs": list(target.source_inputs),
    }
    result = decision(raw, root, [target])
    assert result["status"] == "closed"
