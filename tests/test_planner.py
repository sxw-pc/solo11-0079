from __future__ import annotations

from drillverify.planner import build_plan


def test_plan_actions_are_sorted_and_owner_assigned(bundle):
    assert bundle.actions
    keys = [item.sort_key() for item in bundle.actions]
    assert keys == sorted(keys)
    assert len({item.action_id for item in bundle.actions}) == len(bundle.actions)
    assert {item.owner_team for item in bundle.actions} >= {"team-alpha", "team-beta"}
    assert all(item.due_at >= "2026-11-10" for item in bundle.actions)
    assert all(item.rule_ids for item in bundle.actions)


def test_related_chain_findings_are_grouped(bundle):
    actions = [
        item
        for item in bundle.actions
        if item.object_type == "backup" and item.object_id == "bk-events-018"
    ]
    assert len(actions) == 1
    assert actions[0].category == "chain_integrity"
    assert set(actions[0].rule_ids) == {"CHAIN-001", "CHAIN-002"}


def test_plan_is_deterministic(bundle):
    actions, summary = build_plan(bundle.plan, bundle.findings, bundle.backups, bundle.events)
    assert [item.to_dict() for item in actions] == [item.to_dict() for item in bundle.actions]
    assert summary == bundle.plan_summary


def test_warnings_do_not_create_actions(bundle):
    warning_rules = {item.rule_id for item in bundle.findings if item.severity == "warning"}
    action_rules = {rule for item in bundle.actions for rule in item.rule_ids}
    assert warning_rules.isdisjoint(action_rules)
