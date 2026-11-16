from __future__ import annotations

from pathlib import Path

import yaml

from drillverify.config import load_plan


def test_demo_plan_is_normalized_and_sorted(fixtures_root: Path):
    loaded = load_plan(fixtures_root / "plans" / "recovery_plan.yaml", fixtures_root)
    assert loaded.plan is not None
    assert [item.dataset_id for item in loaded.plan.datasets] == ["ds-events", "ds-ledger", "ds-orders"]
    assert loaded.plan.analysis_window_days == 7
    assert loaded.plan.as_of.isoformat() == "2026-11-10T00:00:00+00:00"
    assert loaded.fingerprint.sha256 and len(loaded.fingerprint.sha256) == 64


def test_non_utc_as_of_is_rejected(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    path.write_text(path.read_text().replace("2026-11-10T00:00:00Z", "2026-11-10T00:00:00"), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert loaded.plan is None
    assert any(item.rule_id == "CFG-001" for item in loaded.findings)


def test_duplicate_dataset_is_reported(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["datasets"].append(dict(raw["datasets"][0]))
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert loaded.plan is not None
    assert any(item.rule_id == "CFG-002" for item in loaded.findings)


def test_unsafe_manifest_path_is_rejected(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["datasets"][0]["artifact_manifest_path"] = "../outside"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert any(item.rule_id == "CFG-004" for item in loaded.findings)
    assert loaded.plan is not None
    assert "ds-orders" not in loaded.plan.dataset_map()


def test_scheduling_block_is_parsed(fixtures_root: Path):
    loaded = load_plan(fixtures_root / "plans" / "recovery_plan.yaml", fixtures_root)
    assert loaded.plan is not None
    scheduling = loaded.plan.scheduling
    assert scheduling is not None
    assert scheduling.slot_minutes == 30
    assert scheduling.horizon_days == 28
    assert scheduling.objectives == ("min_overdue_high", "min_impact")
    assert scheduling.capacity_for("team-alpha") == 2
    assert scheduling.profile_for("chain_integrity").duration_minutes > 0
    assert scheduling.dependencies


def test_invalid_scheduling_horizon_rejects_the_plan(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["scheduling"]["horizon_days"] = 120
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert loaded.plan is None
    assert any(item.rule_id == "CFG-005" for item in loaded.findings)


def test_missing_team_capacity_rejects_the_plan(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["scheduling"]["team_capacities"].pop("team-beta")
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert loaded.plan is None
    assert any("team-beta" in item.message for item in loaded.findings)


def test_unknown_dependency_field_rejects_the_plan(fixture_copy: Path):
    path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(path.read_text())
    raw["scheduling"]["dependencies"][0]["prerequisite"]["severity"] = "high"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(path, fixture_copy)
    assert loaded.plan is None
    assert any(item.rule_id == "CFG-005" for item in loaded.findings)
