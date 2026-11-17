from __future__ import annotations
from pathlib import Path
from drillverify.loaders import load_catalog, load_drills
from drillverify.validators import validate_catalog, validate_drills
def _catalog(fixtures_root: Path, plan):
    loaded = load_catalog(fixtures_root)
    return validate_catalog(loaded, plan, fixtures_root)
def test_catalog_drops_are_all_reported(fixtures_root: Path, bundle):
    result = _catalog(fixtures_root, bundle.plan)
    assert len(result.records) == 63
    assert result.rejected_count == 6
    rules = {item.rule_id for item in result.findings}
    assert {"IN-002", "IN-005", "IN-006", "IN-008", "IN-009", "IN-011"} <= rules
    assert all(item.line > 0 for item in result.findings if item.rule_id.startswith("IN-"))
def test_drill_references_and_enums_are_checked(fixtures_root: Path, bundle):
    catalog = _catalog(fixtures_root, bundle.plan)
    loaded = load_drills(fixtures_root)
    result = validate_drills(loaded, bundle.plan, catalog.records, fixtures_root)
    assert len(result.events) == 21
    assert result.rejected_count == 3
    rules = {item.rule_id for item in result.findings}
    assert {"IN-007", "IN-009", "IN-012", "IN-014"} <= rules
    assert all(item.input_sha256 for item in result.findings)
def test_catalog_records_are_stably_sorted(fixtures_root: Path, bundle):
    result = _catalog(fixtures_root, bundle.plan)
    keys = [(item.dataset_id, item.finished_at, item.backup_id) for item in result.records]
    assert keys == sorted(keys)
