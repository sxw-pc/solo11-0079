"""Row-level validation of recovery-generation and data-digest markers."""

from __future__ import annotations

import json
from pathlib import Path

from drillverify.loaders import load_catalog, load_drills
from drillverify.validators import validate_catalog, validate_drills


def _drills(fixture_copy: Path, bundle, mutate):
    catalog = validate_catalog(load_catalog(fixture_copy), bundle.plan, fixture_copy)
    path = fixture_copy / "logs" / "restore_drill.jsonl"
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append(line)
    path.write_text(
        "\n".join(json.dumps(mutate(dict(row)), sort_keys=True) if isinstance(row, dict) else row
                  for row in rows) + "\n"
    )
    return validate_drills(load_drills(fixture_copy), bundle.plan, catalog.records, fixture_copy)


def test_unknown_generation_reference_is_rejected(fixture_copy: Path, bundle):
    def mark(row):
        if row.get("step") == "verify_rowcount":
            row["recovery_generation"] = "gen-ghost"
            row["data_digest"] = "a" * 64
        return row

    result = _drills(fixture_copy, bundle, mark)
    assert any(item.rule_id == "IN-016" for item in result.findings)


def test_incremental_must_bind_current_generation(fixture_copy: Path, bundle):
    def mark(row):
        if row.get("step") == "restore_base" and row.get("attempt") == 2:
            row["recovery_generation"] = "gen-b"
        if row.get("step") == "apply_incremental":
            row["recovery_generation"] = "gen-a"
        return row

    result = _drills(fixture_copy, bundle, mark)
    rules = [item for item in result.findings if item.rule_id == "IN-016"]
    assert rules and "superseded recovery generation" in rules[0].message


def test_malformed_digest_and_generation_are_rejected(fixture_copy: Path, bundle):
    def mark(row):
        if row.get("step") == "verify_rowcount":
            row["data_digest"] = "not-a-sha"
        if row.get("step") == "verify_checksum":
            row["recovery_generation"] = "Bad Gen"
        return row

    result = _drills(fixture_copy, bundle, mark)
    assert sum(1 for item in result.findings if item.rule_id == "IN-016") >= 2


def test_legacy_events_without_new_fields_are_accepted(fixtures_root: Path, bundle):
    from drillverify.loaders import load_drills as _load
    from drillverify.validators import validate_drills as _validate

    catalog = validate_catalog(load_catalog(fixtures_root), bundle.plan, fixtures_root)
    result = _validate(_load(fixtures_root), bundle.plan, catalog.records, fixtures_root)
    assert all(event.recovery_generation is None for event in result.events)
    assert all(event.data_digest is None for event in result.events)
    assert not any(item.rule_id == "IN-016" for item in result.findings)
