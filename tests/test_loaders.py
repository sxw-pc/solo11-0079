from __future__ import annotations

import csv
from pathlib import Path

from drillverify.loaders import load_catalog, load_drills


def test_catalog_preserves_physical_lines(fixtures_root: Path):
    loaded = load_catalog(fixtures_root)
    assert not loaded.fatal
    assert len(loaded.rows) == 69
    assert loaded.rows[0][0] == 2
    assert loaded.rows[-1][0] == 70
    assert loaded.fingerprint is not None
    assert loaded.fingerprint.path == "catalog/backup_catalog.csv"


def test_missing_catalog_column_is_fatal(fixture_copy: Path):
    path = fixture_copy / "catalog" / "backup_catalog.csv"
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
        fields = [name for name in rows[0] if name != "sha256"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    loaded = load_catalog(fixture_copy)
    assert loaded.fatal
    assert any(item.rule_id == "IN-001" for item in loaded.findings)


def test_jsonl_malformed_line_is_not_silent(fixtures_root: Path):
    loaded = load_drills(fixtures_root)
    assert not loaded.fatal
    assert len(loaded.rows) == 24
    assert any(item.rule_id == "IN-012" and item.line == 25 for item in loaded.findings)


def test_missing_input_file_is_reported(tmp_path: Path):
    loaded = load_catalog(tmp_path)
    assert loaded.fatal
    assert loaded.findings[0].rule_id == "IN-000"
