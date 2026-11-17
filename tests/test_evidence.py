from __future__ import annotations
from pathlib import Path
from drillverify.evidence import assess_artifacts, assess_evidence
from drillverify.loaders import load_catalog, load_drills
from drillverify.validators import validate_catalog, validate_drills
def _records(root: Path, plan):
    raw = load_catalog(root)
    catalog = validate_catalog(raw, plan, root)
    drill_raw = load_drills(root)
    drills = validate_drills(drill_raw, plan, catalog.records, root)
    return catalog.records, drills.events
def test_artifact_and_evidence_integrity(fixtures_root: Path, bundle):
    checks = {item.backup_id: item for item in bundle.artifacts}
    assert checks["bk-orders-042"].artifact_ready
    assert checks["bk-orders-042"].manifest.row_count == 12000
    assert not checks["bk-ledger-002"].artifact_ready
    assert "ART-001" in checks["bk-ledger-002"].failure_rules
    assert "ART-003" in checks["bk-ledger-002"].failure_rules
    evidence = {item.evidence_ref: item for item in bundle.evidence}
    assert evidence["evidence/evidence-002.json"].valid
    assert not evidence["evidence/evidence-missing.txt"].exists
def test_tampered_artifact_hash_is_critical(fixture_copy: Path, bundle):
    blob = fixture_copy / "artifacts" / "blobs" / "bk-orders-042.bin"
    blob.write_bytes(blob.read_bytes() + b"tampered\n")
    records, _ = _records(fixture_copy, bundle.plan)
    result = assess_artifacts(records, bundle.plan, fixture_copy)
    check = next(item for item in result.checks if item.backup_id == "bk-orders-042")
    assert not check.artifact_ready
    assert "ART-004" in check.failure_rules and "ART-005" in check.failure_rules
    assert any(item.rule_id == "ART-005" and item.severity == "critical" for item in result.findings)
def test_malformed_manifest_is_reported(fixture_copy: Path, bundle):
    manifest = fixture_copy / "artifacts" / "manifest-bk-orders-042.json"
    manifest.write_text("{}\n", encoding="utf-8")
    records, _ = _records(fixture_copy, bundle.plan)
    result = assess_artifacts(records, bundle.plan, fixture_copy)
    assert any(item.rule_id == "ART-002" for item in result.findings)
    assert "ART-002" in next(
        item for item in result.checks if item.backup_id == "bk-orders-042"
    ).failure_rules
def test_evidence_check_is_deduplicated(fixtures_root: Path, bundle):
    raw = load_drills(fixtures_root)
    catalog_raw = load_catalog(fixtures_root)
    catalog = validate_catalog(catalog_raw, bundle.plan, fixtures_root)
    drills = validate_drills(raw, bundle.plan, catalog.records, fixtures_root)
    result = assess_evidence(drills.events, fixtures_root)
    refs = [item.evidence_ref for item in result.checks]
    assert len(refs) == len(set(refs))
    assert refs == sorted(refs)
