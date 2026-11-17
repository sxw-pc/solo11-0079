from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import yaml

from drillverify.backup_chain import assess_chains
from drillverify.config import load_plan
from drillverify.evidence import assess_artifacts
from drillverify.loaders import load_catalog
from drillverify.models import (
    ColumnDecl,
    ColumnMap,
    DatasetConfig,
    MigrationEdge,
    RecoveryPlan,
    SchemaContract,
    SchemaMigrationConfig,
)
from drillverify.pipeline import run_pipeline
from drillverify.records import ArtifactCheck, ArtifactManifest, BackupRecord
from drillverify.reporting import build_report
from drillverify.schema_compat import prove_compatibility
from drillverify.validators import validate_catalog

AS_OF = datetime(2026, 11, 10, tzinfo=timezone.utc)


def cols(*spec: tuple) -> tuple[ColumnDecl, ...]:
    return tuple(ColumnDecl(*item) for item in spec)


V1 = SchemaContract("1", cols(("id", "int32", True, "primary"), ("amount", "int64", True), ("comment", "string", False)))
V2 = SchemaContract("2", cols(("id", "int64", True, "primary"), ("amount", "int64", True)))
SAFE_EDGE = MigrationEdge(
    "v1-to-v2", "1", "2",
    (ColumnMap("id", "id", "widen"), ColumnMap("amount", "amount", "identity")),
    ("comment",),
)
NARROW_EDGE = MigrationEdge(
    "v2-to-v1", "2", "1",
    (ColumnMap("id", "id", "narrow", "manifest"), ColumnMap("amount", "amount", "identity")),
)


def cfg(purpose: str, edges: tuple[MigrationEdge, ...], contracts=(V1, V2), target: str = "2") -> SchemaMigrationConfig:
    return SchemaMigrationConfig(target, purpose, contracts, edges)


def plan_with(schema_cfg: SchemaMigrationConfig | None) -> RecoveryPlan:
    dataset = DatasetConfig(
        dataset_id="ds-x", display_name="X", rpo_minutes=60, rto_minutes=60,
        required_steps=("precheck",), checksum_required=False, rowcount_required=False,
        owner_team="team", maintenance_window="sun:00:00-01:00Z", artifact_manifest_path="artifacts",
    )
    return RecoveryPlan(AS_OF, 7, (dataset,), "plans/recovery_plan.yaml", schema_cfg)


def record(backup_id: str, parent: str | None, version: str, backup_type="incremental") -> BackupRecord:
    moment = datetime(2026, 11, 8, 1, tzinfo=timezone.utc)
    return BackupRecord(
        "ds-x", backup_id, parent, backup_type, moment, moment,
        f"artifacts/blobs/{backup_id}.bin", 10, "0" * 64, 1, version, 1,
    )


def ready_checks(records: tuple[BackupRecord, ...]) -> tuple[ArtifactCheck, ...]:
    return tuple(
        ArtifactCheck(item.backup_id, True, ArtifactManifest(item.backup_id, 1, "0" * 64, item.schema_version, "m"), ())
        for item in records
    )


def test_safe_widening_and_optional_drop_is_compatible_for_analysis():
    proof = prove_compatibility(cfg("analysis_readonly", (SAFE_EDGE,)), "1", "2", {})
    assert proof.status == "compatible"
    assert proof.path == ("v1-to-v2",)
    assert proof.failure is None
    document = proof.to_dict()
    assert document["proof_kind"] == "static" and document["migration_executed"] is False


def test_reachable_path_that_loses_required_column_is_rejected():
    v2_extra = SchemaContract("2", cols(("id", "int64", True, "primary"), ("amount", "int64", True), ("currency", "string", True)))
    proof = prove_compatibility(cfg("analysis_readonly", (SAFE_EDGE,), (V1, v2_extra)), "1", "2", {})
    assert proof.status == "incompatible"
    assert proof.failure.rule_id == "SCHEMA-001"
    assert proof.failure.column == "currency" and proof.failure.edge_id == "v1-to-v2"


def test_narrowing_requires_manifest_range_evidence_for_both_purposes():
    missing = prove_compatibility(cfg("analysis_readonly", (NARROW_EDGE,)), "2", "1", {})
    assert missing.status == "unproven"
    assert missing.failure.rule_id == "SCHEMA-002" and missing.failure.unproven
    assert prove_compatibility(cfg("rollback", (NARROW_EDGE,)), "2", "1", {}).status == "unproven"
    overflow = prove_compatibility(cfg("analysis_readonly", (NARROW_EDGE,)), "2", "1", {"id": (0, 5_000_000_000)})
    assert overflow.status == "incompatible" and not overflow.failure.unproven
    proven = prove_compatibility(cfg("analysis_readonly", (NARROW_EDGE,)), "2", "1", {"id": (0, 5_000_000)})
    assert proven.status == "compatible"
    assert prove_compatibility(cfg("rollback", (NARROW_EDGE,)), "2", "1", {"id": (0, 5_000_000)}).status == "compatible"


def test_longer_lossless_path_wins_over_shorter_lossy_one():
    v2_keep = SchemaContract("2", cols(("id", "int64", True, "primary"), ("amount", "int64", True), ("comment", "string", False)))
    v3 = SchemaContract("3", cols(("id", "int64", True, "primary"), ("amount", "int64", True), ("comment", "string", False)))
    direct = MigrationEdge("e-direct", "1", "3", (ColumnMap("id", "id", "widen"), ColumnMap("amount", "amount", "identity")), ("comment",))
    hop1 = MigrationEdge("e-v1-v2", "1", "2", SAFE_EDGE.column_maps + (ColumnMap("comment", "comment", "identity"),))
    hop2 = MigrationEdge("e-v2-v3", "2", "3", tuple(ColumnMap(name, name, "identity") for name in ("id", "amount", "comment")))
    config = cfg("rollback", (direct, hop1, hop2), (V1, v2_keep, v3), target="3")
    proof = prove_compatibility(config, "1", "3", {})
    assert proof.status == "compatible"
    assert proof.path == ("e-v1-v2", "e-v2-v3")
    assert proof.attempts[0].edge_ids == ("e-direct",)
    assert proof.attempts[0].failure.rule_id == "SCHEMA-004"


def test_conflicting_key_meaning_between_paths_is_rejected():
    v1 = SchemaContract("1", cols(("id", "int64", True, "primary"), ("alt", "int64", True, "unique"), ("b", "int32", False)))
    v2 = SchemaContract("2", cols(("key_col", "int64", True, "primary"), ("alt_col", "int64", True, "unique"), ("b", "int32", False)))
    first = MigrationEdge("e-alpha", "1", "2", (ColumnMap("id", "key_col", "rename"), ColumnMap("alt", "alt_col", "rename"), ColumnMap("b", "b", "identity")))
    second = MigrationEdge("e-beta", "1", "2", (ColumnMap("id", "alt_col", "rename"), ColumnMap("alt", "key_col", "rename"), ColumnMap("b", "b", "identity")))
    proof = prove_compatibility(cfg("analysis_readonly", (first, second), (v1, v2)), "1", "2", {})
    assert proof.status == "incompatible"
    assert proof.failure.rule_id == "SCHEMA-003"
    assert proof.failure.evidence["left_path"] != proof.failure.evidence["right_path"]


def test_analysis_and_rollback_decide_differently_on_same_migration():
    analysis = prove_compatibility(cfg("analysis_readonly", (SAFE_EDGE,)), "1", "2", {})
    rollback = prove_compatibility(cfg("rollback", (SAFE_EDGE,)), "1", "2", {})
    assert analysis.status == "compatible"
    assert rollback.status == "incompatible"
    assert rollback.failure.rule_id == "SCHEMA-004" and rollback.failure.column == "comment"


def test_nullability_and_key_uniqueness_are_composed_per_step():
    s_null = SchemaContract("1", cols(("id", "int64", True, "primary"), ("maybe", "int64", False)))
    t_req = SchemaContract("2", cols(("id", "int64", True, "primary"), ("must", "int64", True)))
    null_edge = MigrationEdge("e-null", "1", "2", (ColumnMap("id", "id", "identity"), ColumnMap("maybe", "must", "rename")))
    proof = prove_compatibility(cfg("analysis_readonly", (null_edge,), (s_null, t_req)), "1", "2", {})
    assert proof.status == "incompatible" and proof.failure.rule_id == "SCHEMA-007"
    s_key = SchemaContract("1", cols(("id", "int64", True, "primary"), ("seq", "int64", True)))
    t_key = SchemaContract("2", cols(("id", "int64", True, "primary"), ("other", "int64", False)))
    key_edge = MigrationEdge("e-key", "1", "2", (ColumnMap("seq", "id", "rename"), ColumnMap("id", "other", "rename")))
    proof = prove_compatibility(cfg("analysis_readonly", (key_edge,), (s_key, t_key)), "1", "2", {})
    assert proof.status == "unproven" and proof.failure.rule_id == "SCHEMA-002"
    dup_edge = MigrationEdge("e-dup", "1", "2", (ColumnMap("id", "other", "rename"), ColumnMap("seq", "other", "rename")))
    proof = prove_compatibility(cfg("analysis_readonly", (dup_edge,), (s_key, t_key)), "1", "2", {})
    assert proof.status == "incompatible" and proof.failure.rule_id == "SCHEMA-006"


def test_chain_accepts_proven_version_difference():
    plan = plan_with(cfg("analysis_readonly", (SAFE_EDGE,)))
    records = (record("bk-full", None, "1", "full"), record("bk-inc", "bk-full", "2"))
    result = assess_chains(plan, records, ready_checks(records), "catalog", "hash")
    assert all(item.restorable for item in result.chains)
    assert not any(item.rule_id == "CHAIN-005" for item in result.findings)
    kinds = {(item.backup_id, item.kind) for item in result.schema_proofs}
    assert ("bk-inc", "chain_edge") in kinds and ("bk-full", "restore_target") in kinds


def test_chain_rollback_gate_excludes_point_and_propagates():
    plan = plan_with(cfg("rollback", (SAFE_EDGE,)))
    records = (record("bk-full", None, "1", "full"), record("bk-inc", "bk-full", "2"))
    result = assess_chains(plan, records, ready_checks(records), "catalog", "hash")
    states = {item.backup_id: item for item in result.chains}
    assert not states["bk-full"].restorable and "CHAIN-010" in states["bk-full"].failure_rules
    assert not states["bk-inc"].restorable
    assert "CHAIN-005" in states["bk-inc"].failure_rules and "CHAIN-009" in states["bk-inc"].failure_rules
    assert any(item.rule_id == "SCHEMA-004" and item.object_id == "bk-full" for item in result.findings)
    assert any(item.rule_id == "CHAIN-010" and item.object_id == "bk-full" for item in result.findings)
    legacy = next(item for item in result.findings if item.rule_id == "CHAIN-005" and item.object_id == "bk-inc")
    detail = next(item for item in result.findings if item.rule_id == "SCHEMA-004" and item.object_id == "bk-inc")
    assert legacy.file and detail.file and detail.line
    assert detail.evidence["edge_id"] == "v1-to-v2" and detail.evidence["column"] == "comment"
    assert detail.evidence["static_only"] is True


def test_without_config_version_mismatch_keeps_legacy_equality():
    plan = plan_with(None)
    records = (record("bk-full", None, "1", "full"), record("bk-inc", "bk-full", "2"))
    result = assess_chains(plan, records, ready_checks(records), "catalog", "hash")
    states = {item.backup_id: item for item in result.chains}
    assert states["bk-full"].restorable
    assert not states["bk-inc"].restorable and "CHAIN-005" in states["bk-inc"].failure_rules
    assert result.schema_proofs == ()


def _gated_plan_path(fixture_copy: Path) -> Path:
    plan_path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    raw["schema_migration"] = {
        "target_version": "9",
        "purpose": "analysis_readonly",
        "contracts": [
            {"version": "3", "columns": [{"name": "id", "type": "int64", "required": True, "key_role": "primary"}]},
            {"version": "9", "columns": [{"name": "id", "type": "int64", "required": True, "key_role": "primary"}]},
        ],
        "edges": [],
    }
    plan_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return plan_path


def test_schema_gate_changes_restorable_points_and_rpo(fixture_copy: Path, bundle):
    _gated_plan_path(fixture_copy)
    gated = run_pipeline(fixture_copy)
    assert bundle.summary["restorable_point_count"] > 0
    assert gated.summary["restorable_point_count"] == 0
    assert all(item.status == "no_points" for item in gated.rpo)
    assert any(item.rule_id == "CHAIN-010" for item in gated.findings)
    assert any(item.rule_id == "SCHEMA-005" for item in gated.findings)
    assert any(item.rule_id == "OBJ-POINT-001" and item.object_id == "ds-events" for item in gated.findings)
    proofs = build_report(gated)["schema_proofs"]
    assert proofs
    assert all(item["proof_kind"] == "static" and item["migration_executed"] is False for item in proofs)
    assert {item["status"] for item in proofs} == {"unproven"}


def test_executable_content_in_edges_is_rejected(fixture_copy: Path):
    plan_path = fixture_copy / "plans" / "recovery_plan.yaml"
    raw = yaml.safe_load(plan_path.read_text(encoding="utf-8"))
    raw["schema_migration"] = {
        "target_version": "3",
        "purpose": "analysis_readonly",
        "contracts": [{"version": "3", "columns": [{"name": "id", "type": "int64", "required": True}]}],
        "edges": [{"edge_id": "evil", "from_version": "3", "to_version": "3", "script": "rm -rf /"}],
    }
    plan_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    loaded = load_plan(plan_path, fixture_copy)
    assert loaded.plan is None
    assert any(item.rule_id == "CFG-001" and "declarative" in item.message for item in loaded.findings)


def test_manifest_column_ranges_are_parsed_and_validated(fixture_copy: Path, bundle):
    manifest_path = fixture_copy / "artifacts" / "manifest-bk-orders-042.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["column_ranges"] = {"id": {"min": 1, "max": 5_000_000}}
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    catalog = validate_catalog(load_catalog(fixture_copy), bundle.plan, fixture_copy)
    result = assess_artifacts(catalog.records, bundle.plan, fixture_copy)
    manifest = next(item for item in result.checks if item.backup_id == "bk-orders-042").manifest
    assert manifest.range_map() == {"id": (1, 5_000_000)}
    payload["column_ranges"] = {"id": {"min": 9, "max": 2}}
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    result = assess_artifacts(catalog.records, bundle.plan, fixture_copy)
    check = next(item for item in result.checks if item.backup_id == "bk-orders-042")
    assert "ART-002" in check.failure_rules
