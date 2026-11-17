from __future__ import annotations
import json
from pathlib import Path
import pytest
from drillverify.backup_chain import assess_chains
from shard_fixtures import build_shards, make_backup, run_assessment, write_index, write_manifest
pytestmark = pytest.mark.usefixtures("fixtures_root")
INDEPENDENT = {"s1": (1, 0, 0), "s2": (0, 1, 0), "s3": (0, 0, 1)}
DEPENDENT = {"s1": (1, 0, 0), "s2": (0, 1, 0), "s3": (1, 1, 0)}
DOMAINS = {"s1": "zone-a", "s2": "zone-b", "s3": "zone-c"}
def _check(result):
    return next(item for item in result.checks if item.backup_id == "bk-shard-001")
def _setup(root, plan, vectors, domains, **kwargs):
    backup = make_backup()
    write_index(root, backup)
    purpose = kwargs.pop("purpose", "current")
    entries = build_shards(root, backup, vectors, domains, **kwargs)
    write_manifest(root, backup, entries, purpose=purpose)
    return backup, run_assessment(root, plan, backup)
def test_full_rank_shards_make_artifact_ready(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS)
    check, proof = _check(result), _check(result).shard_assessment
    assert check.artifact_ready and proof.rank == 3 and proof.current_rebuildable
    assert proof.basis_vectors == ((1, 0, 0), (0, 1, 0), (0, 0, 1))
    assert proof.usable_count == 3 and proof.missing_dimensions == ()
def test_enough_shards_but_rank_deficient_is_not_ready(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, DEPENDENT, DOMAINS)
    check = _check(result)
    assert not check.artifact_ready and "ART-010" in check.failure_rules
    proof = check.shard_assessment
    assert proof.rank == 2 and proof.usable_count == 3 and not proof.current_rebuildable
    assert proof.missing_dimensions == (2,) and proof.witness_vectors == ((0, 0, 1),)
    finding = next(item for item in result.findings if item.rule_id == "ART-010")
    assert finding.evidence["witness_vectors"] == [[0, 0, 1]]
def test_adding_missing_dimension_shard_restores_readiness(fixture_copy: Path, bundle):
    vectors = {**DEPENDENT, "s4": (0, 0, 1)}
    _, result = _setup(fixture_copy, bundle.plan, vectors, {**DOMAINS, "s4": "zone-d"})
    assert _check(result).artifact_ready and _check(result).shard_assessment.rank == 3
def test_repeated_and_zero_vectors_cannot_fill_rank(fixture_copy: Path, bundle):
    vectors = {"s1": (1, 0, 0), "s2": (1, 0, 0), "s3": (0, 0, 0)}
    _, result = _setup(fixture_copy, bundle.plan, vectors, DOMAINS)
    check = _check(result)
    assert not check.artifact_ready and "ART-010" in check.failure_rules
    assert check.shard_assessment.rank == 1
    assert check.shard_assessment.missing_dimensions == (1, 2)
def test_bad_hash_shard_is_excluded_from_usable_set(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS, tamper={"s3"})
    check, proof = _check(result), _check(result).shard_assessment
    assert not check.artifact_ready and "ART-009" in check.failure_rules
    assert proof.usable_count == 2 and proof.rank == 2
    bad = next(item for item in proof.shard_proofs if item.shard_id == "s3")
    assert not bad.usable and bad.actual_sha256 != bad.declared_sha256
    assert next(item for item in proof.shard_proofs if item.shard_id == "s1").usable
def test_missing_shard_file_is_reported_and_excluded(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS, missing={"s2"})
    check = _check(result)
    assert {"ART-008", "ART-010"} <= set(check.failure_rules)
    assert check.shard_assessment.usable_count == 2
def test_current_full_rank_but_single_fault_purpose_fails(fixture_copy: Path, bundle):
    # Full rank today, but the unique 001 dimension lives only in one zone.
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS,
                       purpose="single_fault_domain")
    check, proof = _check(result), _check(result).shard_assessment
    assert proof.current_rebuildable and not proof.single_fault_tolerant
    assert not check.artifact_ready and "ART-011" in check.failure_rules
    assert proof.first_failed_domain == "zone-a" and proof.first_failed_domain_rank == 2
    finding = next(item for item in result.findings if item.rule_id == "ART-011")
    assert finding.evidence["fault_domain"] == "zone-a"
def test_same_layout_passes_current_purpose(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS)
    check, proof = _check(result), _check(result).shard_assessment
    assert check.artifact_ready and proof.current_rebuildable
    assert not proof.single_fault_tolerant
def test_tolerant_layout_passes_single_fault_purpose(fixture_copy: Path, bundle):
    vectors = {**INDEPENDENT, "s4": (1, 1, 1)}
    _, result = _setup(fixture_copy, bundle.plan, vectors, {**DOMAINS, "s4": "zone-d"},
                       purpose="single_fault_domain")
    proof = _check(result).shard_assessment
    assert _check(result).artifact_ready and proof.single_fault_tolerant
    assert proof.first_failed_domain is None
def test_same_domain_copies_are_not_independent_redundancy(fixture_copy: Path, bundle):
    # zone-b has two files sharing 010; dimension 1 has no carrier outside it.
    vectors = {"s1": (1, 0, 0), "s2": (1, 0, 1), "s3": (0, 1, 0),
               "s4": (0, 1, 0), "s5": (0, 0, 1), "s6": (1, 0, 1)}
    domains = {"s1": "zone-a", "s2": "zone-a", "s3": "zone-b", "s4": "zone-b",
               "s5": "zone-c", "s6": "zone-c"}
    _, result = _setup(fixture_copy, bundle.plan, vectors, domains,
                       purpose="single_fault_domain")
    check, proof = _check(result), _check(result).shard_assessment
    assert not check.artifact_ready and "ART-011" in check.failure_rules
    assert proof.first_failed_domain == "zone-b" and proof.first_failed_domain_rank == 2
    assert proof.current_rebuildable and proof.usable_count == 6
def test_shard_path_escape_is_blocked_by_fixture_fence(fixture_copy: Path, bundle):
    _, result = _setup(fixture_copy, bundle.plan, INDEPENDENT, DOMAINS,
                       bad_paths={"s2": "/etc/escape.bin"})
    check, proof = _check(result), _check(result).shard_assessment
    assert not check.artifact_ready
    assert {"ART-008", "ART-010"} <= set(check.failure_rules)
    assert proof.usable_count == 2 and proof.rank == 2
def test_malformed_sharding_block_is_art_007(fixture_copy: Path, bundle):
    backup = make_backup()
    write_index(fixture_copy, backup)
    write_manifest(fixture_copy, backup, [], stripe_count=0)
    check = _check(run_assessment(fixture_copy, bundle.plan, backup))
    assert not check.artifact_ready and "ART-007" in check.failure_rules
    assert check.manifest is None and check.shard_assessment is None
def test_catalog_index_artifact_is_still_verified(fixture_copy: Path, bundle):
    backup = make_backup()
    write_index(fixture_copy, backup)
    write_manifest(fixture_copy, backup,
                   build_shards(fixture_copy, backup, INDEPENDENT, DOMAINS))
    blob = fixture_copy / backup.artifact_path
    blob.write_bytes(blob.read_bytes() + b"tampered\n")
    check = _check(run_assessment(fixture_copy, bundle.plan, backup))
    assert not check.artifact_ready
    assert {"ART-004", "ART-005"} <= set(check.failure_rules)
def test_legacy_manifest_keeps_single_file_verification(fixture_copy: Path, bundle):
    backup = make_backup()
    write_index(fixture_copy, backup)
    write_manifest(fixture_copy, backup, [], manifest_version="1", extra={"sharding": None})
    path = fixture_copy / "artifacts" / f"manifest-{backup.backup_id}.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    del document["sharding"]
    path.write_text(json.dumps(document), encoding="utf-8")
    check = _check(run_assessment(fixture_copy, bundle.plan, backup))
    assert check.artifact_ready and check.manifest is not None
    assert not check.manifest.is_sharded and check.shard_assessment is None
def _chain(fixture_copy, bundle, vectors, domains):
    backup, result = _setup(fixture_copy, bundle.plan, vectors, domains)
    chains = assess_chains(bundle.plan, (backup,), result.checks,
                           "catalog/backup_catalog.csv", "hash")
    return backup, chains
def test_rank_deficient_shard_proof_blocks_chain_point(fixture_copy: Path, bundle):
    backup, chains = _chain(fixture_copy, bundle, DEPENDENT, DOMAINS)
    chain = next(item for item in chains.chains if item.backup_id == backup.backup_id)
    assert not chain.artifact_ready and not chain.restorable
    assert chains.points == () and "ART-010" in chain.failure_rules
def test_full_rank_shard_proof_qualifies_chain_point(fixture_copy: Path, bundle):
    backup, chains = _chain(fixture_copy, bundle, INDEPENDENT, DOMAINS)
    chain = next(item for item in chains.chains if item.backup_id == backup.backup_id)
    assert chain.artifact_ready and chain.restorable
    assert len(chains.points) == 1 and chains.points[0].backup_id == backup.backup_id
