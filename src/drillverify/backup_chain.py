"""Deterministic backup-chain reconstruction and restorable-point selection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import Finding, RecoveryPlan
from .records import ArtifactCheck, BackupRecord
from .results import BackupChainResult, RestorablePoint
from .schema_compat import ProofFailure, SchemaProof, SchemaProofRecord, prove_compatibility
from .timeutil import format_utc


@dataclass(frozen=True)
class ChainAssessment:
    chains: tuple[BackupChainResult, ...]
    points: tuple[RestorablePoint, ...]
    findings: tuple[Finding, ...]
    schema_proofs: tuple[SchemaProofRecord, ...] = ()


@dataclass
class _State:
    chain_complete: bool
    artifact_ready: bool
    restorable: bool
    failure_rules: list[str]
    schema_ok: bool = True


def _cycle_nodes(parent_map: dict[str, str]) -> set[str]:
    members: set[str] = set()
    for start in sorted(parent_map):
        seen: list[str] = []
        current = start
        while current in parent_map:
            if current in seen:
                members.update(seen[seen.index(current) :])
                break
            seen.append(current)
            current = parent_map[current]
    return members


def _chain_finding(
    rule: str, severity: str, backup: BackupRecord, path: str, file_hash: str, message: str, **evidence: Any
) -> Finding:
    return Finding(
        rule, severity, "backup", backup.backup_id, message, path, backup.line_no,
        {"dataset_id": backup.dataset_id, **evidence}, file_hash,
    )


def _schema_finding(failure: ProofFailure, backup: BackupRecord, path: str, file_hash: str, proof: SchemaProof) -> Finding:
    evidence = {
        "dataset_id": backup.dataset_id,
        "edge_id": failure.edge_id,
        "column": failure.column,
        "source_version": proof.source_version,
        "target_version": proof.target_version,
        "purpose": proof.purpose,
        "static_only": True,
        **failure.evidence,
    }
    return Finding(failure.rule_id, "high", "backup", backup.backup_id, failure.message, path, backup.line_no, evidence, file_hash)


def assess_chains(
    plan: RecoveryPlan,
    backups: tuple[BackupRecord, ...],
    artifacts: tuple[ArtifactCheck, ...],
    catalog_path: str,
    catalog_hash: str,
) -> ChainAssessment:
    """Recompute chains, detect structural failures and select restorable points."""
    artifact_map = {item.backup_id: item for item in artifacts}
    schema_cfg = plan.schema_migration
    findings: list[Finding] = []
    results: list[BackupChainResult] = []
    points: list[RestorablePoint] = []
    all_proofs: list[SchemaProofRecord] = []

    def ranges_of(backup_id: str) -> dict[str, tuple[int, int]]:
        check = artifact_map.get(backup_id)
        return check.manifest.range_map() if check and check.manifest else {}

    for dataset in plan.datasets:
        own = sorted(
            (item for item in backups if item.dataset_id == dataset.dataset_id),
            key=lambda item: (item.finished_at, item.backup_id),
        )
        own_map = {item.backup_id: item for item in own}
        parent_map = {
            item.backup_id: item.parent_backup_id
            for item in own
            if item.backup_type == "incremental" and item.parent_backup_id in own_map
        }
        cycle_nodes = _cycle_nodes(parent_map)
        memo: dict[str, _State] = {}
        active: set[str] = set()
        proofs: list[SchemaProofRecord] = []

        def evaluate(backup_id: str) -> _State:
            if backup_id in memo:
                return memo[backup_id]
            record = own_map[backup_id]
            own_artifact = artifact_map.get(backup_id)
            artifact_ok = bool(own_artifact and own_artifact.artifact_ready)
            failures: list[str] = list(own_artifact.failure_rules) if own_artifact else []
            if backup_id in active or backup_id in cycle_nodes:
                state = _State(False, artifact_ok, False, sorted(set(failures + ["CHAIN-003"])), schema_cfg is None)
                memo[backup_id] = state
                return state
            active.add(backup_id)
            future = record.finished_at > plan.as_of or record.started_at > plan.as_of
            chain_ok = True
            schema_ok = True
            if future:
                failures.append("CHAIN-006")
                chain_ok = False
            if record.backup_type == "incremental":
                parent = own_map.get(record.parent_backup_id or "")
                if parent is None:
                    failures.extend(["CHAIN-001", "CHAIN-002"])
                    chain_ok = False
                elif backup_id in cycle_nodes or parent.backup_id in cycle_nodes:
                    failures.append("CHAIN-003")
                    chain_ok = False
                else:
                    if parent.finished_at > record.started_at:
                        failures.append("CHAIN-004")
                        chain_ok = False
                    if parent.schema_version != record.schema_version and schema_cfg is not None:
                        adjacent = prove_compatibility(
                            schema_cfg, parent.schema_version, record.schema_version, ranges_of(parent.backup_id)
                        )
                        proofs.append(SchemaProofRecord(dataset.dataset_id, backup_id, "chain_edge", adjacent))
                        if adjacent.status != "compatible":
                            failures.append("CHAIN-005")
                            chain_ok = False
                    elif parent.schema_version != record.schema_version:
                        failures.append("CHAIN-005")
                        chain_ok = False
                    parent_state = evaluate(parent.backup_id)
                    if not parent_state.chain_complete:
                        failures.append("CHAIN-009")
                        chain_ok = False
                    if not parent_state.restorable:
                        failures.append("CHAIN-009")
                    artifact_ok = artifact_ok and parent_state.artifact_ready
                    chain_ok = chain_ok and parent_state.chain_complete
                    schema_ok = schema_ok and parent_state.schema_ok
            if schema_cfg is not None:
                target_proof = prove_compatibility(
                    schema_cfg, record.schema_version, schema_cfg.target_version, ranges_of(backup_id)
                )
                proofs.append(SchemaProofRecord(dataset.dataset_id, backup_id, "restore_target", target_proof))
                if target_proof.status != "compatible":
                    failures.append("CHAIN-010")
                    schema_ok = False
            active.discard(backup_id)
            restorable = chain_ok and artifact_ok and schema_ok
            state = _State(chain_ok, artifact_ok, restorable, sorted(set(failures)), schema_ok)
            memo[backup_id] = state
            return state

        for record in own:
            evaluate(record.backup_id)
        proof_map = {(item.backup_id, item.kind): item.proof for item in proofs}
        all_proofs.extend(proofs)

        for record in own:
            state = memo[record.backup_id]
            if record.finished_at > plan.as_of or record.started_at > plan.as_of:
                findings.append(
                    _chain_finding(
                        "CHAIN-006", "high", record, catalog_path, catalog_hash,
                        "Backup timestamp is later than as_of.",
                        started_at=format_utc(record.started_at),
                        finished_at=format_utc(record.finished_at),
                        as_of=format_utc(plan.as_of),
                    )
                )
            if record.backup_type == "incremental":
                parent = own_map.get(record.parent_backup_id or "")
                if parent is None:
                    for rule, message in (
                        ("CHAIN-001", "Parent backup does not exist in this dataset."),
                        ("CHAIN-002", "Incremental backup has no full-backup ancestry."),
                    ):
                        findings.append(
                            _chain_finding(rule, "high", record, catalog_path, catalog_hash, message, parent_backup_id=record.parent_backup_id)
                        )
                elif record.backup_id in cycle_nodes:
                    findings.append(
                        _chain_finding(
                            "CHAIN-003", "critical", record, catalog_path, catalog_hash,
                            "Backup parent chain contains a cycle.", parent_backup_id=record.parent_backup_id,
                        )
                    )
                else:
                    if parent.finished_at > record.started_at:
                        findings.append(
                            _chain_finding(
                                "CHAIN-004", "high", record, catalog_path, catalog_hash,
                                "Parent backup finishes after the child starts.",
                                parent_backup_id=parent.backup_id,
                                parent_finished_at=format_utc(parent.finished_at),
                                child_started_at=format_utc(record.started_at),
                            )
                        )
                    adjacent = proof_map.get((record.backup_id, "chain_edge"))
                    if parent.schema_version != record.schema_version and (
                        adjacent is None or adjacent.status != "compatible"
                    ):
                        extra = {"proof_status": adjacent.status} if adjacent is not None else {}
                        findings.append(
                            _chain_finding(
                                "CHAIN-005", "high", record, catalog_path, catalog_hash,
                                "Parent schema version is incompatible with the child.",
                                parent_backup_id=parent.backup_id,
                                parent_schema=parent.schema_version,
                                child_schema=record.schema_version,
                                **extra,
                            )
                        )
                        if adjacent is not None and adjacent.failure is not None:
                            findings.append(_schema_finding(adjacent.failure, record, catalog_path, catalog_hash, adjacent))
                    if not memo[parent.backup_id].restorable:
                        findings.append(
                            _chain_finding(
                                "CHAIN-009", "high", record, catalog_path, catalog_hash,
                                "Ancestor backup is not restorable, so this child cannot be a recovery point.",
                                parent_backup_id=parent.backup_id,
                            )
                        )
            target_proof = proof_map.get((record.backup_id, "restore_target"))
            if target_proof is not None and target_proof.status != "compatible":
                findings.append(
                    _chain_finding(
                        "CHAIN-010", "high", record, catalog_path, catalog_hash,
                        f"Backup schema {record.schema_version!r} is not proven compatible with "
                        f"restore target {target_proof.target_version!r} for purpose "
                        f"{target_proof.purpose!r}.",
                        target_version=target_proof.target_version,
                        purpose=target_proof.purpose,
                        proof_status=target_proof.status,
                        static_only=True,
                    )
                )
                if target_proof.failure is not None:
                    findings.append(_schema_finding(target_proof.failure, record, catalog_path, catalog_hash, target_proof))
            results.append(
                BackupChainResult(
                    dataset_id=dataset.dataset_id,
                    backup_id=record.backup_id,
                    parent_backup_id=record.parent_backup_id,
                    finished_at=format_utc(record.finished_at),
                    chain_complete=state.chain_complete,
                    artifact_ready=state.artifact_ready,
                    restorable=state.restorable,
                    failure_rules=tuple(state.failure_rules),
                )
            )
            if state.restorable:
                manifest = artifact_map[record.backup_id].manifest
                if manifest is not None:
                    points.append(
                        RestorablePoint(
                            dataset_id=dataset.dataset_id,
                            backup_id=record.backup_id,
                            finished_at=record.finished_at,
                            row_count=manifest.row_count,
                            data_sha256=manifest.data_sha256,
                            schema_version=manifest.schema_version,
                        )
                    )

    results.sort(key=lambda item: (item.dataset_id, item.finished_at, item.backup_id))
    points.sort(key=lambda item: (item.dataset_id, item.finished_at, item.backup_id))
    all_proofs.sort(key=lambda item: (item.dataset_id, item.backup_id, item.kind))
    unique_findings = {finding.dedupe_key(): finding for finding in findings}
    return ChainAssessment(
        tuple(results),
        tuple(points),
        tuple(sorted(unique_findings.values(), key=Finding.sort_key)),
        tuple(all_proofs),
    )
