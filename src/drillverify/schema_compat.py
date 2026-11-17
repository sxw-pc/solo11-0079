"""Static, fully offline schema-migration compatibility proofs.

This module only combines declared schema contracts, declarative migration
edges and manifest range evidence into a reviewable proof. It never transforms
data, never executes a restore and never runs user code: every edge is pure
declarative data and every verdict names the first failing column or edge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .models import ColumnDecl, ColumnMap, MigrationEdge, SchemaContract, SchemaMigrationConfig

TYPES = ("int32", "int64", "string", "bool")
INT_RANGES = {"int32": (-(2**31), 2**31 - 1), "int64": (-(2**63), 2**63 - 1)}
WIDENING = {("int32", "int64")}
NARROWING = {("int64", "int32")}
TRANSFORMS = ("identity", "rename", "widen", "narrow")
RANGE_PROOFS = ("none", "manifest")
KEY_ROLES = ("none", "primary", "unique")
PURPOSES = ("analysis_readonly", "rollback")
EXECUTABLE_KEYS = ("callable", "code", "eval", "exec", "expression", "function", "script")
_MAX_PATHS = 32


@dataclass(frozen=True)
class ProofFailure:
    rule_id: str
    message: str
    edge_id: str = ""
    column: str = ""
    unproven: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id, "message": self.message, "edge_id": self.edge_id,
            "column": self.column, "unproven": self.unproven,
            "evidence": {key: self.evidence[key] for key in sorted(self.evidence)},
        }


@dataclass(frozen=True)
class PathAttempt:
    edge_ids: tuple[str, ...]
    failure: ProofFailure | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_ids": list(self.edge_ids),
            "status": "proven" if self.failure is None else "failed",
            "failure": self.failure.to_dict() if self.failure else None,
        }


@dataclass(frozen=True)
class SchemaProof:
    source_version: str
    target_version: str
    purpose: str
    status: str
    path: tuple[str, ...]
    attempts: tuple[PathAttempt, ...]
    failure: ProofFailure | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_version": self.source_version, "target_version": self.target_version,
            "purpose": self.purpose, "status": self.status, "path": list(self.path),
            "attempts": [item.to_dict() for item in self.attempts],
            "failure": self.failure.to_dict() if self.failure else None,
            "proof_kind": "static", "migration_executed": False,
        }


@dataclass(frozen=True)
class SchemaProofRecord:
    dataset_id: str
    backup_id: str
    kind: str
    proof: SchemaProof

    def to_dict(self) -> dict[str, Any]:
        return {"dataset_id": self.dataset_id, "backup_id": self.backup_id, "kind": self.kind, **self.proof.to_dict()}


def _fail(rule: str, message: str, edge_id: str = "", column: str = "", unproven: bool = False, **evidence: Any) -> ProofFailure:
    return ProofFailure(rule, message, edge_id, column, unproven, evidence)


def _check_transform(
    edge: MigrationEdge,
    mapping: ColumnMap,
    source: ColumnDecl,
    target: ColumnDecl,
    lineage: Mapping[str, str | None],
    ranges: Mapping[str, tuple[int, int]],
) -> ProofFailure | None:
    if mapping.transform in {"identity", "rename"}:
        if source.type != target.type:
            return _fail("SCHEMA-006", f"Column {mapping.source!r} changes type {source.type} -> {target.type} without a widen/narrow transform.", edge.edge_id, mapping.target)
        if mapping.transform == "identity" and mapping.source != mapping.target:
            return _fail("SCHEMA-006", f"Identity map {mapping.source!r} -> {mapping.target!r} renames a column; declare rename.", edge.edge_id, mapping.target)
        if mapping.transform == "rename" and mapping.source == mapping.target:
            return _fail("SCHEMA-006", f"Rename of column {mapping.source!r} keeps the same name.", edge.edge_id, mapping.target)
        return None
    if mapping.transform == "widen":
        if (source.type, target.type) not in WIDENING:
            return _fail("SCHEMA-006", f"Widening {source.type} -> {target.type} is not a declared safe widening.", edge.edge_id, mapping.target)
        return None
    if mapping.transform == "narrow":
        if (source.type, target.type) not in NARROWING:
            return _fail("SCHEMA-006", f"Narrowing {source.type} -> {target.type} is not a declared safe narrowing.", edge.edge_id, mapping.target)
        if mapping.range_proof != "manifest":
            return _fail("SCHEMA-002", f"Narrowing column {mapping.source!r} to {target.type} declares no manifest range proof.", edge.edge_id, mapping.target, unproven=True)
        origin = lineage.get(mapping.source) or mapping.source
        bounds = ranges.get(origin)
        if bounds is None:
            return _fail("SCHEMA-002", f"Narrowing column {mapping.source!r} to {target.type} needs manifest range evidence for {origin!r}, which the manifest does not provide.", edge.edge_id, mapping.target, unproven=True, origin_column=origin)
        low, high = INT_RANGES[target.type]
        if bounds[0] < low or bounds[1] > high:
            return _fail("SCHEMA-002", f"Manifest range [{bounds[0]}, {bounds[1]}] for column {origin!r} exceeds {target.type} bounds; narrowing may overflow.", edge.edge_id, mapping.target, origin_column=origin, manifest_min=bounds[0], manifest_max=bounds[1], target_min=low, target_max=high)
        return None
    return _fail("SCHEMA-006", f"Unknown transform {mapping.transform!r}.", edge.edge_id, mapping.target)


def _origin_by_target(name: str, edge: MigrationEdge, lineage: Mapping[str, str | None]) -> str | None:
    for mapping in edge.column_maps:
        if mapping.target == name:
            return lineage.get(mapping.source)
    return None


def _prove_path(
    path: tuple[MigrationEdge, ...],
    contracts: Mapping[str, SchemaContract],
    ranges: Mapping[str, tuple[int, int]],
    purpose: str,
) -> tuple[ProofFailure | None, dict[str, tuple[str, str]]]:
    first = contracts[path[0].from_version]
    lineage: dict[str, str | None] = {column.name: column.name for column in first.columns}
    target_cols: dict[str, ColumnDecl] = {}
    for edge in path:
        source = contracts.get(edge.from_version)
        target = contracts.get(edge.to_version)
        if source is None or target is None:
            return _fail("SCHEMA-005", f"Edge {edge.edge_id!r} references an undeclared schema version.", edge.edge_id, unproven=True), {}
        source_cols = source.column_map()
        target_cols = target.column_map()
        mapped_sources: set[str] = set()
        mapped_targets: set[str] = set()
        for mapping in edge.column_maps:
            if mapping.source not in source_cols:
                return _fail("SCHEMA-006", f"Edge {edge.edge_id!r} maps unknown source column {mapping.source!r}.", edge.edge_id, mapping.source), {}
            if mapping.target not in target_cols:
                return _fail("SCHEMA-006", f"Edge {edge.edge_id!r} maps unknown target column {mapping.target!r}.", edge.edge_id, mapping.target), {}
            if mapping.target in mapped_targets:
                return _fail("SCHEMA-006", f"Edge {edge.edge_id!r} writes target column {mapping.target!r} twice.", edge.edge_id, mapping.target), {}
            mapped_sources.add(mapping.source)
            mapped_targets.add(mapping.target)
            failure = _check_transform(edge, mapping, source_cols[mapping.source], target_cols[mapping.target], lineage, ranges)
            if failure is not None:
                return failure, {}
            if target_cols[mapping.target].required and not source_cols[mapping.source].required:
                return _fail("SCHEMA-007", f"Required target column {mapping.target!r} is fed by optional source column {mapping.source!r}.", edge.edge_id, mapping.target), {}
            if target_cols[mapping.target].key_role != "none" and source_cols[mapping.source].key_role == "none":
                return _fail("SCHEMA-002", f"Target key column {mapping.target!r} is fed by non-key source column {mapping.source!r}; uniqueness is unproven.", edge.edge_id, mapping.target, unproven=True), {}
        for name in edge.dropped_columns:
            dropped = source_cols.get(name)
            if dropped is None:
                return _fail("SCHEMA-006", f"Edge {edge.edge_id!r} drops unknown source column {name!r}.", edge.edge_id, name), {}
            if dropped.required or dropped.key_role != "none":
                return _fail("SCHEMA-006", f"Edge {edge.edge_id!r} drops required source column {name!r}; only optional columns may be dropped.", edge.edge_id, name), {}
            if purpose == "rollback":
                return _fail("SCHEMA-004", f"Edge {edge.edge_id!r} drops source column {name!r}; rollback cannot reconstruct it from the target.", edge.edge_id, name), {}
        for name in source_cols:
            if name not in mapped_sources and name not in edge.dropped_columns:
                return _fail("SCHEMA-006", f"Source column {name!r} is neither mapped nor declared dropped by edge {edge.edge_id!r}.", edge.edge_id, name), {}
        for column in target.columns:
            if (column.required or column.key_role != "none") and column.name not in mapped_targets:
                return _fail("SCHEMA-001", f"Required target column {column.name!r} has no proven lineage through edge {edge.edge_id!r}.", edge.edge_id, column.name), {}
        lineage = {column.name: _origin_by_target(column.name, edge, lineage) for column in target.columns}
    meaning = {origin: (name, target_cols[name].type) for name, origin in lineage.items() if origin is not None}
    return None, meaning


def _enum_paths(edges: tuple[MigrationEdge, ...], source: str, target: str, max_len: int) -> list[tuple[MigrationEdge, ...]]:
    adjacency: dict[str, list[MigrationEdge]] = {}
    for edge in sorted(edges, key=lambda item: item.edge_id):
        adjacency.setdefault(edge.from_version, []).append(edge)
    found: list[tuple[MigrationEdge, ...]] = []

    def walk(version: str, path: tuple[MigrationEdge, ...], seen: frozenset[str]) -> None:
        if len(found) >= _MAX_PATHS:
            return
        if version == target:
            found.append(path)
            return
        if len(path) >= max_len:
            return
        for edge in adjacency.get(version, ()):
            if edge.to_version not in seen:
                walk(edge.to_version, path + (edge,), seen | {edge.to_version})

    walk(source, (), frozenset({source}))
    return found


def _conflict(proven: list[tuple[tuple[str, ...], dict[str, tuple[str, str]]]]) -> ProofFailure | None:
    for left in range(len(proven)):
        for right in range(left + 1, len(proven)):
            left_path, left_meaning = proven[left]
            right_path, right_meaning = proven[right]
            for column in sorted(set(left_meaning) & set(right_meaning)):
                if left_meaning[column] != right_meaning[column]:
                    return _fail(
                        "SCHEMA-003",
                        f"Candidate paths assign conflicting meaning to source column {column!r}.",
                        column=column,
                        left_path=list(left_path),
                        right_path=list(right_path),
                        left_meaning=list(left_meaning[column]),
                        right_meaning=list(right_meaning[column]),
                    )
    return None


def prove_compatibility(
    config: SchemaMigrationConfig,
    source_version: str,
    target_version: str,
    ranges: Mapping[str, tuple[int, int]],
) -> SchemaProof:
    """Prove restorability of one backup schema to a target schema, statically."""

    def done(status: str, path: tuple[str, ...], attempts: tuple[PathAttempt, ...], failure: ProofFailure | None) -> SchemaProof:
        return SchemaProof(source_version, target_version, config.purpose, status, path, attempts, failure)

    if source_version == target_version:
        return done("compatible", (), (), None)
    contracts = config.contract_map()
    for version in (source_version, target_version):
        if version not in contracts:
            failure = _fail("SCHEMA-005", f"No schema contract declared for version {version!r}.", unproven=True, version=version)
            return done("unproven", (), (PathAttempt((), failure),), failure)
    paths = _enum_paths(config.edges, source_version, target_version, len(contracts))
    if not paths:
        failure = _fail("SCHEMA-005", f"No declared migration path from schema {source_version!r} to {target_version!r}.", unproven=True)
        return done("unproven", (), (PathAttempt((), failure),), failure)
    attempts: list[PathAttempt] = []
    proven: list[tuple[tuple[str, ...], dict[str, tuple[str, str]]]] = []
    for path in paths:
        failure, meaning = _prove_path(path, contracts, ranges, config.purpose)
        edge_ids = tuple(edge.edge_id for edge in path)
        attempts.append(PathAttempt(edge_ids, failure))
        if failure is None:
            proven.append((edge_ids, meaning))
    if proven:
        conflict = _conflict(proven)
        if conflict is not None:
            return done("incompatible", (), tuple(attempts), conflict)
        chosen = min(proven, key=lambda item: (len(item[0]), item[0]))
        return done("compatible", chosen[0], tuple(attempts), None)
    status = "incompatible" if any(not item.failure.unproven for item in attempts) else "unproven"
    return done(status, (), tuple(attempts), attempts[0].failure)
