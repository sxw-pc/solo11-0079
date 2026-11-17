"""Strict validation of the plan's declarative schema-migration section."""

from __future__ import annotations

from .models import ColumnDecl, ColumnMap, MigrationEdge, SchemaContract, SchemaMigrationConfig
from .schema_compat import EXECUTABLE_KEYS, KEY_ROLES, PURPOSES, RANGE_PROOFS, TRANSFORMS, TYPES


def parse_schema_migration(raw: object) -> tuple[SchemaMigrationConfig | None, list[str]]:
    """Validate the declarative plan section; reject any executable content."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        return None, ["schema_migration must be a mapping."]
    target_version = raw.get("target_version")
    if not isinstance(target_version, str) or not target_version.strip():
        errors.append("schema_migration.target_version must be a non-empty string.")
    purpose = raw.get("purpose")
    if purpose not in PURPOSES:
        errors.append(f"schema_migration.purpose must be one of {', '.join(PURPOSES)}.")
    contracts_raw = raw.get("contracts")
    contracts: list[SchemaContract] = []
    versions: set[str] = set()
    if not isinstance(contracts_raw, list) or not contracts_raw:
        errors.append("schema_migration.contracts must be a non-empty list.")
        contracts_raw = []
    for index, item in enumerate(contracts_raw):
        prefix = f"schema_migration.contracts[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a mapping.")
            continue
        version = item.get("version")
        if not isinstance(version, str) or not version.strip():
            errors.append(f"{prefix}.version must be a non-empty string.")
            continue
        if version in versions:
            errors.append(f"Schema contract for version {version!r} is declared more than once.")
            continue
        versions.add(version)
        columns_raw = item.get("columns")
        columns: list[ColumnDecl] = []
        names: set[str] = set()
        if not isinstance(columns_raw, list) or not columns_raw:
            errors.append(f"{prefix}.columns must be a non-empty list.")
            columns_raw = []
        for cindex, column in enumerate(columns_raw):
            cprefix = f"{prefix}.columns[{cindex}]"
            if not isinstance(column, dict):
                errors.append(f"{cprefix} must be a mapping.")
                continue
            name, ctype = column.get("name"), column.get("type")
            required, key_role = column.get("required"), column.get("key_role", "none")
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{cprefix}.name must be a non-empty string.")
                continue
            if name in names:
                errors.append(f"Column {name!r} is declared more than once in schema version {version!r}.")
                continue
            names.add(name)
            if ctype not in TYPES:
                errors.append(f"{cprefix}.type must be one of {', '.join(TYPES)}.")
                continue
            if not isinstance(required, bool):
                errors.append(f"{cprefix}.required must be a boolean.")
                continue
            if key_role not in KEY_ROLES:
                errors.append(f"{cprefix}.key_role must be one of {', '.join(KEY_ROLES)}.")
                continue
            columns.append(ColumnDecl(name, ctype, required, key_role))
        if sum(1 for column in columns if column.key_role == "primary") > 1:
            errors.append(f"Schema version {version!r} declares more than one primary key.")
        if columns:
            contracts.append(SchemaContract(version, tuple(columns)))
    edges_raw = raw.get("edges")
    edges: list[MigrationEdge] = []
    edge_ids: set[str] = set()
    if not isinstance(edges_raw, list):
        errors.append("schema_migration.edges must be a list.")
        edges_raw = []
    for index, item in enumerate(edges_raw):
        prefix = f"schema_migration.edges[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be a mapping.")
            continue
        if any(key in item for key in EXECUTABLE_KEYS):
            errors.append(f"{prefix} must be declarative; executable content is forbidden.")
            continue
        edge_id = item.get("edge_id")
        from_version, to_version = item.get("from_version"), item.get("to_version")
        if not isinstance(edge_id, str) or not edge_id.strip():
            errors.append(f"{prefix}.edge_id must be a non-empty string.")
            continue
        if edge_id in edge_ids:
            errors.append(f"Migration edge {edge_id!r} is declared more than once.")
            continue
        edge_ids.add(edge_id)
        if from_version not in versions or to_version not in versions:
            errors.append(f"{prefix} must reference declared contract versions.")
            continue
        if from_version == to_version:
            errors.append(f"{prefix} must connect two different versions.")
            continue
        maps_raw = item.get("column_maps", [])
        dropped_raw = item.get("dropped_columns", [])
        maps: list[ColumnMap] = []
        if not isinstance(maps_raw, list):
            errors.append(f"{prefix}.column_maps must be a list.")
            maps_raw = []
        for mindex, mapping in enumerate(maps_raw):
            mprefix = f"{prefix}.column_maps[{mindex}]"
            if not isinstance(mapping, dict):
                errors.append(f"{mprefix} must be a mapping.")
                continue
            if any(key in mapping for key in EXECUTABLE_KEYS):
                errors.append(f"{mprefix} must be declarative; executable content is forbidden.")
                continue
            source, target = mapping.get("source"), mapping.get("target")
            transform = mapping.get("transform")
            range_proof = mapping.get("range_proof", "none")
            if not isinstance(source, str) or not source.strip() or not isinstance(target, str) or not target.strip():
                errors.append(f"{mprefix} needs non-empty source and target columns.")
                continue
            if transform not in TRANSFORMS:
                errors.append(f"{mprefix}.transform must be one of {', '.join(TRANSFORMS)}.")
                continue
            if range_proof not in RANGE_PROOFS:
                errors.append(f"{mprefix}.range_proof must be one of {', '.join(RANGE_PROOFS)}.")
                continue
            maps.append(ColumnMap(source, target, transform, range_proof))
        if not isinstance(dropped_raw, list) or any(not isinstance(name, str) or not name.strip() for name in dropped_raw):
            errors.append(f"{prefix}.dropped_columns must be a list of non-empty strings.")
            dropped_raw = []
        edges.append(MigrationEdge(edge_id, from_version, to_version, tuple(maps), tuple(dropped_raw)))
    if isinstance(target_version, str) and target_version.strip() and versions and target_version not in versions:
        errors.append("schema_migration.target_version must have a declared contract.")
    if errors:
        return None, errors
    return SchemaMigrationConfig(target_version, purpose, tuple(contracts), tuple(edges)), []
