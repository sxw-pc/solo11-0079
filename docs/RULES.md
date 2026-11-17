# Rule Catalogue

Rule IDs are stable. Every finding carries the rule ID, object identity, source
file, physical line where applicable, and input SHA-256. Severities are:

`critical > high > error > medium > warning > low > info`

Input errors use `error`; input advisories use `warning`; analytical conclusions
use `critical`, `high`, `medium`, or `info`.

## Configuration — `CFG-*`

| Rule | Severity | Trigger |
|---|---|---|
| `CFG-001` | error | Missing/invalid plan key, timestamp, dataset field or YAML |
| `CFG-002` | error | Duplicate dataset declaration |
| `CFG-003` | error | No usable dataset declaration |
| `CFG-004` | error | Artifact manifest path escapes the fixture root |

A plan with fatal configuration findings cannot produce a run. A duplicate or
unsafe dataset declaration is rejected while other valid datasets continue.

## Input and schema — `IN-*`

| Rule | Severity | Trigger |
|---|---|---|
| `IN-000` | error | Required input file is missing |
| `IN-001` | error | Required CSV column missing or malformed CSV row |
| `IN-002` | error | Required value missing |
| `IN-003` | error | Invalid type, range, identifier, zero-size advisory |
| `IN-004` | error | Invalid ISO 8601 timestamp |
| `IN-005` | error | Duplicate `backup_id` |
| `IN-006` | error | Unknown `dataset_id` |
| `IN-007` | error | Unknown `backup_id` in a drill event |
| `IN-008` | error | Invalid backup type or parent/precondition mismatch |
| `IN-009` | error | Absolute path, traversal, backslash or path escape |
| `IN-010` | error | Evidence reference outside `evidence/` |
| `IN-011` | error | Invalid SHA-256 representation |
| `IN-012` | error | Malformed JSONL line |
| `IN-013` | error | Invalid drill status |
| `IN-014` | error | Drill identity conflict or dataset/backup mismatch |
| `IN-015` | error | Finish timestamp precedes start timestamp |

Bad rows are rejected with a finding. Rejection is explicit; no malformed row is
silently dropped.

## Backup chain — `CHAIN-*`

| Rule | Severity | Trigger |
|---|---|---|
| `CHAIN-001` | high | Incremental parent absent from the same dataset |
| `CHAIN-002` | high | Incremental has no full-backup ancestry |
| `CHAIN-003` | critical | Parent cycle |
| `CHAIN-004` | high | Parent finishes after child starts |
| `CHAIN-005` | high | Parent schema differs from child schema and no declared migration edge proves it safe |
| `CHAIN-006` | high | Backup start or finish is later than `as_of` |
| `CHAIN-009` | high | An ancestor chain is not restorable |
| `CHAIN-010` | high | Backup schema is not proven compatible with the plan's restore-target schema |

A restorable point requires a structurally complete chain, a ready artifact and
a ready artifact on every ancestor. Future rows are never restorable. Without a
`schema_migration` plan section, schema versions must be equal (legacy rule).
With one, a static proof decides: version names may differ when a declared,
fully proven migration path exists.

## Schema compatibility — `SCHEMA-*`

Static, offline proofs only: no migration is ever executed and no data is
transformed. A proof combines column lineage, integer ranges, nullability and
key uniqueness along every candidate edge path. Missing range evidence is
reported as unproven, never as success.

| Rule | Severity | Trigger |
|---|---|---|
| `SCHEMA-001` | high | Required target column has no proven lineage through an edge |
| `SCHEMA-002` | high | Narrowing or key uniqueness evidence is missing (unproven) or contradicted |
| `SCHEMA-003` | high | Two candidate paths assign conflicting meaning to one source column |
| `SCHEMA-004` | high | Edge drops a column; the rollback purpose cannot reconstruct it |
| `SCHEMA-005` | high | No declared contract for a version or no migration path (unproven) |
| `SCHEMA-006` | high | Edge or contract is invalid (unknown column, bad transform, unaccounted column) |
| `SCHEMA-007` | high | Optional (nullable) source column feeds a required target column |

## Artifact and evidence — `ART-*`, `EVID-*`

| Rule | Severity | Trigger |
|---|---|---|
| `ART-001` | high | Per-backup manifest missing |
| `ART-002` | high | Manifest malformed or required fields invalid |
| `ART-003` | high | Catalog artifact file missing |
| `ART-004` | high | Artifact byte size differs from catalog |
| `ART-005` | critical | Artifact SHA-256 differs from catalog |
| `ART-006` | high | Manifest disagrees with catalog backup/row/schema |
| `EVID-001` | high | Referenced evidence file missing |
| `EVID-002` | high | Evidence empty, unreadable or invalid JSON evidence |
| `EVID-004` | high | Required drill step absent |
| `EVID-005` | high | Effective attempt for required step failed |
| `EVID-006` | medium | Effective required step skipped |
| `EVID-007` | warning | Step retried; retries count toward RTO |
| `EVID-008` | info | Extra step outside declared procedure |
| `EVID-009` | high | Drill references a non-restorable backup |

Evidence findings are deduplicated by reference. Drill coverage uses the highest
attempt per step; retry evidence and all attempts remain available in the log.

## Consistency — `CONS-*`

| Rule | Severity | Trigger |
|---|---|---|
| `CONS-001` | high | `rows_restored` differs from manifest row count |
| `CONS-002` | high | `reported_sha256` differs from manifest data hash |
| `CONS-003` | medium | Required row-count value unavailable or not successful |
| `CONS-004` | medium | Required checksum value unavailable or not successful |

If a manifest is unavailable, the catalog row count is used for the row-count
comparison. Checksum comparison requires a manifest data hash; absence of a
required checksum is reported separately.

## Objectives — `OBJ-*`

| Rule | Severity | Trigger |
|---|---|---|
| `OBJ-POINT-001` | critical | No restorable point inside the analysis window |
| `OBJ-RPO-001` | high | Maximum adjacent/last-point gap exceeds RPO |
| `OBJ-RTO-001` | high | Wall-clock drill duration exceeds RTO |

RPO measures gaps between adjacent in-window restorable points and the gap from
the last point to `as_of`. A gap exactly equal to the objective passes. RTO uses
all attempts, including retries; an unsuccessful drill is `not_met` even when
its duration is below target.

## Attribution and remediation

Each finding maps to one category: `configuration`, `input_quality`,
`chain_integrity`, `artifact_integrity`, `evidence_integrity`,
`data_consistency`, `recoverability`, `rpo_gap`, `rto_gap` or `general`.

Material findings (`critical`, `high`, `error`, `medium`) are grouped by category,
owner, dataset and object. Each action receives a stable content-derived ID, SLA
due date (`as_of` + 1/3/7 days for critical/high+error/medium), owner and all
source rule IDs. Warnings and informational findings never create actions.
