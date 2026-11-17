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
| `CHAIN-005` | high | Parent schema differs from child schema |
| `CHAIN-006` | high | Backup start or finish is later than `as_of` |
| `CHAIN-009` | high | An ancestor chain is not restorable |

A restorable point requires a structurally complete chain, a ready artifact and
a ready artifact on every ancestor. Future rows are never restorable.

## Artifact and evidence — `ART-*`, `EVID-*`

| Rule | Severity | Trigger |
|---|---|---|
| `ART-001` | high | Per-backup manifest missing |
| `ART-002` | high | Manifest malformed or required fields invalid |
| `ART-003` | high | Catalog artifact file missing |
| `ART-004` | high | Artifact byte size differs from catalog |
| `ART-005` | critical | Artifact SHA-256 differs from catalog |
| `ART-006` | high | Manifest disagrees with catalog backup/row/schema |
| `ART-007` | high | Sharded (`manifest_version` 2) block is malformed |
| `ART-008` | high | Shard file missing or its path escapes the fixture root |
| `ART-009` | high | Shard size or SHA-256 differs from the manifest |
| `ART-010` | high | Usable shard vectors do not span all `k` source stripes |
| `ART-011` | high | One fault-domain loss leaves the stripes unrecoverable |
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

Shard findings use the same evidence posture. `ART-008`/`ART-009` mark
individual shards unusable; they are excluded before the linear proof, so a bad
shard can never inflate the rank. `ART-010` reports the achieved rank, the
missing dimensions and unit-vector witnesses. `ART-011` applies only to the
`single_fault_domain` purpose and names the first domain whose total loss breaks
full rank, with the remaining rank. Shard counts and byte totals are never used
as evidence of recoverability.

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
