# Data Contract

All timestamps are ISO 8601 UTC. `as_of` must end in `Z`; other offset-bearing
timestamps are converted to UTC. Paths are POSIX-style and relative to
`fixtures/`. Absolute paths, drive letters, backslash separators, `.` and `..`
components, symlink escapes and empty paths are rejected.

## Recovery plan — `fixtures/plans/recovery_plan.yaml`

Required top-level keys:

| Key | Type | Meaning |
|---|---|---|
| `as_of` | UTC ISO 8601 string ending `Z` | Fixed report clock and analysis endpoint |
| `analysis_window_days` | integer 1–365 | Window start is `as_of - days` |
| `datasets` | non-empty list | Dataset declarations |

Required dataset keys:

| Key | Type | Meaning |
|---|---|---|
| `dataset_id` | `[a-z][a-z0-9-]{2,63}` | Stable dataset identity |
| `display_name` | non-empty string | Synthetic display label |
| `rpo_minutes` | positive integer | Recovery point objective |
| `rto_minutes` | positive integer | Recovery time objective |
| `required_steps` | non-empty unique list | Mandatory drill procedure |
| `checksum_required` | boolean | Checksum evidence required |
| `rowcount_required` | boolean | Row-count evidence required |
| `owner_team` | non-empty string | Synthetic owner label |
| `maintenance_window` | non-empty string | Declared window label |
| `artifact_manifest_path` | safe relative directory | Holds `manifest-<backup_id>.json` |

The manifest path is a directory under the fixture root. It is validated before
any I/O. Each backup resolves to `manifest-<backup_id>.json` inside it.

## Backup catalog — `fixtures/catalog/backup_catalog.csv`

Required columns:

| Column | Type / rule |
|---|---|
| `dataset_id` | Must be declared in the plan |
| `backup_id` | Unique `[a-z][a-z0-9-]{2,63}` |
| `parent_backup_id` | Blank for full, required and valid for incremental |
| `backup_type` | `full` or `incremental` |
| `started_at`, `finished_at` | ISO 8601 with timezone; finish ≥ start |
| `artifact_path` | Safe relative file under the fixture root |
| `artifact_size_bytes` | Non-negative integer |
| `sha256` | Exactly 64 hexadecimal characters |
| `row_count` | Non-negative integer |
| `schema_version` | Non-empty string |

Duplicate IDs, unknown datasets, malformed hashes, unsafe paths, invalid types,
invalid enums, future timestamps and parent/schema/time failures are reported.
Rows that fail structural validation are rejected with a finding; they are never
silently discarded. Chain-level future timestamps and parent anomalies are
reported later with rule IDs.

## Artifact manifest — `fixtures/artifacts/manifest-<backup_id>.json`

```json
{
  "backup_id": "bk-orders-001",
  "row_count": 12000,
  "data_sha256": "<64 lowercase hex>",
  "schema_version": "3"
}
```

`row_count` and `schema_version` must match the catalog. `data_sha256` is the
expected restored-data checksum reported by drills. It is distinct from the
catalog `sha256`, which fingerprints the stored artifact file.

### Optional transaction summary — `transaction_summary`

A manifest may carry a small synthetic summary bundle used only by cohort
verification:

```json
{
  "transaction_summary": {
    "rows": [
      {
        "part_id": "p-ord-1",
        "tx_ref_masked": "tx-**-**",
        "amount": 70,
        "role": "order",
        "source_fingerprint": "<64 lowercase hex>"
      }
    ]
  }
}
```

Each row is one contribution: a stable `part_id` (unique across the cohort;
split parts of one logical record each get their own), a masked transaction
reference (`*` hides characters), a non-negative integer amount, a role of
`order`, `event`, `debit` or `credit`, and the fingerprint of the extract the
row was derived from. The source dataset/backup is the manifest that holds the
row. A malformed section raises `ART-007` and disables cohort evaluation for
that member; an absent section is not an error by itself.

## Transaction cohorts — `fixtures/plans/transaction_cohorts.yaml` (optional)

```yaml
schema_version: 1
cohorts:
  - cohort_id: cohort-close-1109
    purpose: strict_publish        # or triage_review
    members:
      - dataset_id: ds-orders
        backup_id: bk-orders-042
        expected_manifest_sha256: "<optional 64 hex pin>"
      - dataset_id: ds-ledger
        backup_id: bk-ledger-002
    required_roles: [order, event, debit, credit]
    anchor_roles: [debit, credit]
    role_sources:
      order: [ds-orders]
      event: [ds-events]
      debit: [ds-ledger]
      credit: [ds-ledger]
    search_budget: 100000          # optional, bounded
```

Members must be existing restorable points spanning at least two datasets; no
restore is executed and no closest cut is searched. Contributions attribute
only to anchors (distinct masked references among `anchor_roles` rows) that
refine their mask, each contribution is used at most once, and every used
transaction must close `required_roles`. The checker enumerates the bounded
integer domain exhaustively within `search_budget` and reports the exact
minimum and maximum net gap with complete matching witnesses. The verdict is
independent of per-dataset RPO and drill RTO and never uses the report clock
as transaction evidence.

## Drill log — `fixtures/logs/restore_drill.jsonl`

One JSON object per line. Required keys:

| Key | Type / rule |
|---|---|
| `drill_id` | Stable `[a-z][a-z0-9-]{2,63}` |
| `dataset_id`, `backup_id` | Must exist and agree with each other |
| `step` | `[a-z][a-z0-9_]{1,40}` |
| `status` | `success`, `failed` or `skipped` |
| `attempt` | Integer ≥ 1 |
| `started_at`, `finished_at` | ISO 8601 with timezone; finish ≥ start |
| `evidence_ref` | Safe relative path under `evidence/` |
| `detail` | String |
| `rows_restored` | Null or non-negative integer |
| `reported_sha256` | Null or 64 hexadecimal characters |

All attempts remain in the audit trail. The highest attempt per step is the
effective outcome; ties are broken by physical line number. Wall-clock RTO uses
the earliest start and latest finish across all attempts. Malformed JSONL lines
are rejected with `IN-012` and a physical line number.

## Evidence

Evidence files are referenced by `evidence_ref`. They must exist, be non-empty
and be readable. A `.json` evidence file must be an object containing a string
`evidence_id`. Evidence checks are deduplicated by reference and hashed.

## Report contract

`outputs/report.json` includes: schema/tool version, run ID, `generated_at`
(equal to configured `as_of`), status, summary, plan, input manifest, dataset
summaries, backups, chain results, restorable points, RPO/RTO results, drills,
artifact/evidence checks, findings, attribution and remediation plan.

Each finding contains `rule_id`, `severity`, `object_type`, `object_id`,
`message`, `file`, `line`, `input_sha256` and structured evidence. Input files
that are missing are traced to the catalog or drill-log SHA-256 that cited them;
the absent file itself naturally has no fingerprint.
