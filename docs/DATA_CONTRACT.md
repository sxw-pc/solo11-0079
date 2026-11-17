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
| `recovery_evidence_policy` | Optional; `strict_replay` (default) or `evidence_reuse` |

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
| `recovery_generation` | Optional; lowercase id opened by a successful `restore_base` |
| `data_digest` | Optional; null or 64 hex chars digest of the restored data object |

All attempts remain in the audit trail. The highest attempt per step is the
effective outcome; ties are broken by physical line number. Wall-clock RTO uses
the earliest start and latest finish across all attempts. Malformed JSONL lines
are rejected with `IN-012` and a physical line number.

### Recovery generations and evidence lineage

Logs without the two optional fields keep the legacy semantics and are read
unchanged. When either field appears, generation rules apply. A recovery
generation begins at a successful `restore_base` carrying
`recovery_generation`; a later successful `restore_base` opens a newer
generation and invalidates every downstream verification bound to an older
generation, regardless of attempt number. A successful `apply_incremental`
must reference the current generation and its `data_digest` becomes the
generation's final restored-data digest. Downstream steps
(`verify_rowcount`, `verify_checksum`, `publish_report`) bind to a generation
and, when a final digest exists, to that digest.

If a recovery step was retried and no current-generation downstream evidence
exists, the drill cannot inherit old success checks. The dataset's
`recovery_evidence_policy` selects one business-authorized route:

| Policy | Reuse condition |
|---|---|
| `strict_replay` (default) | Never reuse; re-run downstream verification after a new generation. The drill stays `inconclusive` until re-verified. |
| `evidence_reuse` | Reuse an old check only when the full 64-char `data_digest` equals the current generation digest and its evidence file is valid. |

Matching row counts, backup ids or file names alone never establish identical
data. A missing digest, a differing digest or an invalid evidence file blocks
reuse under both policies. Backup-chain restorability and artifact/evidence
hash checks are unchanged and always apply. A drill with no hard failure but
unproven lineage is reported `inconclusive`; only `success` can make RTO pass,
while RTO duration still spans the first attempt through the last finish and
includes failed retries. The report's drill-evidence ledger lists every adopted,
reused or invalidated step with the reason.

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
