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

### Versioned sharded form — `manifest_version: "2"`

A manifest without `manifest_version` (or `"1"`) keeps the single-file contract
above. An explicit `"2"` adds a `sharding` block for locally synthesized XOR
data/parity shards. The catalog `artifact_path` file remains the backup index
and is still verified with its catalog hash and size; shard paths never replace
it. Every shard path is confined by the same fixture-root fence.

```json
{
  "manifest_version": "2",
  "backup_id": "bk-orders-001",
  "row_count": 12000,
  "data_sha256": "<64 lowercase hex>",
  "schema_version": "3",
  "sharding": {
    "stripe_count": 3,
    "recovery_purpose": "current",
    "shards": [
      {
        "shard_id": "s1",
        "coefficients": [1, 0, 0],
        "path": "artifacts/shards/bk-orders-001/s1.bin",
        "size_bytes": 64,
        "sha256": "<64 lowercase hex>",
        "fault_domain": "zone-a"
      }
    ]
  }
}
```

| Key | Type / rule |
|---|---|
| `stripe_count` (`k`) | Integer 1–16, the bounded number of source stripes |
| `recovery_purpose` | `current` or `single_fault_domain` (defaults to `current`) |
| `shards` | Non-empty list; `shard_id` values are unique strings |
| `coefficients` | Exactly `k` GF(2) bits, each `0` or `1` |
| `path` | Safe relative file under the fixture root |
| `size_bytes` | Non-negative integer, checked against the file |
| `sha256` | Exactly 64 hexadecimal characters, checked against the file |
| `fault_domain` | Non-empty string grouping shards that fail together |

Each shard file is verified independently. A missing, escaping, wrong-size or
wrong-hash shard is unusable and never enters the usable set. The tool performs
no reconstruction: it runs deterministic GF(2) Gaussian elimination on the
usable coefficient vectors and proves whether their rank is `k`. File count and
byte totals never substitute for rank; repeated or zero vectors add no rank.
The report carries the independent basis, the missing-dimension witness
vectors and per-shard proofs, never shard contents.

`current` requires the usable matrix to be full rank. `single_fault_domain`
additionally removes every shard of each fault domain in turn and re-proves
full rank; it reports the first failing domain and the remaining rank. Shards
in one fault domain are never counted as independent redundancy.

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
