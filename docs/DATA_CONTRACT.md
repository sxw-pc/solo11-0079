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

`maintenance_window` uses `ddd:HH:MM-HH:MMZ` with a lowercase three-letter weekday
(`mon`…`sun`), 24-hour UTC times and a same-day end after the start. Windows are
repeated weekly and clipped to the scheduling horizon.

The manifest path is a directory under the fixture root. It is validated before
any I/O. Each backup resolves to `manifest-<backup_id>.json` inside it.

## Remediation scheduling — `scheduling` block

The optional top-level `scheduling` block turns remediation actions into an
executable slot-level schedule. When present it is strictly validated; any issue
is `CFG-005` and prevents a run.

| Key | Type / rule | Meaning |
|---|---|---|
| `slot_minutes` | must equal `30` | Fixed discrete slot size |
| `horizon_days` | integer 1–28 | Scheduling horizon from `as_of` |
| `action_limit` | integer 1–12 (default 12) | Max actions in one independent owner-team batch |
| `objectives` | non-empty unique list of `min_overdue_high`, `min_impact` | Authorized optimization goals |
| `default_objective` | one of `objectives` | Objective reported as selected |
| `team_capacities` | mapping team → 1–16 | Parallel actions per slot for each owner team |
| `action_profiles` | mapping category → `{duration_minutes, impact_minutes}` | Must cover every remediation category |
| `dependencies` | list of dependency rules | Explicit prerequisite ordering |

Each dependency rule is `{dataset_id, prerequisite: selector, dependent: selector}`.
A selector is a non-empty conjunction of exact values over `action_id`,
`category`, `rule_id`, `object_type`, `object_id`. Selectors resolve only against
actions of the declared dataset; `action_id` values are the stable IDs from the
remediation plan. A selector that matches no action, a prerequisite that is itself
unschedulable, or a dependency cycle marks the dependent action unschedulable with
an explicit reason instead of being silently dropped.

Hard scheduling constraints: an action may start only in a discrete slot whose
entire duration fits inside its own dataset maintenance window and inside the
horizon; a team's concurrent actions per slot never exceed its declared capacity;
and a dependent action starts only after every prerequisite has finished.

Two objectives are optimized with identical hard constraints:

- `min_overdue_high` — fewest overdue high-risk actions, then fewest unscheduled
  actions, then least maintenance impact.
- `min_impact` — most scheduled actions, then least maintenance impact, then
  fewest overdue high-risk actions.

Unscheduled actions count as overdue, so no objective is improved by dropping
work. Search is exact. Any action left out is reported with one of
`unknown_dataset`, `invalid_maintenance_window`, `no_team_capacity`,
`no_duration_profile`, `no_window_slot_in_horizon`, `action_limit_exceeded`,
`dependency_missing`, `dependency_cycle`, `dependency_unschedulable`,
`dependency_conflict`, `capacity_conflict`, `window_conflict` or
`search_incomplete`. The result reports overdue counts, total maintenance-impact
minutes and every unscheduled action for both objectives.

Independent owner-team batches are the exact-solve units: capacity is declared
per team and every dependency is dataset-scoped, so no slot constraint crosses a
team. A batch above `action_limit` is returned unplanable, with every action in
that batch explained; no action is ever silently truncated. The schedule reports
`batches` with each team's action count and over-limit flag, plus an overall
`status` of `empty`, `unplanable`, `partial` or `feasible`.

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
artifact/evidence checks, findings, attribution and remediation plan. The
remediation plan carries the action list plus a `schedule` object with both
objectives, the selected objective, every scheduled slot and every unscheduled
action with its reason.

Each finding contains `rule_id`, `severity`, `object_type`, `object_id`,
`message`, `file`, `line`, `input_sha256` and structured evidence. Input files
that are missing are traced to the catalog or drill-log SHA-256 that cited them;
the absent file itself naturally has no fingerprint.
