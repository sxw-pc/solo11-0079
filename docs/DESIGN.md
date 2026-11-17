# Design

## Goal

Given a local backup catalog, drill log, recovery targets and synthetic evidence,
produce a deterministic answer to four questions:

1. Which backups are genuinely restorable?
2. Does the observed recovery posture satisfy declared RPO and RTO?
3. Which evidence, chain or consistency condition caused a failure?
4. What is the smallest traceable re-drill and remediation plan?

DrillVerify stops at static evidence review. It never executes a backup, restore,
cleanup or remote operation.

## Module map

| Module | Responsibility |
|---|---|
| `config.py` | Strict recovery-plan parsing and path confinement |
| `loaders.py` | CSV/JSONL readers preserving physical line numbers |
| `validators.py` | Row validation, cross-reference checks, explicit rejection |
| `evidence.py` | Artifact, manifest and evidence-file integrity |
| `backup_chain.py` | Full/incremental chain reconstruction and points |
| `objectives.py` | RPO gap and wall-clock RTO evaluation |
| `consistency.py` | Required step coverage, retries, row/hash reconciliation |
| `attribution.py` | Stable failure categories and probes |
| `planner.py` | Deterministic owner-assigned remediation actions plus action revisions |
| `approvals.py` / `approvals_load.py` | Synthetic approval-book records and strict loading |
| `approvals_auth.py` | Delegation-path resolution and evidence binding |
| `approvals_review.py` / `approvals_verdict.py` | Two-contract closure verdicts |
| `closure_ledger.py` | Closure-review persistence for the read-only console |
| `reporting.py` | JSON, Markdown and self-contained HTML output |
| `ledger.py` | Append-only SQLite audit rows and query-only reads |
| `web.py` | Local read-only Flask review console |
| `pipeline.py` | Ordered orchestration and run-level status |
| `cli.py` | `run`, `demo`, `validate` and `serve` entry points |

Files are kept below 300 lines. Domain types are split among `models.py`,
`records.py`, `results.py` and `actions.py` to avoid one oversized module.

## Stage order

```text
plan -> loaders -> validators -> artifacts/evidence
     -> chains/restorable points
     -> drill checks + RPO/RTO
     -> findings + attribution
     -> remediation plan
     -> report writers + ledger
```

Each stage consumes only validated records. Input findings are retained and
merged at the end. Findings are deduplicated by `(rule, object, file, line)` and
sorted by severity, rule, object and source location.

## Restorable-point semantics

An incremental backup is structurally restorable only when:

- its parent exists in the same dataset;
- the parent chain reaches a full backup without a cycle;
- parent finish time is not after child start time;
- parent and child schema versions agree;
- every member is at or before `as_of`;
- every artifact and per-backup manifest in the ancestry is ready.

Artifact readiness includes catalog file presence, byte size, file SHA-256 match,
manifest presence, manifest parse success, and catalog/manifest agreement on
backup ID, row count and schema version.

## Objective semantics

RPO:

- consider restorable points with `window_start <= finished_at <= as_of`;
- sort by finish time then backup ID;
- compute each adjacent gap and the last-point-to-`as_of` gap;
- choose the maximum with deterministic tie-breaking;
- fail when maximum gap is strictly greater than the target.

RTO:

- group events by drill;
- use the earliest start and latest finish across every attempt;
- compare whole elapsed minutes with the dataset target;
- mark unsuccessful drills `not_met`; mark duration excess as `breach`.

## Determinism strategy

The run ID is a truncated SHA-256 of tool/report version, `as_of`, window, sorted
dataset IDs and the sorted input fingerprint manifest. Report content never uses
wall-clock time. SQLite row IDs are deliberately excluded from deterministic
output. Re-running on unchanged inputs produces byte-identical JSON, Markdown,
HTML and remediation-plan files.

## Failure model

Input problems are `error`/`warning`; analytical problems are `critical`, `high`,
`medium` or `info`. A run fails when any finding is `critical`, `high` or `error`;
it warns for `medium`/`warning`; otherwise it passes. A failed drill is a valid
run result, not a pipeline crash. Only an unusable recovery plan prevents a run.

## Closure review semantics

A remediation action is an operational plan entry, not a claim that a fix
succeeded. The closure review therefore answers a narrower question: may the
*process* around the action be recorded as closed?

Every action carries a content-derived `revision` over its priority, rule IDs,
probes and source input hashes. An approval in the optional approval book is
bound to that revision and to one completion-evidence version. A later run that
changes a source finding, probe location or probe hash produces a different
revision; the old approval is not inherited and is never reused for another
action.

Two authorization contracts are evaluated together:

- `historical`: the two approvers were authorized when they signed, even if a
  delegation was revoked later.
- `current`: each delegation chain must also still be valid at the closure
  decision instant.

Delegation chains must be time-bounded, acyclic, within the role boundary and
founded on a direct role holder. The action owner and the completion declarer
must be different actual people from both approvers; aliases sharing an
`identity_id` do not create independence. A count of `approved` events is never
sufficient. Withdrawals and evidence replacements reopen a previously closed
process and name the broken authorization or evidence input as a witness.
Missing identity, an invalid book or an exceeded event budget yields `unproven`
rather than a guess.

The review never changes backup chains, restorable points, RPO/RTO results or
action due dates. Without an approval book every action keeps its original plan
view and no closure is claimed.

## Web and ledger design

The ledger stores the full report snapshot plus normalized input, finding,
objective, chain, drill and action rows. The console reads through query-only
SQLite connections. Pages are small Jinja templates with shared local CSS; there
is no front-end build chain or browser automation. Route IDs are integer ledger
rows, while report identity remains the stable content-derived run ID.
