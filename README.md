# DrillVerify — 备演核验台

DrillVerify is a fully offline, configuration-driven bench for reviewing local
backup/restore-drill evidence. It does not run backups or restores. It rebuilds
backup chains, selects defensible restorable points, checks RPO/RTO evidence,
attributes failures, and produces a deterministic re-drill plan and audit ledger.

All bundled data is synthetic. Paths, teams, datasets and evidence are placeholders.

## Quick start

```bash
python -m pip install -r requirements.txt
make test
make demo
make serve
```

`make demo` reads `fixtures/`, then writes:

- `outputs/report.json`, `outputs/report.md`, `outputs/report.html`
- `outputs/remediation_plan.json`
- `outputs/run_manifest.json`
- `outputs/ledger.sqlite3`

The review console listens only on `127.0.0.1:5000`. It opens SQLite with
`PRAGMA query_only = ON`, registers GET/HEAD/OPTIONS routes only, and uses local
templates and CSS with no CDN, JavaScript dependency, online font or remote asset.

## Commands

```bash
PYTHONPATH=src python -m drillverify demo --fixtures fixtures --out outputs
PYTHONPATH=src python -m drillverify validate --fixtures fixtures
PYTHONPATH=src python -m drillverify serve --db outputs/ledger.sqlite3 --host 127.0.0.1 --port 5000
```

`demo` and `run` exit `0` when a run was produced, even when the run status is
`fail` (a failed drill is a valid finding). Add `--strict` to exit `1` when the
report status is `fail`. Unusable configuration exits `2`.

Binding is rejected unless the host is exactly `127.0.0.1`, `localhost` or `::1`.
There are no write, execute, rerun, delete or downstream-dispatch endpoints.

## Pipeline

1. Load and validate the recovery plan, catalog CSV and drill JSONL.
2. Hash every input and reject unsafe fixture paths.
3. Check artifact files, sizes, SHA-256 values and per-backup manifests.
4. Rebuild full/incremental chains and select restorable points.
5. Evaluate RPO gaps and drill wall-clock RTO.
6. Check required steps, evidence, row counts and checksums.
7. Attribute failures to stable categories and generate owner-assigned actions.
8. Bind actions to discrete maintenance-window slots and report overdue,
   impact and unschedulable reasons for both authorized objectives.
9. Write reports, a self-contained HTML artifact and an append-only SQLite ledger.

## Determinism and traceability

- Configured `as_of` is the only report clock. Runtime `now()` is never used.
- Every finding has a rule ID, object ID, file, line, input SHA-256 and stable sort key.
- Report JSON, Markdown, HTML and the remediation plan are byte-stable for the same
  inputs. SQLite row IDs may differ between runs and are not part of report content.
- `fixtures/expected/` holds golden summary and finding projections for the demo.

## Safety boundaries

DrillVerify never calls a backup or restore executable, never reads production
paths, never opens a network connection, never accepts a remote bind address and
never stores credentials. Required evidence lives under `fixtures/evidence/`; all
manifest, artifact and evidence paths are confined to the fixture root.

## Layout

```text
src/drillverify/      pipeline, validators, report writers, ledger, read-only web app
fixtures/             synthetic plan, catalog, drill log, evidence and artifacts
fixtures/expected/    deterministic demo snapshots
tests/                offline pytest suite
docs/                 data contract, rules, compliance and design
```

See `docs/DATA_CONTRACT.md`, `docs/RULES.md`, `docs/COMPLIANCE.md` and
`docs/DESIGN.md` for details.
