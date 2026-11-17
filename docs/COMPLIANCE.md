# Compliance and Safety

## Offline operation

- DrillVerify makes no DNS, HTTP, socket, cloud-SDK or database-network calls.
- Tests monkeypatch `socket.connect`, `create_connection` and `getaddrinfo` to
  raise, then run the full pipeline.
- Templates and CSS contain no remote URLs, `@import`, CDN references or scripts.
- Required runtime dependencies are Flask, Jinja2, PyYAML and the Python standard
  library. pytest is test-only.
- No online installation step is performed by the code or Make targets. Install
  dependencies from an approved local package source before running.

## Local-only service

- `serve` accepts only `127.0.0.1`, `localhost` or `::1`.
- Other hosts, including `0.0.0.0`, public addresses and DNS names, are rejected
  before the Flask server starts.
- The default port is 5000 and the default bind address is loopback.
- SQLite read paths issue `PRAGMA query_only = ON` and open no write transaction.
- Registered routes are GET/HEAD/OPTIONS only. A before-request guard rejects
  POST, PUT, PATCH and DELETE with 405.
- No endpoint accepts a command, task, shell string, SQL fragment or file write.

## Read-only review boundary

The web console is a viewer over an existing ledger. It cannot:

- modify catalog or plan inputs;
- delete findings or runs;
- execute, schedule, rerun or dispatch a backup or restore;
- connect to a backup server;
- upload or download evidence outside the local ledger;
- change user roles or permissions.

## Data and secrets

The repository contains only synthetic fixtures:

- team names `team-alpha`, `team-beta`, `team-gamma`;
- dataset IDs `ds-orders`, `ds-events`, `ds-ledger`;
- backup IDs and artifact paths under `fixtures/`;
- timestamps anchored to the configured `as_of`;
- no credentials, tokens, private keys, certificates, accounts or production paths.

Hash values in fixtures are ordinary SHA-256 digests of synthetic content. They
are not secrets. Evidence JSON contains only synthetic IDs and notes.

## Path confinement

Every declared catalog artifact path, evidence reference, manifest directory and
sharded-manifest shard path is normalized and resolved under the fixture root.
Absolute paths, drive letters, backslashes, traversal components, home expansion
and symlink escapes are rejected before opening a file. Rejected rows produce
errors rather than being silently skipped.

## Sharded-artifact proof boundary

- Shard verification is static: files are only read for size and SHA-256.
- No shard is decoded, combined, reconstructed, exported or transmitted.
- Recoverability is a GF(2) linear-independence proof over verified coefficient
  vectors, never a file-count or byte-total heuristic.
- Fault-domain tolerance removes shards conceptually and re-runs elimination;
  no failure is injected and no storage system is contacted.

## Determinism and auditability

- No report timestamp is read from the runtime clock.
- Findings, chain results, points, objectives, actions and input manifests have
  explicit stable sort keys.
- JSON is emitted with sorted keys and fixed indentation.
- The HTML report embeds its CSS and has no external dependencies.
- SQLite uses auto-increment row IDs; those IDs are the only documented variation
  between otherwise identical runs.

## Known limitations

- The service is a local review bench, not an authenticated multi-user system.
- There is no backup engine, restore executor, scheduler, alerting integration or
  remote storage adapter.
- Row-count and checksum reconciliation trusts the declared manifest as the
  expected value; it does not recompute data content from a real restore.
- The Werkzeug development server is intentionally used for local review only.
