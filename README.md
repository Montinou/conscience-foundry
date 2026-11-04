# conscience-foundry

`conscience_foundry` is a domain-agnostic Python package of contracts and processing for
verified text artifacts. It admits source files, extracts canonical UTF-8 text with exact
Unicode-scalar coordinates, records every state change in a PostgreSQL ledger and builds
content-addressed, independently verifiable releases. It has no consumer imports, no shared
consumer database and no model or GPU dependency.

## Scope

- Pydantic-maintained wire contracts, exported as JSON Schema 2020-12, with canonical JSON
  (RFC 8785) identities and digests.
- A single F1 processor, `text.utf8.v1`: bytes in, the same bytes out, no normalization, one
  body section.
- Budget, attempt and release state owned by one PostgreSQL ledger; workers never touch it.
- An explicit operator command line (`cfoundry`) where every effect needs a flag and a grant.
- Fake transports and synthetic fixtures for offline acceptance. Live providers, credentials,
  tariffs and endpoints are never defaults; they are supplied from outside the repository, and a
  missing value blocks.

Private data, raw corpora, credentials and operational records do not belong in this repository
or in any built distribution.

## Quick start

```
uv sync
uv run ruff check .
uv run mypy src/conscience_foundry
uv run pytest tests/acceptance/test_public_package.py -q
```

Database tests need an explicitly authorized disposable PostgreSQL; see the guide.

## Guide

[docs/guide/f1.md](docs/guide/f1.md) documents the commands, scopes, evidence labels, the locked
toolchain, isolated PostgreSQL requirements, live blockers and every acceptance gate that has not
been run.

## License

Apache License 2.0; see `LICENSE`.

## Cooperative local execution and settlement

Local execution requires independently approved operator configuration: an existing allocator and
bootstrap bound to its roots, a runtime manifest matching every approved execution configuration,
and a separately approved quote manifest outside the repository. Supply explicit installed limits
for `cfoundry.local-allocation-estimate.v1`, `cf.local-process-observation.v1`,
`cfoundry.local-attempt-allocation.v1`, and `cfoundry.local-storage-allocation.v1`; the manifest
envelope uses the existing `cf.metadata-schema.v1` limit. Setup is a separate operator action:
commands reopen trusted state and never initialize or reset it. Each effect requires its own
explicit command grant. This worker is cooperative and deterministic; it is not a hard OS sandbox
or a CPU/RSS quota.

After an attempt has reached a confirmed terminal state and been reconciled, while its funding
window is open, issue `cfoundry local-receipts --attempt-id ID --execute`. Save both returned
Refs as JSON files. Settle each terminal attempt using `cfoundry record-billing --attempt-id ID
--amount AMOUNT --evidence ATTEMPT_REF_FILE --execute`, using the configured fixed internal
allocation charge. This charge is not a provider bill. Once every attempt is terminal, reconciled,
and settled, use `cfoundry close-local-storage --run-id ID --evidence STORAGE_REF_FILE --execute`.
It verifies the retained candidate, closes the complete durable allocation and settles its fixed
storage charge. No command automatically cleans retained data.

An uncertain process or result keeps its reservation; do not retry a dispatch automatically.
Funding expiry prevents new candidates and artifact copies, but already durable valid evidence
can finish a historical close or settlement with current operator authorization. If closure
succeeds but settlement is interrupted, retry the close command with an already retained valid
candidate. Before the first settlement any equivalent retained candidate can finalize; afterward
the committed exact Ref and amount bind retries, and a different Ref is refused.
