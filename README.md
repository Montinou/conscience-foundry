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
