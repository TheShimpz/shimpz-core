# Services repository rules

## Authority

- This repository owns Space-scoped Services. PostgreSQL is currently the only Service.
- A Service exposes one common platform API while preserving isolated Team bindings. This repository does not own
  Team lifecycle, Assistant egress, Assistant release, Brain egress, or generic shared daemons.
- Read the canonical [Shimpz architecture](https://github.com/TheShimpz/shimpz/blob/main/docs/ARCHITECTURE.md)
  before adding a Service or changing authority, protocols, runtime topology, or source placement. Adding a Service
  requires an ADR.

## Delivery and engineering

- Deliver the smallest useful microtask, validate it, commit it with a clear English conventional message, and
  push it immediately.
- When working through the umbrella checkout, commit and push this repository before committing its umbrella
  gitlink.
- Shimpz is pre-production. Change the current contract directly; do not add Driver aliases, earlier schemas,
  retired endpoints, or cleanup code triggered only by obsolete state.
- Preserve per-Team principals, superuser isolation, file-backed tokens, least privilege, idempotent lifecycle,
  audit redaction, and fail-closed authentication.
- Use Python 3.14.
- Tests that support workers use half of local processors and all GitHub Actions runner processors.

## Validation

- This standalone repository has no Ruff authority. Before committing Python, run
  `ruff check --config ruff.toml services` from the umbrella root.
- Run the PostgreSQL Service tests with `python3 postgresql/tests/test_postgresql_service.py`.
