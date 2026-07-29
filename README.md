# Shimpz Services

This repository is the source of the Space-scoped Services consumed by Shimpz.

- `postgresql/` provisions Team-scoped PostgreSQL principals and databases without exposing the
  superuser.

Assistant runtime egress moved to the `shimpz-assistants` repository at `egress/`.
Assistant release policy moved to the same repository at `release/`.
Brain provider egress moved to the `shimpz-brain` repository at `egress/`.

PostgreSQL preserves fail-closed authentication, Team isolation, audit, and secret redaction.
