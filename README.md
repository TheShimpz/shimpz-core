# Shimpz Services

This repository is the source of the Space-scoped Services consumed by Shimpz.

- `postgresql/` provisions Team-scoped PostgreSQL principals and databases without exposing the
  superuser.

PostgreSQL preserves fail-closed authentication, Team isolation, audit, and secret redaction.
