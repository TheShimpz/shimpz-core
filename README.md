# Shimpz Services

This repository is the source of the Space-scoped Services consumed by Shimpz.

- `pg/` provisions Team-scoped PostgreSQL principals and databases without exposing the superuser.

PostgreSQL moves to `postgresql/` when the umbrella checkout moves from `drivers/` to `services/`.

Assistant runtime egress moved to the `shimpz-assistants` repository at `egress/`.
Assistant release policy moved to the same repository at `release/`.
Brain provider egress moved to the `shimpz-brain` repository at `egress/`.

PostgreSQL preserves its fail-closed authentication, Team isolation, audit, and secret-redaction
boundaries during the remaining path and vocabulary transition.
