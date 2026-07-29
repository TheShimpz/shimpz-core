# Shimpz Services

This repository is the source of the Space-scoped Services consumed by Shimpz.

- `pg/` provisions Team-scoped PostgreSQL principals and databases without exposing the superuser;
- `egress/` is the current shared enforcement engine for Brain and Assistant-release traffic.

PostgreSQL moves to `postgresql/` when the umbrella checkout moves from `drivers/` to `services/`.
The remaining enforcement engine stays current only until its already-decided Brain and
Assistant-release responsibilities are extracted. It is not classified as a Service merely because
it temporarily shares this repository.

Assistant runtime egress moved to the `shimpz-assistants` repository at `egress/`.

Each current component preserves its fail-closed authentication, isolation, network, audit, and
secret-redaction boundaries during that transition.
