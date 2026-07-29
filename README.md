# Shimpz Services

This repository is the source of the Space-scoped Services consumed by Shimpz.

- `pg/` provisions Team-scoped PostgreSQL principals and databases without exposing the superuser;
- `egress/` is the current shared enforcement engine for Brain and Assistant-release traffic; and
- `app-egress/` is the current shared enforcement engine for Assistant destination policies.

PostgreSQL moves to `postgresql/` when the umbrella checkout moves from `drivers/` to `services/`.
The two enforcement engines remain current only until their already-decided Assistant and Brain
responsibilities are extracted. They are not classified as Services merely because they temporarily
share this repository.

Each current component preserves its fail-closed authentication, isolation, network, audit, and
secret-redaction boundaries during that transition.
