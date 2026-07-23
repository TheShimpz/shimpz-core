# Shimpz core Drivers

This repository contains the narrow privilege brokers used by the hosted and local Shimpz control
planes:

- `team/` owns Team and Assistant lifecycle, Brain turns, Power execution, storage, inference,
  secrets, accounts, approvals, and the restricted Docker socket boundary;
- `pg/` provisions Team-scoped PostgreSQL principals and databases without exposing the superuser;
- `apps/` admits and operates deployed App containers through validated manifests and isolated networks;
- `egress/` provides audited Brain HTTP CONNECT egress; and
- `app-egress/` enforces per-App and per-Assistant destination policies.

Each service exposes named, bounded operations rather than a generic passthrough. Authentication,
tenant ownership, network membership, resource limits, schema validation, metadata-only audit, and
secret redaction fail closed at these boundaries. Hosted and local Team controllers share domain
modules while retaining their different authority and deployment contracts.

See [`team/LOCAL_CONTROLLER.md`](team/LOCAL_CONTROLLER.md) for the installed local controller and each
directory's tests for its executable contract.
