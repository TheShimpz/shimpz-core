# Shimpz Developers-to-Controller contract v1

This directory is the language-neutral authority for the narrow boundary
between Developers and the hosted Team Controller.

It covers:

- EdDSA JWS delegation claims for Team listing and Assistant installation;
- the authorized Team list;
- immutable dynamic Assistant resolution;
- the hosted Controller install request and result; and
- the final, context-bound install authorization request and receipt.

Every authoritative object is closed. Unknown fields fail validation. The
schemas use JSON Schema draft 2020-12 and share definitions through
`definitions.schema.json`; each operation has a small standalone entry-point
schema.

## Security boundary

The JWT wire fields `iss` and `aud` retain their standard interoperable names.
Product code should expose them as `issuer` and `audience` and construct claims
through operation-specific helpers. Their values are fixed:

```text
issuer:   https://developers.shimpz.com
audience: https://developers.shimpz.com/team-controller
```

A delegation is valid for at most 60 seconds. An install authorization is valid
for at most 120 seconds. JSON Schema validates their shape; the reference
verifier and every consumer also enforce these lifetime relationships.

The Controller install JSON is never authority by itself. The internal request
must also carry the named Developers service credential and the compact
delegation JWS. The claims and body must bind the same account, Team, source
digest, request ID, and idempotency key before the Controller invokes its
existing ownership authorization.

Resolve returns only an unblocked, installable publication. It contains a full
digest image reference and the complete `assistant-direct-v1` envelope. Modes
are JSON integers: `365` is octal `0555`, and `292` is octal `0444`. No port,
health endpoint, authored server, mutable image, capability, or alternative
runtime setting is admitted.

Signature and DSSE provenance bundles are not embedded. Resolve supplies
immutable references under
`ghcr.io/theshimpz/shimpz-assistant-trust` and the signer identity. The
Controller fetches both trust artifacts and verifies them with Cosign against
the full executable image digest. Missing, unavailable, invalid, or
inconsistent trust material fails closed.

## Golden vectors

`vectors.json` contains reusable fixtures and positive and negative cases for
every entry point. A case may apply one deterministic mutation:

- `set` creates or replaces an object property;
- `remove` removes an existing object property; and
- `path` is a non-empty array of object-property names.

This small mutation format keeps security-sensitive resolve vectors readable
without making consumers implement a general patch language.

Validate the frozen authority and every vector from the umbrella root:

```console
python contracts/developers-controller/v1/verify.py
```

Synchronize the already-verified authority into an empty or previously
synchronized consumer directory:

```console
python contracts/developers-controller/v1/verify.py \
  --sync ../consumer/contracts/developers-controller/v1
```

The sync rejects symlinks, special files, and unknown destination entries.
Consumers record the producing umbrella commit and verify
`contract-files.sha256` before running their independent implementation against
the unchanged vectors.
