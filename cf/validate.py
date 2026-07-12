"""Allowlist validation for cf-driver's endpoints — runs BEFORE any Cloudflare API call.

Nothing here talks to Cloudflare; it only decides yes/no and returns validated, structured
values the caller (app.py) passes to cf_client.py. This is the actual security boundary
described in SECURITY_ENGINEERING_PLAN.md item 3: even a fully compromised `shimpz-brain` can only
ever request one of the narrow, named operations this module allows — never an arbitrary
Cloudflare API method+path the way the old `cf` helper permitted.
"""

from __future__ import annotations

import re

FQDN_RE = re.compile(r"^[A-Za-z0-9.-]+$")
DNS_RECORD_TYPES = frozenset({"CNAME", "A", "AAAA"})
SCOPES = frozenset({"public", "private"})


class ValidationError(Exception):
    """A request failed the allowlist — nothing was touched."""


def validate_fqdn(fqdn: object) -> str:
    if not isinstance(fqdn, str) or not fqdn or not FQDN_RE.match(fqdn):
        raise ValidationError(f"fqdn must match {FQDN_RE.pattern!r}: {fqdn!r}")
    return fqdn


def validate_hostname_service(service: object) -> str:
    """The tunnel ingress target for one hostname — always `http://<container>:<port>`.

    Never a raw passthrough of whatever string shimpz-brain supplies: this is the ONE shape every
    real ingress rule this driver has ever written actually needs (shimpz-caddy on its
    fixed port, or `http_status:404` for teardown), so anything else is refused rather than
    silently accepted as a routing rule to who-knows-where.
    """
    if not isinstance(service, str) or not re.match(r"^http://[A-Za-z0-9_.-]+:\d+$", service):
        raise ValidationError(f"service must be 'http://<host>:<port>': {service!r}")
    return service


def validate_dns_type(record_type: object) -> str:
    if record_type not in DNS_RECORD_TYPES:
        raise ValidationError(f"type must be one of {sorted(DNS_RECORD_TYPES)}: {record_type!r}")
    return record_type


def validate_scope(scope: object) -> str:
    if scope not in SCOPES:
        raise ValidationError(f"scope must be one of {sorted(SCOPES)}: {scope!r}")
    return scope


def validate_email(email: object) -> str:
    if not isinstance(email, str) or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValidationError(f"owner_email must look like an email address: {email!r}")
    return email


def validate_access_app_body(body: object) -> dict:
    """The shape of a restorable Access app — used ONLY by the rollback `restore` endpoint.

    `body` here is always something THIS driver itself returned from an earlier
    GET/list call (a snapshot shimpz-publish is handing back verbatim to undo a delete) — this
    validates it still LOOKS like a real Access app definition, not an arbitrary object,
    before ever forwarding it to Cloudflare's create endpoint.
    """
    if not isinstance(body, dict):
        raise ValidationError("app must be an object")
    if not isinstance(body.get("domain"), str) or not body["domain"]:
        raise ValidationError("app.domain must be a non-empty string")
    if body.get("type") != "self_hosted":
        raise ValidationError(f"app.type must be 'self_hosted': {body.get('type')!r}")
    if not isinstance(body.get("policies"), list) or not body["policies"]:
        raise ValidationError("app.policies must be a non-empty list")
    return {
        "name": body.get("name", f"Shimpz {body['domain']}"),
        "domain": body["domain"],
        "type": "self_hosted",
        "session_duration": body.get("session_duration", "24h"),
        "policies": body["policies"],
    }


def longest_matching_zone(fqdn: str, zones: list[dict]) -> tuple[str, str] | None:
    """The longest Cloudflare zone name that is a suffix of `fqdn` (handles .com.br etc.).

    Pure port of shimpzdetect.sh's `_zone_for` — same algorithm, same tie-break (longest zone
    name wins), so a project migrating from the old `cf`-based flow sees identical zone
    resolution. Returns (zone_name, zone_id) or None if nothing matches.
    """
    best_name, best_id = "", None
    for zone in zones:
        name, zid = zone.get("name", ""), zone.get("id", "")
        if (fqdn == name or fqdn.endswith(f".{name}")) and len(name) > len(best_name):
            best_name, best_id = name, zid
    return (best_name, best_id) if best_id else None
