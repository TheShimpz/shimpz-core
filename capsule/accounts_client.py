"""Verify a Shimpz account session token against the `accounts` service.

This is how the capsule-driver scopes every op to the authenticated account (Capsule ownership). The
public store only FORWARDS the user's token (it holds no secret); THIS driver is the enforcer — it
verifies the token here and ties/authorizes Capsules by the returned account_id. Stdlib only.

SELF-HOST PHONE-HOME: on shimpz.com's own Space this points at the internal `accounts` container; a
self-hosted Space instead sets SHIMPZ_ACCOUNTS_URL=https://shimpz.com/api/accounts — the SAME verify
call then validates the account against shimpz.com (the store's public passthrough), which is what
makes a marketplace install on a self-hosted Space require a real Shimpz account.
"""

from __future__ import annotations

import http.client
import json
import os
from urllib.parse import urlparse

ACCOUNTS_URL = os.environ.get("SHIMPZ_ACCOUNTS_URL", "http://accounts:7079")


def verify(token: str) -> str | None:
    """Return the account_id for a valid token, else None. NEVER raises — accounts down → None → deny."""
    if not token:
        return None
    parsed = urlparse(ACCOUNTS_URL)
    https = parsed.scheme == "https"
    conn_cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
    path = f"{parsed.path.rstrip('/')}/v1/verify"
    try:
        conn = conn_cls(parsed.hostname, parsed.port or (443 if https else 7079), timeout=10)
        conn.request("POST", path, json.dumps({"token": token}), {"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
    except OSError, json.JSONDecodeError:
        return None
    return data.get("account_id") if resp.status == 200 else None
