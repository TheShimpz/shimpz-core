"""Verify a Shimpz account session token against the `accounts` service.

This is how the team-driver scopes every op to the authenticated account (Team ownership). The
public store only FORWARDS the user's token (it holds no secret); THIS driver is the enforcer — it
verifies the token here and ties/authorizes Teams by the returned account_id. Stdlib only.

SELF-HOST PHONE-HOME: on shimpz.com's own Space this points at the internal `accounts` container; a
self-hosted Space instead sets SHIMPZ_ACCOUNTS_URL=https://shimpz.com/api/accounts — the SAME verify
call then validates the account against shimpz.com (the store's public passthrough), which is what
makes a marketplace install on a self-hosted Space require a real Shimpz account.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import threading
import time
from collections import OrderedDict, defaultdict
from contextlib import suppress
from urllib.parse import urlparse

ACCOUNTS_URL = os.environ.get("SHIMPZ_ACCOUNTS_URL", "http://accounts:7079")
VERIFY_TIMEOUT_SECONDS = 10
VERIFY_CACHE_TTL_SECONDS = 60
VERIFY_CACHE_MAX_ENTRIES = 1024
VERIFY_POOL_MAX_IDLE = 16
_verification_cache: OrderedDict[bytes, tuple[float, str]] = OrderedDict()
_verification_cache_lock = threading.Lock()
_connection_pool: defaultdict[tuple[object, str, int, float], list[http.client.HTTPConnection]] = defaultdict(list)
_connection_pool_lock = threading.Lock()


def _cached_verification(token_digest: bytes, now: float) -> str | None:
    with _verification_cache_lock:
        cached = _verification_cache.get(token_digest)
        if cached is None:
            return None
        expires_at, account_id = cached
        if expires_at <= now:
            _verification_cache.pop(token_digest, None)
            return None
        _verification_cache.move_to_end(token_digest)
        return account_id


def _cache_verification(token_digest: bytes, account_id: str, now: float) -> None:
    with _verification_cache_lock:
        _verification_cache[token_digest] = (now + VERIFY_CACHE_TTL_SECONDS, account_id)
        _verification_cache.move_to_end(token_digest)
        while len(_verification_cache) > VERIFY_CACHE_MAX_ENTRIES:
            _verification_cache.popitem(last=False)


def _acquire_connection(
    conn_cls,
    host: str,
    port: int,
) -> tuple[tuple[object, str, int, float], http.client.HTTPConnection]:
    key = (conn_cls, host, port, VERIFY_TIMEOUT_SECONDS)
    with _connection_pool_lock:
        idle = _connection_pool.get(key)
        if idle:
            return key, idle.pop()
    return key, conn_cls(host, port, timeout=VERIFY_TIMEOUT_SECONDS)


def _release_connection(
    key: tuple[object, str, int, float],
    connection: http.client.HTTPConnection,
) -> None:
    with _connection_pool_lock:
        idle = _connection_pool[key]
        if len(idle) < VERIFY_POOL_MAX_IDLE:
            idle.append(connection)
            return
    with suppress(OSError):
        connection.close()


def _discard_connection(connection: http.client.HTTPConnection) -> None:
    with suppress(OSError):
        connection.close()


def _reset_state() -> None:
    """Clear process caches for import-isolated contract tests."""
    with _verification_cache_lock:
        _verification_cache.clear()
    with _connection_pool_lock:
        connections = [connection for idle in _connection_pool.values() for connection in idle]
        _connection_pool.clear()
    for connection in connections:
        _discard_connection(connection)


def _remote_verification(token: str) -> str | None:
    key = None
    conn = None
    reusable = False
    try:
        parsed = urlparse(ACCOUNTS_URL)
        https = parsed.scheme == "https"
        conn_cls = http.client.HTTPSConnection if https else http.client.HTTPConnection
        host = parsed.hostname
        if host is None:
            return None
        port = parsed.port or (443 if https else 7079)
        path = f"{parsed.path.rstrip('/')}/v1/verify"
        key, conn = _acquire_connection(conn_cls, host, port)
        conn.request("POST", path, json.dumps({"token": token}), {"Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read()
        reusable = True
        data = json.loads(raw or b"{}")
    except OSError, ValueError, http.client.HTTPException:
        return None
    finally:
        if reusable and key is not None and conn is not None:
            _release_connection(key, conn)
        elif conn is not None:
            _discard_connection(conn)
    if resp.status != 200 or not isinstance(data, dict):
        return None
    account_id = data.get("account_id")
    return account_id if isinstance(account_id, str) and account_id else None


def verify(token: str) -> str | None:
    """Return the account_id for a valid token, else None. NEVER raises — accounts down → None → deny."""
    if not isinstance(token, str) or not token:
        return None
    token_digest = hashlib.sha256(token.encode("utf-8")).digest()
    now = time.monotonic()
    cached = _cached_verification(token_digest, now)
    if cached is not None:
        return cached
    account_id = _remote_verification(token)
    if account_id is not None:
        _cache_verification(token_digest, account_id, now)
    return account_id
