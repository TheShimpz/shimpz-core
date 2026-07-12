#!/usr/local/bin/python3
"""app-egress-proxy — the ONLY internet route for DEPLOYED APPS (Shimpz L2, deny-by-default egress).

Every app container is on an `internal:true` network (no NAT to the internet). Its ONLY egress is
`HTTPS_PROXY=http://<app-egress-token>@app-egress-proxy:8889`, reached over an internal proxy network.
Unlike the brain's single-tenant egress-proxy (one global allowlist, network-gated), this proxy serves
MANY apps, so it is PER-APP TOKEN-GATED: each app carries its own token (issued by shimpz-driver at
deploy) and the proxy forwards a CONNECT only to the hosts THAT app declared in `[needs].egress` (plus
`pay.shimpz.com` iff the app is paid — its `effective_egress`). The driver writes each app's
allowlist to the policy dir as `<token>.json`.

Deny-by-default and fail-closed: an unknown token, an app that declared no egress, an unlisted host, a
non-:443 port, or this process being down all mean the app reaches NOTHING external. Same CONNECT-only,
opaque-TLS, hostname-allowlist design as the brain proxy (no CA injection, no plaintext seen, DNS-tunnel
exfil closed because the app has no default route and can't resolve external names itself).
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import select
import socket
import socketserver
import sys
from pathlib import Path

import audit

LISTEN_PORT = int(os.environ.get("SHIMPZ_APP_EGRESS_PORT", "8889"))
POLICY_DIR = Path(os.environ.get("SHIMPZ_APP_EGRESS_POLICY_DIR", "/policy"))
ALLOWED_PORTS = {443}  # HTTPS only — every legitimate app destination is TLS
CONNECT_TIMEOUT = 15
IDLE_TIMEOUT = 300
BUFSIZE = 65536
_STATUS = {
    200: "Connection established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    407: "Proxy Authentication Required",
    502: "Bad Gateway",
}


def load_policy(policy_dir: Path) -> dict[str, frozenset[str]]:
    """Read the per-app allowlists the driver wrote: `<token>.json` = a JSON list of hostnames.

    Returns {token: frozenset(lowercased hosts)}. A missing dir → {} (deny everything — fail-closed). An
    unreadable/garbage file is SKIPPED (that app gets no egress) rather than crashing the proxy for others.
    """
    policy: dict[str, frozenset[str]] = {}
    if not policy_dir.is_dir():
        return policy
    for f in policy_dir.glob("*.json"):
        token = f.stem
        try:
            hosts = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # a bad policy file denies that app's egress — never opens another's
        if isinstance(hosts, list) and all(isinstance(h, str) for h in hosts):
            policy[token] = frozenset(h.lower().rstrip(".") for h in hosts)
    return policy


def permitted(token: str, host: str, port: int, policy: dict[str, frozenset[str]]) -> bool:
    """Forward a CONNECT to host:port iff the app (identified by `token`) declared exactly this host.

    Deny-by-default: unknown/empty token, an app with no allowlist, an unlisted host, or a non-:443 port
    all return False. `effective_egress` entries are EXACT hostnames, so this is an exact match (no wildcard
    — an app lists every host it needs); this is the enforcement kernel of the ShimpzPay/egress lock.
    """
    if port not in ALLOWED_PORTS:
        return False
    allow = policy.get(token)
    if not allow:
        return False
    return host.lower().rstrip(".") in allow


def extract_token(headers: str) -> str | None:
    """Pull the per-app token out of a `Proxy-Authorization: Basic base64(token:)` header (or None).

    The app's HTTPS_PROXY is `http://<token>@app-egress-proxy:8889`, so clients send Basic proxy auth
    with the token as the username. We take the username half; a missing/garbled header → None (→ 407).
    """
    for line in headers.split("\r\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "proxy-authorization":
            scheme, _, creds = value.strip().partition(" ")
            if scheme.lower() != "basic":
                return None
            try:
                decoded = base64.b64decode(creds, validate=True).decode("latin1")
            except (ValueError, UnicodeDecodeError):
                return None
            return decoded.split(":", 1)[0] or None
    return None


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        cli = self.request
        cli.settimeout(CONNECT_TIMEOUT)
        probe = self.client_address[0] == "127.0.0.1"  # the Docker HEALTHCHECK (a deliberate denied CONNECT)
        headers = self._read_request(cli)
        if headers is None:
            return
        request_line = headers.split("\r\n", 1)[0]
        parts = request_line.split(" ")
        if len(parts) < 2 or parts[0] != "CONNECT":
            self._reply(cli, 405)
            audit.log("connect", request_line[:80], result="denied", level="info" if probe else "warn", code=405)
            return
        host, port = self._split_target(parts[1])
        if host is None:
            self._reply(cli, 400)
            audit.log("connect", parts[1][:80], result="denied", level="info" if probe else "warn", code=400)
            return
        token = extract_token(headers)
        if token is None:
            self._reply(cli, 407)
            audit.log("connect", f"{host}:{port}", result="denied", level="info" if probe else "warn", code=407)
            return
        if not permitted(token, host, port, load_policy(POLICY_DIR)):
            self._reply(cli, 403)
            audit.log("connect", f"{host}:{port}", result="denied", level="warn", code=403, app=token[:12])
            return
        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as exc:
            self._reply(cli, 502)
            audit.log("connect", f"{host}:{port}", result="error", reason=str(exc), app=token[:12])
            return
        audit.log("connect", f"{host}:{port}", result="ok", app=token[:12])
        self._reply(cli, 200)
        self._tunnel(cli, upstream)

    @staticmethod
    def _read_request(sock: socket.socket) -> str | None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
            if len(buf) > BUFSIZE:
                return None
        return buf.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")

    @staticmethod
    def _split_target(target: str) -> tuple[str | None, int]:
        host, sep, port_s = target.rpartition(":")
        if not sep:
            return target or None, 443
        try:
            return (host or None), int(port_s)
        except ValueError:
            return None, 0

    def _reply(self, cli: socket.socket, code: int) -> None:
        with contextlib.suppress(OSError):
            extra = 'Proxy-Authenticate: Basic realm="app-egress"\r\n' if code == 407 else ""
            cli.sendall(f"HTTP/1.1 {code} {_STATUS[code]}\r\n{extra}\r\n".encode())

    @staticmethod
    def _tunnel(a: socket.socket, b: socket.socket) -> None:
        for s in (a, b):
            s.settimeout(None)
        try:
            while True:
                readable, _, errored = select.select([a, b], [], [a, b], IDLE_TIMEOUT)
                if errored or not readable:
                    return
                for src in readable:
                    data = src.recv(BUFSIZE)
                    if not data:
                        return
                    (b if src is a else a).sendall(data)
        except OSError:
            return
        finally:
            for s in (a, b):
                with contextlib.suppress(OSError):
                    s.shutdown(socket.SHUT_RDWR)
                s.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    server = Server(("0.0.0.0", LISTEN_PORT), Handler)  # noqa: S104 — proxy-net-only by design (internal)
    print(f"app-egress-proxy listening on :{LISTEN_PORT}; policy_dir={POLICY_DIR}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
