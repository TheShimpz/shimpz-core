#!/usr/local/bin/python3
"""egress-proxy — the ONLY internet route for the `shimpz-brain` brain (SECURITY_ENGINEERING_PLAN.md item 8).

The brain is off the `edge` bridge; its ONLY egress is `HTTPS_PROXY=http://egress-proxy:8888`, reached
over the 2-member internal `egress_net`. Two things this ALWAYS gives, regardless of the allowlist:
the internal datastores stay unreachable (this proxy has no route to postgres/redpanda), and EVERY
outbound destination is audited (the full egress trail — how the Meta-Ads breakage was found in seconds).
`SHIMPZ_EGRESS_ALLOW` picks the posture: `*` (the default) = BROAD+AUDIT — forward any host, audit all — the
right fit for a GENERAL agent that reaches whatever host a task needs; a comma-list = a tight allowlist
(only those hosts, :443 only) for a narrow-purpose deployment. See `permitted()`.

Design (deliberately minimal — no bearer, no TLS termination):
  * network-gated, not token-gated: only `shimpz-brain` shares `egress_net`, same doctrine as the per-pair
    driver nets. `egress_out` (single-member) is the sidecar's own route to the internet.
  * CONNECT-only: a plain-HTTP forward request is refused (405) so `http://` exfil is impossible; the
    tunnel is opaque TLS end-to-end (no CA injection, the proxy never sees plaintext).
  * allowlist by HOSTNAME (the proxy resolves the name), so it survives Anthropic/Telegram CDN-IP
    rotation, and the brain — having no default route — cannot even resolve external names itself
    (DNS-tunnel exfil is closed for free).
  * fail-closed: if this process is down, the brain reaches nothing external.
"""

from __future__ import annotations

import contextlib
import os
import select
import socket
import socketserver
import sys

import audit

LISTEN_PORT = int(os.environ.get("SHIMPZ_EGRESS_PORT", "8888"))
ALLOW = [h.strip().lower().rstrip(".") for h in os.environ.get("SHIMPZ_EGRESS_ALLOW", "").split(",") if h.strip()]
ALLOWED_PORTS = {443}  # HTTPS only — every legitimate brain destination is TLS
CONNECT_TIMEOUT = 15
IDLE_TIMEOUT = 300  # tear down a tunnel idle this long
BUFSIZE = 65536
_STATUS = {
    200: "Connection established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    502: "Bad Gateway",
}


def permitted(host: str, port: int) -> bool:
    """Whether to forward a CONNECT to host:port.

    `*` in the allowlist = BROAD+AUDIT mode: forward ANY host on ANY port. This is the right posture for
    a GENERAL agent — the brain reaches whatever host a task needs (Meta/Google/any API). It is NOT
    "no security": the internal datastores stay unreachable regardless (the brain is off `edge` and this
    proxy has no route to postgres/redpanda), and EVERY CONNECT is still audited — the full egress trail.

    Otherwise ALLOWLIST mode: only the listed hosts, and only on :443. A `.suffix` entry matches the apex
    + any subdomain (`.anthropic.com` → `anthropic.com`, `api.anthropic.com`); a bare entry matches exactly.
    """
    if "*" in ALLOW:
        return True
    if port not in ALLOWED_PORTS:
        return False
    host = host.lower().rstrip(".")
    for entry in ALLOW:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        cli = self.request
        cli.settimeout(CONNECT_TIMEOUT)
        probe = self.client_address[0] == "127.0.0.1"  # the Docker HEALTHCHECK (a deliberate denied CONNECT)
        header = self._read_request_line(cli)
        if header is None:
            return
        parts = header.split(" ")
        if len(parts) < 2 or parts[0] != "CONNECT":
            self._reply(cli, 405)
            audit.log("connect", header[:80], result="denied", level="info" if probe else "warn", code=405)
            return
        host, port = self._split_target(parts[1])
        if host is None:
            self._reply(cli, 400)
            audit.log("connect", parts[1][:80], result="denied", level="info" if probe else "warn", code=400)
            return
        if not permitted(host, port):
            self._reply(cli, 403)
            src = {"source": "loopback-probe"} if probe else {}
            audit.log("connect", f"{host}:{port}", result="denied", level="info" if probe else "warn", code=403, **src)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as exc:
            self._reply(cli, 502)
            audit.log("connect", f"{host}:{port}", result="error", reason=str(exc))
            return
        audit.log("connect", f"{host}:{port}", result="ok")
        self._reply(cli, 200)
        self._tunnel(cli, upstream)

    @staticmethod
    def _read_request_line(sock: socket.socket) -> str | None:
        """Read up to the end of the CONNECT request headers; return the request line (or None)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(4096)
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
            if len(buf) > BUFSIZE:  # a well-formed CONNECT is tiny; anything huge is junk
                return None
        return buf.split(b"\r\n", 1)[0].decode("latin1", "replace")

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
            cli.sendall(f"HTTP/1.1 {code} {_STATUS[code]}\r\n\r\n".encode())

    @staticmethod
    def _tunnel(a: socket.socket, b: socket.socket) -> None:
        """Splice bytes both ways until either side closes or the tunnel goes idle."""
        for s in (a, b):
            s.settimeout(None)
        try:
            while True:
                readable, _, errored = select.select([a, b], [], [a, b], IDLE_TIMEOUT)
                if errored or not readable:  # socket error, or idle past IDLE_TIMEOUT
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
    if not ALLOW:
        # An empty allowlist would deny everything and silently break the brain — refuse to start
        # so the misconfiguration is loud, not a mysterious total outage. (fail-fast doctrine.)
        print("egress-proxy: SHIMPZ_EGRESS_ALLOW is empty — refusing to start", file=sys.stderr)
        sys.exit(1)
    server = Server(("0.0.0.0", LISTEN_PORT), Handler)  # noqa: S104 — egress_net-only by design (2-member internal)
    print(f"egress-proxy listening on :{LISTEN_PORT}; allow={ALLOW}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
