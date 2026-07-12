#!/usr/local/bin/python3
"""r2-driver — the ONLY container that holds the Cloudflare R2 credentials (RCLONE_CONFIG_R2_*).

SECURITY_ENGINEERING_PLAN.md item 7: `shimpz-brain` (the brain) never sees the R2 secret; it calls this
restricted, allowlisted, audited HTTP API instead. Every endpoint is one SPECIFIC operation with a
fixed request shape (validate.py) — never a generic "run rclone" passthrough. Before this split a
prompt-injected brain could `rclone delete` the whole bucket or exfiltrate the access key; now it can
only ever ask for one of: upload one file (get a presigned link), list a prefix, download one object.

Mandatory controls (same contract as the other sidecars):
  - Auth fail-closed on EVERY endpoint: `Authorization: Bearer <token>` required; no anonymous route.
  - No CORS, ever: this API is for `shimpz-brain`'s own r2send/r2ls/r2get wrappers, never a page in Chrome.
  - No execution endpoint: r2_client.py shells rclone with a FIXED argv (never a shell string), so a
    bucket key can't inject a command. There is no "arbitrary rclone" endpoint by design.
  - Redacted audit: only keys/prefixes/sizes — never file bytes, never the presigned link itself
    (a live download credential), never the R2 secret.

Streaming both directions (no base64, no shared volume): the upload body IS the raw file bytes; the
download response IS the raw file bytes — neither is ever fully buffered in memory, so a multi-GB R2
object (the whole reason R2 exists over kclient) transfers with bounded memory.

Endpoints (all require `Authorization: Bearer <token>`):
  POST /v1/r2/upload   body=<raw bytes>  headers: X-R2-Filename, X-R2-Expire? -> {key, link, size}
  GET  /v1/r2/list     ?prefix=<prefix>  -> {prefix, entries: [{size, modtime, path}, ...]}
  GET  /v1/r2/get      ?key=<key>        -> <raw bytes>  (X-R2-Size header)
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import audit
import r2_client
import token_store
import validate

LISTEN_PORT = int(os.environ.get("SHIMPZ_R2DRIVER_PORT", "7075"))
_CHUNK = 1024 * 1024

_token = token_store.ensure_token()


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _date_key(filename: str) -> str:
    return f"uploads/{time.strftime('%Y/%m/%d', time.gmtime())}/{filename}"


class Handler(BaseHTTPRequestHandler):
    server_version = "r2-driver/1.0"

    def _authed(self) -> bool:
        return self.headers.get("Authorization", "") == f"Bearer {_token}"

    def _send_json(self, status: HTTPStatus, payload: object) -> None:
        import json

        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # NEVER an Access-Control-Allow-Origin header — this API is not browser-callable.
        self.end_headers()
        self.wfile.write(body)

    def _stream_body_to(self, dest: Path) -> int:
        """Stream the raw request body to `dest` in bounded chunks, enforcing the upload cap."""
        remaining = int(self.headers.get("Content-Length", "0") or "0")
        validate.validate_upload_size(remaining)
        written = 0
        with dest.open("wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(_CHUNK, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                written += len(chunk)
                remaining -= len(chunk)
        if written == 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "empty upload body")
        return written

    def _dispatch(self, method: str) -> None:
        if not self._authed():
            # 127.0.0.1 = this container's own Docker HEALTHCHECK proving the 403 gate is live
            # (an unauthenticated probe every 30s BY DESIGN) — keep the audit line but at info,
            # so warn/error carries only real denials, never a heartbeat.
            if self.client_address[0] == "127.0.0.1":
                audit.log("auth", self.path, result="denied", level="info", source="loopback-probe")
            else:
                audit.log("auth", self.path, result="denied")
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid or missing bearer token"})
            return
        try:
            self._route(method)
        except ApiError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=exc.message)
            self._send_json(exc.status, {"error": exc.message})
        except validate.ValidationError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=str(exc))
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except r2_client.R2NotFoundError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=str(exc))
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except r2_client.R2Error as exc:
            audit.log(method.lower(), self.path, result="error", reason=str(exc))
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 — top-level HTTP handler: log + surface, never crash the server, NEVER treat as success
            audit.log(method.lower(), self.path, result="error", reason=str(exc))
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _route(self, method: str) -> None:
        split = urlsplit(self.path)
        path, query = split.path, parse_qs(split.query)

        if method == "POST" and path == "/v1/r2/upload":
            self._upload()
            return
        if method == "GET" and path == "/v1/r2/list":
            prefix = validate.validate_prefix((query.get("prefix") or [""])[0])
            entries = r2_client.list_prefix(prefix)
            trace = audit.log("r2.list", prefix or "<root>", result="ok", count=len(entries))
            self._send_json(HTTPStatus.OK, {"prefix": prefix, "entries": entries, "trace_id": trace})
            return
        if method == "GET" and path == "/v1/r2/get":
            self._get(validate.validate_key((query.get("key") or [""])[0]))
            return
        raise ApiError(HTTPStatus.NOT_FOUND, f"no route for {method} {path}")

    def _upload(self) -> None:
        filename = validate.validate_filename(self.headers.get("X-R2-Filename"))
        expire = validate.validate_expire(self.headers.get("X-R2-Expire"))
        key = _date_key(filename)
        fd, tmp_str = tempfile.mkstemp(prefix="r2up-", dir="/tmp")
        tmp = Path(tmp_str)
        os.close(fd)
        try:
            size = self._stream_body_to(tmp)
            r2_client.upload(str(tmp), key)
            url = r2_client.link(key, expire)
        finally:
            tmp.unlink(missing_ok=True)
        trace = audit.log("r2.upload", key, result="ok", size=size)
        self._send_json(HTTPStatus.OK, {"key": key, "link": url, "size": size, "trace_id": trace})

    def _get(self, key: str) -> None:
        fd, tmp_str = tempfile.mkstemp(prefix="r2dl-", dir="/tmp")
        tmp = Path(tmp_str)
        os.close(fd)
        try:
            size = r2_client.download(key, str(tmp))
            validate.validate_download_size(size)
            audit.log("r2.get", key, result="ok", size=size)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("X-R2-Size", str(size))
            self.end_headers()
            with tmp.open("rb") as fh:
                while chunk := fh.read(_CHUNK):
                    self.wfile.write(chunk)
        finally:
            tmp.unlink(missing_ok=True)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: object) -> None:
        # Suppress BaseHTTPRequestHandler's default stderr access log — audit.log() is the single
        # source of truth for what happened, in the schema logq expects.
        pass


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)  # noqa: S104 — r2driver_net-only by design
    print(f"r2-driver listening on :{LISTEN_PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
