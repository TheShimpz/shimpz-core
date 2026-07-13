"""capsule-driver — a socket-holding sidecar dedicated to Capsule lifecycle.

Besides shimpz-driver, this is the ONLY container holding /var/run/docker.sock — and it exposes ONLY
named operations (create/list/status/logs/stop/start/restart/destroy), never a generic Docker
passthrough. A Capsule is one isolated `shimpz-brain`: its OWN internal network, its OWN config+workspace
volumes, and a SCOPED Postgres database (provisioned via pg-driver — this driver never holds the
superuser). Every mutating call is bearer-gated → validated → mutated → audited (trace_id returned).
A compromised caller can only ever request what validate.py permits.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import os
import secrets
import threading
import time
from collections import defaultdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import accounts_client
import audit
import docker
import docker.errors
import manifests
import marketplace
import pgdriver_client
import token_store
import validate

LISTEN_PORT = int(os.environ.get("SHIMPZ_CAPSULEDRIVER_PORT", "7077"))
# Hard ceiling on live capsules per Space — a runaway/hostile caller can't exhaust host RAM/disk/IPs.
MAX_CAPSULES = int(os.environ.get("SHIMPZ_MAX_CAPSULES", "200"))
# Per-capsule app allowance — an owner can't exhaust the host by installing without bound either.
MAX_APPS_PER_CAPSULE = int(os.environ.get("SHIMPZ_MAX_APPS_PER_CAPSULE", "20"))
# Same volume app-egress-proxy reads (<token>.json allowlists) — shared with shimpz-driver by design:
# ONE proxy serves every token-gated app, capsule-scoped or not, each confined to its own hosts.
APP_EGRESS_POLICY_DIR = Path(os.environ.get("SHIMPZ_APP_EGRESS_POLICY_DIR", "/app-egress-policy"))
HEALTH_RETRIES = int(os.environ.get("SHIMPZ_HEALTH_RETRIES", "40"))
HEALTH_DELAY_SECONDS = float(os.environ.get("SHIMPZ_HEALTH_DELAY_SECONDS", "1.5"))

_docker = docker.from_env()
_token = token_store.ensure_token()

# Per-capsule lock: create/destroy of the SAME capsule must serialize; different capsules run parallel.
_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)


def _lock_for(cid: str) -> threading.Lock:
    with _locks_guard:
        return _locks[cid]


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


# ── docker helpers ───────────────────────────────────────────────────────────
def _get_container(name: str):
    try:
        return _docker.containers.get(name)
    except docker.errors.NotFound:
        return None


def _ensure_volume(name: str) -> None:
    try:
        _docker.volumes.get(name)
    except docker.errors.NotFound:
        _docker.volumes.create(name=name)


def _ensure_capsule_network(cid: str):
    net_name = manifests.capsule_network_name(cid)
    try:
        return _docker.networks.get(net_name)
    except docker.errors.NotFound:
        # internal=True: the capsule has NO NAT of its own — its only route out is egress-proxy.
        return _docker.networks.create(net_name, driver="bridge", internal=True)


def _already_connected(exc: docker.errors.APIError) -> bool:
    """True only for the ONE idempotent case: this container is already on this network (403)."""
    resp = exc.response
    return (
        resp is not None
        and resp.status_code == HTTPStatus.FORBIDDEN
        and "already exists in network" in (exc.explanation or "")
    )


def _safe_connect(network, container_name: str, *, aliases: list[str] | None = None, required: bool) -> None:
    try:
        container = _docker.containers.get(container_name)
    except docker.errors.NotFound as exc:
        if required:
            raise ApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR, f"required shared-plane container {container_name!r} not found"
            ) from exc
        return
    try:
        network.connect(container, aliases=aliases)
    except docker.errors.APIError as exc:
        if _already_connected(exc):
            return
        if required:
            raise ApiError(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                f"failed to connect {container_name!r} to the capsule network: {exc}",
            ) from exc


def _wire_capsule_deps(network) -> None:
    for container_name, aliases in manifests.shared_deps():
        _safe_connect(network, container_name, aliases=aliases, required=True)


def _teardown_capsule_network(cid: str) -> None:
    try:
        network = _docker.networks.get(manifests.capsule_network_name(cid))
    except docker.errors.NotFound:
        return
    network.reload()
    for container_id in network.attrs.get("Containers", {}):
        with contextlib.suppress(docker.errors.APIError):
            network.disconnect(container_id, force=True)
    with contextlib.suppress(docker.errors.APIError):
        network.remove()


def _describe(container) -> dict:
    return {
        "id": container.labels.get("capsule.id"),
        "name": container.labels.get("capsule.name"),
        "owner": container.labels.get("capsule.owner", ""),
        "brain": container.labels.get("capsule.brain", manifests.DEFAULT_BRAIN),
        "status": container.status,
        "container": container.name,
    }


def _owner_of(cid: str) -> str | None:
    """The account_id that owns capsule `cid`, or None if the capsule does not exist."""
    container = _get_container(manifests.capsule_container_name(cid))
    return container.labels.get("capsule.owner", "") if container is not None else None


def _authorize(cid: str, principal: tuple[str, str | None]) -> None:
    """Operator may touch any capsule; an account may only touch a capsule it owns.

    Raises 404 (not 403) for an account acting on someone else's / a missing capsule — an account must
    not even be able to tell whether another account's capsule exists.
    """
    kind, account_id = principal
    if kind == "operator":
        if _owner_of(cid) is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
        return
    if _owner_of(cid) != account_id:
        raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")


# ── installed apps (the P4 deploy arm) ───────────────────────────────────────
def _capsule_app_containers(cid: str) -> list:
    """Every installed-app container of capsule `cid` (its OWN label set — never `capsule.driver`)."""
    return _docker.containers.list(all=True, filters={"label": ["capsule.app.driver", f"capsule.id={cid}"]})


def _app_egress_token(cid: str, app_id: str) -> str:
    """The app instance's stable egress token (its Proxy-Authorization to app-egress-proxy).

    Kept in the policy volume (drivers + proxy only) and reused across reinstalls, exactly like
    shimpz-driver's per-app tokens — the proxy maps token → this instance's own allowlist.
    """
    tdir = APP_EGRESS_POLICY_DIR / ".tokens"
    tdir.mkdir(parents=True, exist_ok=True)
    tf = tdir / f"{manifests.capsule_app_container_name(cid, app_id)}.token"
    with contextlib.suppress(OSError):
        tok = tf.read_text(encoding="utf-8").strip()
        if tok:
            return tok
    tok = secrets.token_hex(16)
    tf.write_text(tok, encoding="utf-8")
    return tok


def _write_egress_policy(token: str, egress: tuple[str, ...]) -> None:
    APP_EGRESS_POLICY_DIR.mkdir(parents=True, exist_ok=True)
    (APP_EGRESS_POLICY_DIR / f"{token}.json").write_text(json.dumps(sorted(egress)), encoding="utf-8")


def _remove_egress_policy(cid: str, app_id: str) -> None:
    tf = APP_EGRESS_POLICY_DIR / ".tokens" / f"{manifests.capsule_app_container_name(cid, app_id)}.token"
    with contextlib.suppress(OSError):
        token = tf.read_text(encoding="utf-8").strip()
        if token:
            (APP_EGRESS_POLICY_DIR / f"{token}.json").unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        tf.unlink(missing_ok=True)


def _probe_app_health(container, port: int) -> bool:
    """One in-container HTTP probe of /api/health, /health, / (first non-404 wins; all-404 = alive).

    Tries curl, then a stdlib-python fallback — the packaging contract requires the image to ship one
    of the two. A connection failure or a 5xx is unhealthy; anything else answers, so the app is up.
    """
    script_tpl = (
        "import urllib.request,urllib.error\n"
        "try:\n"
        "    print(urllib.request.urlopen('http://127.0.0.1:{port}{path}', timeout=3).status)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
    )
    code = "000"
    for path in ("/api/health", "/health", "/"):
        probes = (
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "3",
                f"http://127.0.0.1:{port}{path}",
            ],
            ["python3", "-c", script_tpl.format(port=port, path=path)],
        )
        code = "000"
        for probe in probes:
            try:
                rc, out = container.exec_run(probe)
            except docker.errors.APIError:  # the binary isn't in this image — try the other one
                continue
            answer = out.decode(errors="replace").strip() if rc == 0 else "000"
            if answer.isdigit() and answer != "000":
                code = answer
                break
        if code != "000" and code != "404":
            return not code.startswith("5")
    return code == "404"  # every path 404s but the server answered — a bare API is still alive


def _wait_app_healthy(container, port: int) -> tuple[bool, str]:
    for attempt in range(HEALTH_RETRIES):
        container.reload()
        if container.status in ("exited", "dead"):
            return False, f"container not running (status={container.status})"
        if container.status == "running" and _probe_app_health(container, port):
            return True, "ok"
        if attempt < HEALTH_RETRIES - 1:
            time.sleep(HEALTH_DELAY_SECONDS)
    return False, "health probe never answered"


def _teardown_app(cid: str, app_id: str) -> bool:
    """Idempotently remove one installed app: container + scoped DB + egress policy. True = DB dropped."""
    container = _get_container(manifests.capsule_app_container_name(cid, app_id))
    if container is not None:
        with contextlib.suppress(docker.errors.APIError):
            container.remove(force=True)
    _remove_egress_policy(cid, app_id)
    try:
        pgdriver_client.drop_db(manifests.capsule_app_db_project(cid, app_id))
    except Exception:  # noqa: BLE001 — surfaced by the caller's audit line; teardown proceeds regardless
        return False
    return True


def _install_app(cid: str, app_id: str, spec: marketplace.AppSpec, owner: str) -> dict:
    with _lock_for(cid):
        capsule = _get_container(manifests.capsule_container_name(cid))
        if capsule is None:
            raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
        capsule_name = capsule.labels.get("capsule.name", "")
        existing = _get_container(manifests.capsule_app_container_name(cid, app_id))
        if existing is not None:  # idempotent: installing an installed app returns it, changes nothing
            return {"capsule": cid, "app": app_id, "status": existing.status, "installed": False}
        if len(_capsule_app_containers(cid)) >= MAX_APPS_PER_CAPSULE:
            raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, f"app limit reached for {cid!r} ({MAX_APPS_PER_CAPSULE})")
        # Transactional like _create: on ANY failure the app's own artifacts are rolled back (the
        # capsule itself is never touched) — no orphan DB, policy file, or half-started container.
        try:
            database_url = ""
            if spec.db:
                database_url = pgdriver_client.create_db(manifests.capsule_app_db_project(cid, app_id))["database_url"]
            network = _ensure_capsule_network(cid)
            proxy_env: dict[str, str] = {}
            if spec.egress:
                token = _app_egress_token(cid, app_id)
                _write_egress_policy(token, spec.egress)
                # The app must resolve the proxy INSIDE the capsule net; connecting the shared proxy
                # here mirrors _wire_capsule_deps (it refuses internal destinations, so no new L3 path).
                _safe_connect(network, manifests.APP_EGRESS_CONTAINER, aliases=["app-egress-proxy"], required=True)
                proxy_env = {
                    "HTTPS_PROXY": f"http://{token}@app-egress-proxy:8889",
                    "https_proxy": f"http://{token}@app-egress-proxy:8889",
                }
            kwargs = manifests.build_capsule_app_kwargs(
                cid,
                app_id,
                spec,
                database_url=database_url,
                proxy_env=proxy_env,
                owner=owner,
                capsule_name=capsule_name,
            )
            container = _docker.containers.create(**kwargs)
            # Re-attach with the app aliases (create can't set them): the capsule brain and sibling
            # apps reach it as http://<app-id>:<port>, and as http://<app-id>.capsule:<port> — the
            # `.capsule` form tail-matches the NO_PROXY suffix baked into every capsule container, so
            # proxied clients skip egress-proxy for it. Still the ONE capsule network, nothing else.
            network.disconnect(container)
            network.connect(container, aliases=[app_id, f"{app_id}.capsule"])
            container.start()
            healthy, reason = _wait_app_healthy(container, spec.port)
            if not healthy:
                log_tail = container.logs(tail=40).decode(errors="replace")
                raise ApiError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    f"app {app_id!r} failed its health probe ({reason}; rolled back): {log_tail[-800:]}",
                )
        except Exception as exc:
            _teardown_app(cid, app_id)
            if isinstance(exc, ApiError):
                raise
            raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, f"app install failed (rolled back): {exc}") from exc
        return {
            "capsule": cid,
            "app": app_id,
            "status": "running",
            "installed": True,
            **({"database": manifests.capsule_app_db_project(cid, app_id)} if spec.db else {}),
        }


def _uninstall_app(cid: str, app_id: str) -> dict:
    with _lock_for(cid):
        dropped = _teardown_app(cid, app_id)
        return {"capsule": cid, "app": app_id, "uninstalled": True, "db_dropped": dropped}


def _list_apps(cid: str) -> dict:
    apps = [
        {
            "app": c.labels.get("capsule.app"),
            "status": c.status,
            "container": c.name,
        }
        for c in _capsule_app_containers(cid)
    ]
    return {"capsule": cid, "apps": apps}


# ── the Captain's chat (ADR-0004): named exec ops into the capsule's OWN brain ──────────────────
# No new network path — the store forwards, ownership is enforced here, and the brain is reached the
# same way an operator would reach it: an exec, as the runtime user, inside that capsule only.
CHAT_TIMEOUT_SECONDS = int(os.environ.get("SHIMPZ_CAPSULE_CHAT_TIMEOUT", "170"))
CHAT_OUTPUT_CAP = 60000
INBOX_DIR = "/config/workspace/inbox"
MAX_INBOX_FILE_BYTES = 30 * 1024 * 1024  # the store caps uploads well below Cloudflare's 100 MB
_BRAIN_USER = "abc"  # the brain image's runtime user (uid 1000) — holds the claude credentials
_AUTH_MARKERS = ("please run /login", "not logged in", "invalid api key", "credentials", "please log in", "oauth")


def _running_capsule(cid: str):
    container = _get_container(manifests.capsule_container_name(cid))
    if container is None:
        raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
    if container.status != "running":
        raise ApiError(HTTPStatus.CONFLICT, f"capsule {cid!r} is not running (status={container.status})")
    return container


def _brain_exec(container, cmd: list[str]) -> tuple[int, str]:
    rc, out = container.exec_run(cmd, user=_BRAIN_USER, workdir="/config/workspace", environment={"HOME": "/config"})
    return rc, (out or b"").decode(errors="replace")


def _brain_status(cid: str) -> dict:
    """{brain, title, authenticated} — authenticated = an API key in the env OR a persisted login.

    Auth is the CAPTAIN's step (interactive `claude` login, or a key), never pre-provisioned — the
    chat UI uses this to show 'brain awaiting login' instead of a dead prompt.
    """
    container = _running_capsule(cid)
    brain = container.labels.get("capsule.brain", manifests.DEFAULT_BRAIN)
    rc, _ = _brain_exec(
        container, ["sh", "-c", '[ -n "$ANTHROPIC_API_KEY" ] || [ -s /config/.claude/.credentials.json ]']
    )
    title = manifests.BRAINS.get(brain, {}).get("title", brain)
    return {"capsule": cid, "brain": brain, "title": title, "authenticated": rc == 0}


# The brain's QUESTIONS surface in the web chat: shimpz-ask (unchanged) drops `<rid>.req` into
# $SHIMPZ_HOME/ipc and blocks on `<rid>.resp` — in a Capsule there is NO Telegram gateway, so the
# web chat is the responder. Both ops run shimpzipc itself inside the capsule (the protocol's single
# source of truth), as the runtime user, via the fixed venv python — never a caller-shaped command.
_IPC_LIST_SCRIPT = (
    "import json, os, sys\n"
    "sys.path.insert(0, '/opt/shimpz-lib')\n"
    "import shimpzipc\n"
    "ipc = os.path.join(os.environ.get('SHIMPZ_HOME', '/config/.shimpz'), 'ipc')\n"
    "asks = []\n"
    "for rid, _req, payload in shimpzipc.pending(ipc):\n"
    "    if payload.get('type') == 'ask':\n"
    "        asks.append({'rid': str(rid), 'text': payload.get('text', ''),\n"
    "                     'options': payload.get('options') or [], 'default': payload.get('default')})\n"
    "print(json.dumps(asks))\n"
)
_IPC_ANSWER_SCRIPT = (
    "import json, os, sys\n"
    "sys.path.insert(0, '/opt/shimpz-lib')\n"
    "import shimpzipc\n"
    "ipc = os.path.join(os.environ.get('SHIMPZ_HOME', '/config/.shimpz'), 'ipc')\n"
    "rid, answer = sys.argv[1], sys.argv[2]\n"
    "wrote = shimpzipc.answer(ipc, rid, {'answer': answer})\n"
    "if wrote:\n"
    "    shimpzipc.mark_sent(os.path.join(ipc, rid + '.req'))\n"
    "print(json.dumps({'answered': bool(wrote)}))\n"
)


def _chat_asks(cid: str) -> dict:
    """The brain's pending shimpz-ask questions — what the web chat renders as option cards."""
    container = _running_capsule(cid)
    rc, out = _brain_exec(container, ["/opt/venv/bin/python", "-c", _IPC_LIST_SCRIPT])
    asks = []
    if rc == 0:
        with contextlib.suppress(json.JSONDecodeError, ValueError):
            asks = json.loads(out or "[]")
    return {"capsule": cid, "asks": asks}


def _chat_answer(cid: str, body: dict) -> dict:
    """Answer one pending ask — unblocks the shimpz-ask the brain is waiting on mid-turn."""
    rid = validate.validate_ask_rid(body.get("rid"))
    answer = validate.validate_chat_message(body.get("answer"))
    container = _running_capsule(cid)
    rc, out = container.exec_run(
        ["/opt/venv/bin/python", "-c", _IPC_ANSWER_SCRIPT, rid, answer],
        user=_BRAIN_USER,
        environment={"HOME": "/config"},
    )
    answered = False
    if rc == 0:
        with contextlib.suppress(json.JSONDecodeError, ValueError):
            answered = bool(json.loads((out or b"").decode(errors="replace") or "{}").get("answered"))
    audit.log("chat_answer", cid, result="ok" if answered else "denied", rid=rid)
    return {"capsule": cid, "rid": rid, "answered": answered}


# The Claude-subscription OAuth flow, PER CAPSULE — the exact mirror of shimpz-driver's brain-login
# (drivers/apps/app.py): only ever the FIXED binary `shimpz-login` (baked into the brain image every
# capsule runs), owner-enforced upstream, audited, the pasted code validated + argv'd, NEVER logged.
def _capsule_login_start(cid: str) -> dict:
    container = _running_capsule(cid)
    # detached: the bridge blocks holding the PKCE state until the Captain pastes the code
    container.exec_run(["shimpz-login", "run"], detach=True, user=_BRAIN_USER, environment={"HOME": "/config"})
    trace_id = audit.log("brain_login", cid, result="ok", step="start")
    return {"capsule": cid, "started": True, "trace_id": trace_id}


def _capsule_login_url(cid: str) -> dict:
    container = _running_capsule(cid)
    rc, out = _brain_exec(container, ["sh", "-c", 'cat "${SHIMPZ_HOME:-/config/.shimpz}/login/url" 2>/dev/null'])
    url = out.strip() if rc == 0 else ""
    audit.log("brain_login", cid, result="ok", step="url", has_url=bool(url))
    return {"capsule": cid, "url": url} if url else {"capsule": cid, "pending": True}


def _capsule_login_code(cid: str, body: dict) -> dict:
    code = validate.validate_login_code(body.get("code"))
    container = _running_capsule(cid)
    rc, _ = container.exec_run(["shimpz-login", "submit", code], user=_BRAIN_USER, environment={"HOME": "/config"})
    ok = rc == 0
    audit.log("brain_login", cid, result="ok" if ok else "error", step="code")
    return {"capsule": cid, "ok": ok}


def _capsule_login_status(cid: str) -> dict:
    container = _running_capsule(cid)
    rc, out = _brain_exec(container, ["shimpz-login", "status", "--json"])
    result: dict = {"loggedIn": False}
    if rc == 0:
        with contextlib.suppress(json.JSONDecodeError, ValueError):
            parsed = json.loads(out or "{}")
            result = {"loggedIn": bool(parsed.get("loggedIn")), "email": parsed.get("email")}
    if not result["loggedIn"]:
        # surface the bridge's OWN last verdict (it writes result as JSON) so a failed exchange is
        # never a mute generic error — the Captain sees the real reason and can just start over
        rc, raw = _brain_exec(container, ["sh", "-c", 'cat "${SHIMPZ_HOME:-/config/.shimpz}/login/result" 2>/dev/null'])
        if rc == 0 and raw.strip():
            with contextlib.suppress(json.JSONDecodeError, ValueError):
                verdict = json.loads(raw)
                if not verdict.get("ok") and verdict.get("message"):
                    result["last_error"] = str(verdict["message"])[:300]
    audit.log("brain_login", cid, result="ok", step="status", logged_in=result["loggedIn"])
    return {"capsule": cid, **result}


def _claude_cmd(message: str, *, resume: bool, stream: bool) -> list[str]:
    """The headless brain invocation, mirroring shimpzchat.py's own flags EXACTLY.

    `--dangerously-skip-permissions` is MANDATORY here: with no interactive approver in `-p` mode, a
    tool call (Bash, shimpz-ask, …) would otherwise BLOCK forever on a permission prompt no one can
    answer — the same reason the Telegram brain runs with it (as the unprivileged `abc` user, which
    is what makes the flag acceptable; the capsule is already sandboxed: no docker.sock, no host, its
    own net + scoped DB). `stream` uses stream-json (the same read loop the Telegram brain relays) so
    the web chat can update the reply LIVE and show tool status; else plain text (the fallback path).
    """
    cmd = ["timeout", str(CHAT_TIMEOUT_SECONDS), "claude", "-p"]
    if resume:
        cmd.append("--continue")
    cmd.append("--dangerously-skip-permissions")
    if stream:
        cmd += ["--output-format", "stream-json", "--verbose", "--include-partial-messages"]
    else:
        cmd += ["--output-format", "text"]
    return [*cmd, message]


def _chat(cid: str, message: str) -> dict:
    """One Captain→brain exchange (non-streaming fallback), run inside the capsule with its own config.

    `claude -p --continue` exactly as the owner runs it; 409 when the brain was never authenticated.
    """
    container = _running_capsule(cid)
    rc, out = _brain_exec(container, _claude_cmd(message, resume=True, stream=False))
    if rc != 0 and "no conversation" in out.lower():  # first message ever — nothing to --continue
        rc, out = _brain_exec(container, _claude_cmd(message, resume=False, stream=False))
    if rc == 124:
        raise ApiError(HTTPStatus.GATEWAY_TIMEOUT, f"the brain did not answer within {CHAT_TIMEOUT_SECONDS}s")
    if rc != 0:
        lowered = out.lower()
        if any(marker in lowered for marker in _AUTH_MARKERS):
            raise ApiError(HTTPStatus.CONFLICT, "brain not authenticated — the Captain must log the brain in first")
        raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, f"brain error (rc={rc}): {out[-800:]}")
    return {"capsule": cid, "reply": out.strip()[:CHAT_OUTPUT_CAP]}


def _stream_events(container, message: str, *, resume: bool):
    """Run one live stream-json claude and yield simplified events as they arrive.

    Mirrors shimpzchat.py's _consume_event: `assistant` text blocks → {"t":"text"} (the growing reply,
    rendered as markdown by the client), `tool_use` → {"t":"tool"} (the status ticker), `result` →
    the definitive final text. Reads the docker exec byte stream, splits on newlines, parses NDJSON.
    """
    exec_id = _docker.api.exec_create(
        container.id,
        _claude_cmd(message, resume=resume, stream=True),
        user=_BRAIN_USER,
        workdir="/config/workspace",
        environment={"HOME": "/config"},
    )["Id"]
    buf = b""
    final = ""
    tail = ""  # last bit of raw output, so an auth failure (no text, non-zero exit) is still classifiable
    for chunk in _docker.api.exec_start(exec_id, stream=True):
        buf += chunk
        tail = (tail + chunk.decode("utf-8", "replace"))[-2000:]
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            evt = _parse_stream_line(line)
            if evt is None:
                continue
            kind, value = evt
            if kind == "text":
                final = value
                yield {"t": "text", "text": value}
            elif kind == "tool":
                yield {"t": "tool", "label": value}
            elif kind == "result":
                final = value or final
    rc = _docker.api.exec_inspect(exec_id).get("ExitCode")
    yield {"t": "_end", "rc": rc, "final": final, "tail": tail}


def _parse_stream_line(line: bytes):
    """One stream-json line → ('text'|'tool'|'result', value) or None. Never raises."""
    text = line.decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        evt = json.loads(text)
    except json.JSONDecodeError:
        return None
    etype = evt.get("type")
    if etype == "assistant":
        for blk in evt.get("message", {}).get("content", []):
            if blk.get("type") == "text" and (blk.get("text") or "").strip():
                return ("text", blk["text"].strip())
            if blk.get("type") == "tool_use":
                return ("tool", str(blk.get("name") or "tool"))
    elif etype == "result":
        return ("result", (evt.get("result") or "").strip())
    return None


def _stop_chat(cid: str) -> dict:
    """Kill this capsule's in-flight chat brain (the Stop button).

    v1: one chat per capsule, so a single pkill of the stream-json claude ends the current turn
    cleanly (SIGTERM → the exec drains).
    """
    container = _running_capsule(cid)
    container.exec_run(["pkill", "-u", _BRAIN_USER, "-f", "output-format stream-json"], user="root")
    audit.log("chat_stop", cid, result="ok")
    return {"capsule": cid, "stopped": True}


def _put_inbox_file(cid: str, filename: str, content_b64: str) -> dict:
    """Land an uploaded file in the capsule's OWN workspace inbox (chat references it by path)."""
    container = _running_capsule(cid)
    safe_name = validate.validate_inbox_filename(filename)
    try:
        data = base64.b64decode(content_b64 or "", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid base64 content: {exc}") from exc
    if not data or len(data) > MAX_INBOX_FILE_BYTES:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"file must be 1..{MAX_INBOX_FILE_BYTES} bytes")
    _brain_exec(container, ["mkdir", "-p", INBOX_DIR])
    container.put_archive(INBOX_DIR, manifests.build_inbox_tar(safe_name, data))
    return {"capsule": cid, "path": f"{INBOX_DIR}/{safe_name}", "bytes": len(data)}


# ── operations ───────────────────────────────────────────────────────────────
def _teardown(cid: str) -> bool:
    """Idempotently remove a capsule's container + network + scoped DB + BOTH volumes + its APPS.

    Returns whether every DB drop succeeded. Used by _destroy AND by _create's rollback — a destroyed
    capsule leaves NO remanence, so a later capsule whose name collides to the same cid can never
    inherit prior data. Apps go first: each installed app's container, scoped DB and egress policy are
    removed before the network they live on.
    """
    dropped = True
    for app_container in _capsule_app_containers(cid):
        app_id = app_container.labels.get("capsule.app", "")
        if app_id:
            dropped = _teardown_app(cid, app_id) and dropped
    container = _get_container(manifests.capsule_container_name(cid))
    if container is not None:
        with contextlib.suppress(docker.errors.APIError):
            container.remove(force=True)
    _teardown_capsule_network(cid)
    try:
        pgdriver_client.drop_db(manifests.capsule_db_project(cid))
    except Exception:  # noqa: BLE001 — surfaced by the caller's audit line; teardown proceeds regardless
        dropped = False
    for vol in (manifests.capsule_config_volume(cid), manifests.capsule_workspace_volume(cid)):
        with contextlib.suppress(docker.errors.APIError, docker.errors.NotFound):
            _docker.volumes.get(vol).remove(force=True)
    return dropped


def _create(cid: str, body: dict, owner: str = "") -> dict:
    name = str(body.get("name") or cid).strip() or cid
    brain = str(body.get("brain") or manifests.DEFAULT_BRAIN).strip()
    if brain not in manifests.BRAINS:
        raise ApiError(
            HTTPStatus.BAD_REQUEST, f"unknown brain {brain!r} — this Space accepts: {sorted(manifests.BRAINS)}"
        )
    with _lock_for(cid):
        existing = _get_container(manifests.capsule_container_name(cid))
        if existing is not None:
            # An account may only "re-create" (get) its OWN capsule; a name collision with a different
            # owner is invisible (404), never a hijack of someone else's capsule.
            if owner and existing.labels.get("capsule.owner", "") != owner:
                raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
            return {"capsule": cid, "name": name, "status": existing.status, "created": False}
        # Hard quota — an authenticated caller must not be able to exhaust host RAM/disk or the Docker
        # network address pool by creating capsules without bound.
        current = len(_docker.containers.list(all=True, filters={"label": "capsule.driver"}))
        if current >= MAX_CAPSULES:
            raise ApiError(HTTPStatus.TOO_MANY_REQUESTS, f"capsule limit reached ({current}/{MAX_CAPSULES})")
        # Transactional: on ANY failure, roll back everything partially created before surfacing — never
        # leak an orphan DB/role, network, or volume for an operator to hunt down later.
        try:
            db = pgdriver_client.create_db(manifests.capsule_db_project(cid))
            _ensure_volume(manifests.capsule_config_volume(cid))
            _ensure_volume(manifests.capsule_workspace_volume(cid))
            network = _ensure_capsule_network(cid)
            _wire_capsule_deps(network)
            kwargs = manifests.build_capsule_kwargs(
                cid, name, database_url=db["database_url"], owner=owner, brain=brain
            )
            container = _docker.containers.create(**kwargs)
            container.start()
        except Exception as exc:
            _teardown(cid)
            if isinstance(exc, ApiError):
                raise
            raise ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, f"capsule create failed (rolled back): {exc}") from exc
        return {
            "capsule": cid,
            "name": name,
            "status": "running",
            "created": True,
            "database": manifests.capsule_db_project(cid),
        }


def _destroy(cid: str) -> dict:
    with _lock_for(cid):
        dropped = _teardown(cid)
        return {"capsule": cid, "destroyed": True, "db_dropped": dropped}


def _list(owner: str | None = None) -> dict:
    """All capsules for the operator; only the account's own when `owner` is set."""
    caps = _docker.containers.list(all=True, filters={"label": "capsule.driver"})
    if owner is not None:
        caps = [c for c in caps if c.labels.get("capsule.owner", "") == owner]
    return {"capsules": [_describe(c) for c in caps]}


def _status(cid: str) -> dict:
    container = _get_container(manifests.capsule_container_name(cid))
    if container is None:
        raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
    return _describe(container)


def _logs(cid: str, lines: int) -> dict:
    container = _get_container(manifests.capsule_container_name(cid))
    if container is None:
        raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
    return {"capsule": cid, "logs": container.logs(tail=lines).decode("utf-8", "replace")}


def _lifecycle(cid: str, op: str) -> dict:
    container = _get_container(manifests.capsule_container_name(cid))
    if container is None:
        raise ApiError(HTTPStatus.NOT_FOUND, f"capsule {cid!r} not found")
    getattr(container, op)()
    return {"capsule": cid, "op": op, "status": "ok"}


# ── HTTP ─────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "capsule-driver/1.0"

    def log_message(self, *_args) -> None:  # audit.log is the ONLY log source
        pass

    def _principal(self) -> tuple[str, str | None] | None:
        """('operator', None) for the admin bearer; ('account', <id>) for a valid account token; else None.

        The operator token (the admin panel) has full access. A store-forwarded account token is verified
        against the accounts service and scopes every op to that account's OWN capsules — the store holds
        no privileged secret, this driver is the enforcer.
        """
        if self.headers.get("Authorization", "") == f"Bearer {_token}":
            return ("operator", None)
        account_token = self.headers.get("X-Shimpz-Account", "")
        if account_token:
            account_id = accounts_client.verify(account_token)
            if account_id:
                return ("account", account_id)
        return None

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream_chat(self, cid: str, message: str) -> None:
        """Chunked NDJSON stream of a live brain turn — one JSON event per line, flushed as it happens.

        The store reads this line-by-line and relays each event over the Captain's WebSocket. On the
        first-message case (no session to --continue) the brain emits a 'no conversation' error with no
        text; we transparently restart fresh so the Captain never sees that internal retry.
        """
        container = _running_capsule(cid)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def emit(obj: dict) -> None:
            line = (json.dumps(obj) + "\n").encode()
            self.wfile.write(f"{len(line):X}\r\n".encode() + line + b"\r\n")
            self.wfile.flush()

        produced = False
        for resume in (True, False):
            end = None
            for evt in _stream_events(container, message, resume=resume):
                if evt.get("t") == "_end":
                    end = evt
                    break
                produced = True
                emit({"type": evt["t"], **{k: v for k, v in evt.items() if k != "t"}})
            if produced or (end and "no conversation" not in (end.get("tail", "").lower())):
                break  # got output, or a real (non-first-message) failure — don't retry
        tail_lower = (end or {}).get("tail", "").lower()
        if not produced and any(m in tail_lower for m in _AUTH_MARKERS):
            emit({"type": "error", "status": 409, "detail": "brain not authenticated"})
        else:
            emit({"type": "done", "reply": (end or {}).get("final", "")[:CHAT_OUTPUT_CAP]})
        self.wfile.write(b"0\r\n\r\n")  # terminating chunk
        self.wfile.flush()
        audit.log("chat", cid, result="ok", streamed=True)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid JSON body: {exc}") from exc

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        principal = self._principal()
        if principal is None:
            if self.client_address[0] == "127.0.0.1":
                audit.log("auth", self.path, result="denied", level="info", source="loopback-probe")
            else:
                audit.log("auth", self.path, result="denied")
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid or missing credentials"})
            return
        try:
            self._route(method, principal)
        except ApiError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=exc.message)
            self._send_json(exc.status, {"error": exc.message})
        except validate.ValidationError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=str(exc))
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except marketplace.MarketplaceError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=str(exc))
            self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 — fail loud, never leak a stack to the caller
            audit.log(method.lower(), self.path, result="error", reason=str(exc))
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _route(self, method: str, principal: tuple[str, str | None]) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        parts = [p for p in path.split("/") if p]
        kind, account_id = principal

        if method == "GET" and path == "/v1/capsules":
            self._send_json(HTTPStatus.OK, _list(owner=account_id if kind == "account" else None))
            return

        if len(parts) >= 3 and parts[0] == "v1" and parts[1] == "capsules":
            cid = validate.validate_capsule_id(parts[2])
            sub = parts[3] if len(parts) > 3 else ""
            if method == "POST" and sub == "create":
                body = self._read_body()
                # an account owns what it creates; an operator may create-on-behalf via an explicit owner
                owner = account_id or str(body.get("owner", "")).strip()
                result = _create(cid, body, owner)
                trace = audit.log("create", cid, result="ok", created=result.get("created"), owner=owner)
                self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
                return
            # every other op acts on an EXISTING capsule → gate on ownership first (404 if not yours)
            _authorize(cid, principal)
            if method == "DELETE" and sub == "":
                result = _destroy(cid)
                trace = audit.log("destroy", cid, result="ok", db_dropped=result["db_dropped"])
                self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
                return
            if sub == "apps":
                self._route_apps(method, parts, cid, principal)
                return
            if sub == "brain":
                self._route_brain(method, parts, cid)
                return
            if sub == "chat":
                self._route_chat(method, parts, cid)
                return
            if method == "POST" and sub == "files":
                body = self._read_body()
                result = _put_inbox_file(cid, body.get("filename"), body.get("content_b64"))
                trace = audit.log("inbox_file", cid, result="ok", path=result["path"], bytes=result["bytes"])
                self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
                return
            if method == "GET" and sub == "status":
                self._send_json(HTTPStatus.OK, _status(cid))
                return
            if method == "GET" and sub == "logs":
                self._send_json(HTTPStatus.OK, _logs(cid, int(query.get("lines", "200"))))
                return
            if method == "POST" and sub in ("stop", "start", "restart"):
                result = _lifecycle(cid, sub)
                audit.log(sub, cid, result="ok")
                self._send_json(HTTPStatus.OK, result)
                return

        raise ApiError(HTTPStatus.NOT_FOUND, f"no such operation: {method} {path}")

    def _route_brain(self, method: str, parts: list[str], cid: str) -> None:
        """/v1/capsules/{cid}/brain[/login/*] — status + the Claude-subscription OAuth bridge.

        Ownership was already enforced by _authorize; every op only ever execs the FIXED binary
        `shimpz-login` (or reads its files) inside THIS capsule's own brain container.
        """
        if method == "GET" and len(parts) == 4:
            self._send_json(HTTPStatus.OK, _brain_status(cid))
            return
        if len(parts) == 6 and parts[4] == "login":
            step = parts[5]
            if method == "POST" and step == "start":
                self._send_json(HTTPStatus.OK, _capsule_login_start(cid))
                return
            if method == "GET" and step == "url":
                self._send_json(HTTPStatus.OK, _capsule_login_url(cid))
                return
            if method == "POST" and step == "code":
                self._send_json(HTTPStatus.OK, _capsule_login_code(cid, self._read_body()))
                return
            if method == "GET" and step == "status":
                self._send_json(HTTPStatus.OK, _capsule_login_status(cid))
                return
        raise ApiError(HTTPStatus.NOT_FOUND, f"no such operation: {method} /{'/'.join(parts)}")

    def _route_chat(self, method: str, parts: list[str], cid: str) -> None:
        """/v1/capsules/{cid}/chat[/stream|/stop|/asks|/answer] — the Captain's brain conversation.

        Ownership was already enforced by _authorize. `chat` (bare) is the non-streaming fallback;
        `chat/stream` is the live NDJSON turn; the rest are the shimpz-ask surface + the Stop control.
        """
        sub2 = parts[4] if len(parts) > 4 else ""
        if method == "POST" and not sub2:
            message = validate.validate_chat_message(self._read_body().get("message"))
            result = _chat(cid, message)
            audit.log("chat", cid, result="ok", chars_in=len(message), chars_out=len(result["reply"]))
            self._send_json(HTTPStatus.OK, result)
            return
        if method == "POST" and sub2 == "stream":
            self._stream_chat(cid, validate.validate_chat_message(self._read_body().get("message")))
            return
        if method == "POST" and sub2 == "stop":
            self._send_json(HTTPStatus.OK, _stop_chat(cid))
            return
        if method == "GET" and sub2 == "asks":
            self._send_json(HTTPStatus.OK, _chat_asks(cid))
            return
        if method == "POST" and sub2 == "answer":
            self._send_json(HTTPStatus.OK, _chat_answer(cid, self._read_body()))
            return
        raise ApiError(HTTPStatus.NOT_FOUND, f"no such operation: {method} /{'/'.join(parts)}")

    def _route_apps(self, method: str, parts: list[str], cid: str, principal: tuple[str, str | None]) -> None:
        """/v1/capsules/{cid}/apps[/{app}] — the P4 deploy arm. Ownership was already enforced."""
        kind, account_id = principal
        if method == "POST" and len(parts) == 4:
            app_id, spec = marketplace.resolve(self._read_body().get("app"))
            # The marketplace gate, enforced where the socket lives: a NON-first-party app needs a
            # VERIFIED Shimpz account — on a self-hosted Space the verify call IS the phone-home
            # (SHIMPZ_ACCOUNTS_URL → shimpz.com), so not even the Space operator bypasses it.
            if not spec.first_party and kind != "account":
                raise ApiError(HTTPStatus.UNAUTHORIZED, f"installing {app_id!r} requires a valid Shimpz account")
            owner = account_id or _owner_of(cid) or ""
            result = _install_app(cid, app_id, spec, owner)
            trace = audit.log("install", cid, result="ok", app=app_id, installed=result["installed"])
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        if method == "GET" and len(parts) == 4:
            self._send_json(HTTPStatus.OK, _list_apps(cid))
            return
        if method == "DELETE" and len(parts) == 5:
            # Shape-validated only — NOT resolved: an app later pulled from the registry must still
            # be uninstallable from every capsule that has it.
            app_id = marketplace.validate_app_id(parts[4])
            result = _uninstall_app(cid, app_id)
            trace = audit.log("uninstall", cid, result="ok", app=app_id, db_dropped=result["db_dropped"])
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        raise ApiError(HTTPStatus.NOT_FOUND, f"no such operation: {method} /{'/'.join(parts)}")


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()  # noqa: S104


if __name__ == "__main__":
    main()
