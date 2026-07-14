"""Turn a validated capsule id into docker-py container kwargs for an isolated brain.

The ONE place that decides what a Capsule container actually gets. Every security-relevant field
(security_opt, network, mounts, limits, Telegram/browser OFF) is a hardcoded constant here; the caller
never carries any of them, so there is nothing to override. A Capsule is a `shimpz-brain` with:
its OWN internal core and Brain-egress networks, its OWN config+workspace volumes, a SCOPED Postgres
DSN, no docker.sock, no secrets keyring, no browser, and no Telegram. Only the Brain reaches the broad
egress-proxy; installed Apps remain on core and use the token-gated app proxy when declared.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import os
import re
import tarfile
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath

import docker
import docker.types
import network_policy
from marketplace import AppSpec

# Multi-instance (R137): SHIMPZ_SUFFIX names this Space's resources; empty (the default) is prod.
SUFFIX = os.environ.get("SHIMPZ_SUFFIX", "")
IMAGE = os.environ.get("SHIMPZ_CAPSULE_IMAGE", "shimpz-brain:shimpz-local")
CODEX_IMAGE = os.environ.get("SHIMPZ_CODEX_CAPSULE_IMAGE", "shimpz-brain-codex:shimpz-local")
# Hostile-tenant Capsules are unconditionally locked to gVisor. This is deliberately not an
# environment setting: Docker rejects create when runsc is unavailable, and the driver refuses
# lifecycle mutations until the daemon registry preserves its exact handler path, built-in security
# defaults, and every existing workload proves this exact runtime.
RUNTIME = "runsc"
RUNTIME_PATH = network_policy.CAPSULE_RUNTIME_PATH
CONTAINER_ALL_INTERFACES = str(ipaddress.IPv4Address(0))
CONTAINER_TMP = str(PurePosixPath("/") / "tmp")

# ── Brains (ADR-0004): the agent RUNTIME a Capsule boots, a per-Capsule choice ──────────────────
# The same trusted-registry pattern as the marketplace: the store forwards only a brain id; THIS map
# decides the image. Only brains that actually boot are listed (the storefront-honesty rule). The
# Codex image is registered because its real build/boot/auth proof is shipped in
# ``tests/test-codex-brain-live.py``. Credentials are always account-owned and land only in the
# Capsule's private /config; no provider receives a platform-global key.
BRAINS: dict[str, dict[str, str]] = {
    "claude-code": {
        "image": IMAGE,
        "title": "Claude Code",
        "default_model": "claude-sonnet-5",
        "healthcheck": "claude --version >/dev/null",
        "readycheck": "claude --version >/dev/null",
    },
    "codex": {
        "image": CODEX_IMAGE,
        "title": "Codex",
        "default_model": "",
        "healthcheck": "codex --version >/dev/null && shimpz-codex-auth status >/dev/null",
        "readycheck": "test -s /config/.codex/config.toml && codex --version >/dev/null",
    },
}
DEFAULT_BRAIN = "claude-code"


def build_inbox_tar(filename: str, data: bytes) -> bytes:
    """A single-file tar for put_archive into the capsule's workspace inbox.

    Owned by the runtime user (uid/gid 1000 = abc) so the brain can read AND clean it up.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name=filename)
        info.size = len(data)
        info.mode = 0o644
        info.uid = info.gid = 1000
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# Shared-plane identities are suffix-aware and intentionally split. Postgres plus installed Apps live
# on the Capsule core/data network. The broad Brain proxy lives only on the separate Brain-egress
# network, so an App can never use it as an unauthenticated confused deputy.
EGRESS_CONTAINER = network_policy.EGRESS_CONTAINER
POSTGRES_CONTAINER = network_policy.POSTGRES_CONTAINER

CAPSULE_PREFIX = network_policy.CAPSULE_PREFIX
NET_PREFIX = network_policy.CORE_NETWORK_PREFIX

# Per-capsule envelope. The hard cap is charged in full against capsule-driver's global/owner
# admission budget before Docker provisioning begins; the lower cgroup reservation is only runtime
# reclaim protection, never the capacity-accounting unit. cgroup v2: mem_reservation ≈ memory.low,
# mem_limit ≈ memory.max.
MEM_LIMIT = os.environ.get("SHIMPZ_CAPSULE_MEM_LIMIT", "2g")
MEM_RESERVATION = os.environ.get("SHIMPZ_CAPSULE_MEM_RESERVATION", "384m")
NANO_CPUS = int(os.environ.get("SHIMPZ_CAPSULE_NANO_CPUS", str(4_000_000_000)))  # 4 vCPU ceiling; idle ≈ 0
PIDS_LIMIT = int(os.environ.get("SHIMPZ_CAPSULE_PIDS_LIMIT", "2048"))


def hard_memory_bytes(value: str | int | float, *, setting: str) -> int:
    """Parse one Docker hard-memory setting once and reject an absent/unbounded value."""
    if isinstance(value, bool):
        raise ValueError(f"{setting} must be a valid positive Docker memory size")
    match = re.fullmatch(
        r"(?P<number>[0-9]+(?:\.[0-9]+)?)(?P<unit>[kmgtp]?)(?:i?b)?",
        str(value).strip(),
        re.IGNORECASE,
    )
    if match is None:
        raise ValueError(f"{setting} must be a valid positive Docker memory size")
    try:
        parsed = Decimal(match.group("number")) * Decimal(1024 ** "bkmgtp".index(match.group("unit").lower() or "b"))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{setting} must be a valid positive Docker memory size") from exc
    if parsed <= 0 or parsed != parsed.to_integral_value():
        raise ValueError(f"{setting} must be a valid positive Docker memory size")
    return int(parsed)


MEM_LIMIT_BYTES = hard_memory_bytes(MEM_LIMIT, setting="SHIMPZ_CAPSULE_MEM_LIMIT")

MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def model_for_brain(brain: str, value: object = None) -> str:
    """Return one Capsule's validated provider model, or that provider's explicit default."""
    if brain not in BRAINS:
        raise ValueError(f"unsupported brain: {brain!r}")
    if value is None or value == "":
        return BRAINS[brain]["default_model"]
    if not isinstance(value, str):
        raise ValueError("model must be a string")
    model = value.strip()
    if not model:
        return BRAINS[brain]["default_model"]
    if MODEL_RE.fullmatch(model) is None:
        raise ValueError("model must be 1-128 safe identifier characters")
    return model


# Per-capsule APP envelope (mirrors drivers/apps: 1g because real uvicorn backends idle near 500 MiB —
# R125; 0.5 vCPU; pids capped). One installed app = one container INSIDE the capsule's own network.
APP_MEM_LIMIT = os.environ.get("SHIMPZ_CAPSULE_APP_MEM_LIMIT", "1g")
APP_NANO_CPUS = int(os.environ.get("SHIMPZ_CAPSULE_APP_NANO_CPUS", str(500_000_000)))
APP_PIDS_LIMIT = int(os.environ.get("SHIMPZ_CAPSULE_APP_PIDS_LIMIT", "256"))
APP_MEM_LIMIT_BYTES = hard_memory_bytes(APP_MEM_LIMIT, setting="SHIMPZ_CAPSULE_APP_MEM_LIMIT")
# The MANY-tenant egress proxy (per-app token-gated) — connected into a capsule's net only when an
# installed app actually declares egress; the capsule brain itself keeps using the brain-grade egress-proxy.
APP_EGRESS_CONTAINER = network_policy.APP_EGRESS_CONTAINER

# Vector reads Docker's json-file logs and derives the capsule from the line's own label (no Docker API).
# Keep the required json-file driver, but never inherit its unbounded default: a hostile workload can
# otherwise fill the host filesystem without exceeding its cgroup memory/PID admission envelope.
CAP_LOG_MAX_SIZE = "5m"
CAP_LOG_MAX_FILE = "2"
CAP_LOG_CONFIG = docker.types.LogConfig(
    type=docker.types.LogConfig.types.JSON,
    config={
        "labels": "capsule.id",
        "max-size": CAP_LOG_MAX_SIZE,
        "max-file": CAP_LOG_MAX_FILE,
    },
)


def capsule_container_name(cid: str) -> str:
    return network_policy.capsule_container_name(cid)


def capsule_network_name(cid: str) -> str:
    return network_policy.network_name(cid, network_policy.CORE_KIND)


def capsule_brain_egress_network_name(cid: str) -> str:
    return network_policy.network_name(cid, network_policy.BRAIN_EGRESS_KIND)


def capsule_network_labels(cid: str, kind: str) -> dict[str, str]:
    return network_policy.network_labels(cid, kind)


def capsule_config_volume(cid: str) -> str:
    return network_policy.volume_name(cid, network_policy.CONFIG_VOLUME_KIND)


def capsule_workspace_volume(cid: str) -> str:
    return network_policy.volume_name(cid, network_policy.WORKSPACE_VOLUME_KIND)


def capsule_db_project(cid: str) -> str:
    return f"capsule_{cid}"


def capsule_app_sane(app_id: str) -> str:
    """The catalog id ('notification-center') as a Docker/Postgres-safe token ('notification_center')."""
    return app_id.replace("-", "_")


def capsule_app_container_name(cid: str, app_id: str) -> str:
    return network_policy.capsule_app_container_name(cid, app_id)


def capsule_app_db_project(cid: str, app_id: str) -> str:
    """The per-(capsule, app) DB project: 'cap_<sha10(cid)>_<app>'.

    Deterministic (uninstall/teardown re-derive it with no lookup) and always within pg-driver's
    58-char project cap: a readable 'capsule_<cid>_<app>' would overflow at the 40-char capsule-id
    maximum, so the capsule contributes a fixed 10-hex digest instead.
    """
    digest = hashlib.sha256(cid.encode()).hexdigest()[:10]
    return f"cap_{digest}_{capsule_app_sane(app_id)}"


def core_deps() -> list[tuple[str, list[str]]]:
    """Shared services allowed on a Capsule's app/data plane."""
    return [(POSTGRES_CONTAINER, ["postgres"])]


def brain_egress_deps() -> list[tuple[str, list[str]]]:
    """The broad proxy allowed only on a Capsule Brain's separate egress plane."""
    return [(EGRESS_CONTAINER, ["egress-proxy"])]


def build_capsule_kwargs(
    cid: str,
    name: str,
    *,
    database_url: str,
    owner: str = "",
    brain: str = DEFAULT_BRAIN,
    model: object = None,
) -> dict:
    """Kwargs for docker-py's low-level `containers.create` — never `run`.

    `run` would risk an accidental host-port publish or default-network attach; the whole isolation
    model depends on create + one explicit network. `brain` picks the agent runtime image from the
    trusted BRAINS registry (validated by the caller) and is recorded as the capsule.brain label.
    """
    selected_model = model_for_brain(brain, model)
    env = {
        "PUID": "1000",
        "PGID": "1000",
        "TZ": "America/Sao_Paulo",
        "TITLE": f"Capsule {name}",
        "SHIMPZ_HOME": "/config/.shimpz",
        "SHIMPZ_CAPSULE_ID": cid,
        "SHIMPZ_CAPSULE_NAME": name,
        # The core network has no default route. Only this Brain also joins its private egress network,
        # where the broad/audited CONNECT proxy is its sole outbound path. NO_PROXY lists core services;
        # `.capsule` is the SUFFIX every installed app also answers on (<app-id>.capsule) — app names
        # aren't knowable at capsule create, a suffix is, so http://<app-id>.capsule:<port> bypasses
        # the proxy in every NO_PROXY-honoring client (curl/python/node all tail-match entries).
        "HTTPS_PROXY": "http://egress-proxy:8888",
        "HTTP_PROXY": "http://egress-proxy:8888",
        "https_proxy": "http://egress-proxy:8888",
        "http_proxy": "http://egress-proxy:8888",
        "NO_PROXY": "localhost,127.0.0.1,::1,egress-proxy,postgres,.capsule",
        "no_proxy": "localhost,127.0.0.1,::1,egress-proxy,postgres,.capsule",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        # The capsule's OWN scoped database — a least-privilege proj_ role, never the superuser.
        "DATABASE_URL": database_url,
        # Infinity-memory + run knobs (mirror the main brain).
        "SHIMPZ_MEMORY_DIR": "/config/.shimpz/memory",
        "SHIMPZ_MEM_TTL_DAYS": "90",
        "SHIMPZ_RECENT_TURNS": "6",
        "SHIMPZ_PONYTAIL": "1",
        "SHIMPZ_CTX_MAX_BYTES": "1500000",
        "SHIMPZ_THINKING_TOKENS": "10000",
        "SHIMPZ_MAX_TURNS": "80",
        "SHIMPZ_AUTO_CONTINUE": "3",
        # Thread caps sized to this capsule's CPU envelope (the kernel still shows all 96 host cores).
        "LP_NUM_THREADS": "4",
        "OMP_NUM_THREADS": "4",
        "OPENBLAS_NUM_THREADS": "4",
        "MKL_NUM_THREADS": "4",
        "NUMEXPR_NUM_THREADS": "4",
        # Telegram OFF — a Capsule is not the owner's phone-facing brain (empty = gateway off).
        "TELEGRAM_BOT_TOKEN": "",
        "TELEGRAM_ALLOWED_USERS": "",
    }
    if brain == "claude-code":
        env["SHIMPZ_MODEL"] = selected_model
    return {
        "image": BRAINS[brain]["image"],
        "name": capsule_container_name(cid),
        "hostname": cid,
        "runtime": RUNTIME,
        "environment": env,
        # Hardened, identical to the main brain minus the browser's elevated caps: no new privileges,
        # not privileged, no docker.sock, no secrets keyring.
        "security_opt": ["no-new-privileges:true", "apparmor=docker-default"],
        "privileged": False,
        "ipc_mode": "private",
        "cgroupns": "private",
        # Boot-minimized against the shipping LSIO/s6 Brain images: CHOWN + DAC_OVERRIDE are required
        # for supervised init, SETGID + SETUID for the abc transition, and KILL for clean shutdown.
        # Removing any required member was exercised independently; no other default capability stays.
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN", "DAC_OVERRIDE", "KILL", "SETGID", "SETUID"],
        # Create on the Capsule core network. app.py then attaches only this Brain to its separate
        # Brain-egress network; broad egress-proxy is never a core-network member.
        "network": capsule_network_name(cid),
        "mounts": [
            docker.types.Mount(target="/config", source=capsule_config_volume(cid), type="volume"),
            docker.types.Mount(target="/config/workspace", source=capsule_workspace_volume(cid), type="volume"),
        ],
        "tmpfs": {CONTAINER_TMP: "size=2g,mode=1777"},
        "mem_limit": MEM_LIMIT,
        # Equal memory and memory+swap ceilings disable swap for this hostile workload. Leaving
        # MemorySwap unset lets Docker grant an additional swap allowance on swap-enabled hosts.
        "memswap_limit": MEM_LIMIT,
        "mem_reservation": MEM_RESERVATION,
        "nano_cpus": NANO_CPUS,
        "pids_limit": PIDS_LIMIT,
        "ulimits": [docker.types.Ulimit(name="nofile", soft=65536, hard=65536)],
        # Hostile workloads may only become runnable through the driver's static+live proof. Docker
        # daemon startup or a natural process crash must never auto-start them behind that gate.
        "restart_policy": {"Name": "no"},
        "healthcheck": docker.types.Healthcheck(
            test=["CMD-SHELL", BRAINS[brain]["healthcheck"]],
            interval=30 * 10**9,
            timeout=10 * 10**9,
            retries=3,
            start_period=60 * 10**9,
        ),
        "labels": {
            "capsule.driver": "1",
            "capsule.id": cid,
            "capsule.name": name,
            "capsule.owner": owner,
            "capsule.brain": brain,
            "capsule.model": selected_model,
        },
        "log_config": CAP_LOG_CONFIG,
        "detach": True,
    }


def build_capsule_app_kwargs(
    cid: str,
    app_id: str,
    spec: AppSpec,
    *,
    database_url: str = "",
    proxy_env: dict[str, str] | None = None,
    owner: str = "",
    capsule_name: str = "",
) -> dict:
    """Kwargs for an installed APP container inside capsule `cid`'s own core/data network.

    Tighter than the capsule brain (the packaging contract allows it): non-root fixed uid, cap_drop ALL,
    read-only rootfs with a /tmp tmpfs, no mounts at all — the app's ONLY state is its scoped DB, so an
    app container is disposable by construction. `proxy_env` is the app-egress lock (HTTPS_PROXY with the
    app's own token) — injected here by app.py only when the registry spec declares egress, never
    caller-suppliable. NOTE: the label is `capsule.app.driver`, NOT `capsule.driver` — app containers must
    never count against the capsule quota or appear in the capsule list.
    """
    env = {
        # The contract: the app answers HTTP on $PORT on its own interface (see sdk packaging docs).
        "PORT": str(spec.port),
        "HOST": CONTAINER_ALL_INTERFACES,
        "SHIMPZ_CAPSULE_ID": cid,
        # The capsule's DISPLAY name — the owner-given identity ("the hero's name"), so every app can
        # speak AS its capsule ("Zyon asks your approval") instead of leaking an internal id.
        "SHIMPZ_CAPSULE_NAME": capsule_name or cid,
        "SHIMPZ_APP": app_id,
        "NO_PROXY": "localhost,127.0.0.1,::1,postgres,.capsule",
        "no_proxy": "localhost,127.0.0.1,::1,postgres,.capsule",
        **({"DATABASE_URL": database_url} if database_url else {}),
        **(proxy_env or {}),
    }
    return {
        "image": spec.image,
        "name": capsule_app_container_name(cid, app_id),
        "runtime": RUNTIME,
        "environment": env,
        "user": "10001:10001",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true", "apparmor=docker-default"],
        "privileged": False,
        "ipc_mode": "private",
        "cgroupns": "private",
        # ONE network at create: the capsule's OWN internal bridge (app.py re-attaches with the app-id
        # alias so the capsule brain reaches it as http://<app-id>:<port>). Never a shared app net —
        # apps are per-Capsule (ADR-0002); a shared instance would mix tenant data.
        "network": capsule_network_name(cid),
        "read_only": True,
        "tmpfs": {CONTAINER_TMP: "size=256m"},
        "mem_limit": APP_MEM_LIMIT,
        "memswap_limit": APP_MEM_LIMIT,
        "nano_cpus": APP_NANO_CPUS,
        "pids_limit": APP_PIDS_LIMIT,
        "ulimits": [docker.types.Ulimit(name="nofile", soft=4096, hard=4096)],
        "restart_policy": {"Name": "no"},
        "labels": {
            "capsule.app.driver": "1",
            "capsule.id": cid,
            "capsule.app": app_id,
            "capsule.app.db": "1" if spec.db else "0",
            "capsule.owner": owner,
        },
        "log_config": CAP_LOG_CONFIG,
        "detach": True,
    }
