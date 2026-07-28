#!/opt/venv/bin/python
"""Docker HEALTHCHECK probe: runtime/images/topology readiness and auth-gate enforcement.

The probe reads raw Engine responses over Docker's local Unix socket with stdlib HTTP, avoiding client
construction and keeping its startup dependency closure narrow. The configured hostile-tenant runtime
must remain bound to the reviewed absolute handler while Docker advertises its built-in seccomp and
AppArmor defaults; every advertised Brain image must be present, and every existing Team Brain/App
must actually use that runtime. The probe never accepts Docker's default runc, a running workload left
outside the current registry, or a missing provider. Then an unauthenticated driver GET must be
refused with 403 — a 2xx means the auth gate is not enforced.
"""

import http.client
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import marketplace
from container_policy import network as network_policy
from hosted_install import dynamic_assistants

DOCKER_SOCKET = os.environ.get("DOCKER_HOST_SOCKET", "/var/run/docker.sock")
# Must stay identical to manifests.RUNTIME without importing the SDK-backed module. This is not an
# operator override: hostile-tenant readiness is always tied to the shipping gVisor runtime.
REQUIRED_RUNTIME = "runsc"
REQUIRED_RUNTIME_PATH = "/usr/local/bin/runsc"
DEFAULT_BRAIN_IMAGE = (
    "registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c"
)
REQUIRED_BRAIN_IMAGES = {
    "runtime": os.environ.get("SHIMPZ_TEAM_IMAGE", DEFAULT_BRAIN_IMAGE),
}
REQUIRED_IMAGES = tuple(REQUIRED_BRAIN_IMAGES.values())
LISTEN_PORT = int(os.environ.get("SHIMPZ_TEAMDRIVER_PORT", "7077"))
DYNAMIC_ASSISTANTS = dynamic_assistants.DynamicAssistantStore(
    Path(
        os.environ.get(
            "SHIMPZ_TEAM_DYNAMIC_ASSISTANT_PATH",
            "/var/lib/team-driver/dynamic-assistants/bindings.json",
        )
    )
)


def _docker_json(path: str) -> tuple[int, object | None]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    response = None
    try:
        client.connect(DOCKER_SOCKET)
        request = f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
        client.sendall(request.encode("ascii"))
        response = http.client.HTTPResponse(client)
        response.begin()
        payload = json.loads(response.read())
    except OSError, http.client.HTTPException, json.JSONDecodeError, UnicodeError, ValueError:
        return 0, None
    else:
        return response.status, payload
    finally:
        if response is not None:
            response.close()
        client.close()


def daemon_isolation_ready() -> bool:
    """Evaluate the runtime handler and daemon profiles from one Engine-info snapshot."""
    status, info = _docker_json("/info")
    return (
        status == 200
        and isinstance(info, dict)
        and network_policy.daemon_isolation_valid(info, REQUIRED_RUNTIME, REQUIRED_RUNTIME_PATH)
    )


def _image_id(image_ref: str) -> str | None:
    encoded = urllib.parse.quote(image_ref, safe="")
    status, metadata = _docker_json(f"/images/{encoded}/json")
    if status != 200 or not isinstance(metadata, dict):
        return None
    image_id = metadata.get("Id")
    return image_id if isinstance(image_id, str) and image_id else None


def images_ready() -> bool:
    """Require the exact local image references advertised by the provider registry."""
    return all(_image_id(image_ref) is not None for image_ref in REQUIRED_IMAGES)


def _expected_workload_image(
    metadata: dict,
    image_ids: dict[str, str],
    bindings: dict[tuple[str, str], dynamic_assistants.DynamicAssistantBinding],
) -> tuple[str, str, bool] | None:
    config = metadata.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict):
        return None
    if labels.get("team.driver") == "1":
        provider = labels.get("team.brain")
        image_ref = REQUIRED_BRAIN_IMAGES.get(provider) if isinstance(provider, str) else None
        compact_app_runtime = False
    elif labels.get("team.app.driver") == "1":
        app_id = labels.get("team.app")
        app_spec = marketplace.APPS.get(app_id) if isinstance(app_id, str) else None
        if app_spec is not None:
            image_ref = app_spec.image
            compact_app_runtime = False
        else:
            team_id = labels.get("team.id")
            binding = bindings.get((team_id, app_id)) if isinstance(team_id, str) and isinstance(app_id, str) else None
            try:
                image_ref = binding.resolution["image_reference"] if binding is not None else None
                compact_app_runtime = binding is not None
            except KeyError, TypeError:
                return None
    else:
        return None
    if not isinstance(image_ref, str) or not image_ref:
        return None
    if image_ref not in image_ids:
        resolved = _image_id(image_ref)
        if resolved is None:
            return None
        image_ids[image_ref] = resolved
    return image_ref, image_ids[image_ref], compact_app_runtime


def _workload_network_kinds(
    metadata: dict,
    team_id: str,
    image_ids: dict[str, str],
    bindings: dict[tuple[str, str], dynamic_assistants.DynamicAssistantBinding],
) -> frozenset[str] | None:
    expected_image = _expected_workload_image(metadata, image_ids, bindings)
    if expected_image is None or not network_policy.workload_security_valid(
        metadata,
        team_id,
        REQUIRED_RUNTIME,
        expected_image_ref=expected_image[0],
        expected_image_id=expected_image[1],
        compact_app_runtime=expected_image[2],
    ):
        return None
    return network_policy.workload_network_kinds(metadata, team_id)


def _stopped_unbound_dynamic_app(
    metadata: dict,
    running: bool,
    bindings: dict[tuple[str, str], dynamic_assistants.DynamicAssistantBinding],
) -> bool:
    if running:
        return False
    config = metadata.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        not isinstance(labels, dict)
        or labels.get("team.app.driver") != "1"
        or labels.get("team.app.dynamic") != "1"
        or "team.driver" in labels
    ):
        return False
    host_config = metadata.get("HostConfig")
    restart_policy = host_config.get("RestartPolicy") if isinstance(host_config, dict) else None
    if not isinstance(restart_policy, dict) or restart_policy.get("Name") != "no":
        return False
    team_id = labels.get("team.id")
    app_id = labels.get("team.app")
    if not isinstance(team_id, str) or not team_id or not isinstance(app_id, str) or not app_id:
        return False
    return app_id not in marketplace.APPS and (team_id, app_id) not in bindings


def _inspect_workloads(
    summaries: list,
) -> (
    tuple[
        dict[str, dict],
        set[str],
        dict[str, int],
        set[str],
        dict[str, tuple[str, frozenset[str], bool]],
    ]
    | None
):
    inspections: dict[str, dict] = {}
    team_ids: set[str] = set()
    brains_by_team_id: dict[str, int] = {}
    running_brains: set[str] = set()
    workloads: dict[str, tuple[str, frozenset[str], bool]] = {}
    image_ids: dict[str, str] = {}
    bindings: dict[tuple[str, str], dynamic_assistants.DynamicAssistantBinding] = {}
    bindings_loaded = False
    for summary in summaries:
        if not isinstance(summary, dict):
            return None
        labels = summary.get("Labels")
        if not isinstance(labels, dict) or not ({"team.driver", "team.app.driver"} & set(labels)):
            continue
        container_id = summary.get("Id")
        team_id = labels.get("team.id")
        if not isinstance(container_id, str) or not container_id or not isinstance(team_id, str) or not team_id:
            return None
        app_id = labels.get("team.app")
        if (
            not bindings_loaded
            and labels.get("team.app.driver") == "1"
            and isinstance(app_id, str)
            and app_id not in marketplace.APPS
        ):
            bindings = {(binding.team_id, binding.assistant_id): binding for binding in DYNAMIC_ASSISTANTS.snapshot()}
            bindings_loaded = True
        inspect_status, metadata = _docker_json(f"/containers/{container_id}/json")
        if inspect_status != 200 or not isinstance(metadata, dict):
            return None
        state = metadata.get("State")
        running = state.get("Running") if isinstance(state, dict) else None
        if not isinstance(running, bool):
            return None
        expected_kinds = _workload_network_kinds(metadata, team_id, image_ids, bindings)
        if expected_kinds is None:
            # A current rollback can leave its stopped container after deleting the binding. It
            # cannot execute and remains visible for cleanup; a running or ambiguous orphan fails closed.
            if _stopped_unbound_dynamic_app(metadata, running, bindings):
                continue
            return None
        inspections[container_id] = metadata
        team_ids.add(team_id)
        if labels.get("team.driver") == "1":
            brains_by_team_id[team_id] = brains_by_team_id.get(team_id, 0) + 1
            if running:
                running_brains.add(team_id)
        workloads[container_id] = (team_id, expected_kinds, running)
    return inspections, team_ids, brains_by_team_id, running_brains, workloads


def _load_network_members(network: dict, inspections: dict[str, dict]) -> bool:
    members = network.get("Containers")
    if not isinstance(members, dict):
        return False
    for member_id in members:
        if member_id in inspections:
            continue
        inspect_status, metadata = _docker_json(f"/containers/{member_id}/json")
        if inspect_status != 200 or not isinstance(metadata, dict):
            return False
        inspections[member_id] = metadata
    return True


def _team_network_ready(
    team_id: str,
    inspections: dict[str, dict],
    running_brains: set[str],
    workloads: dict[str, tuple[str, frozenset[str], bool]],
) -> bool:
    kind = network_policy.CORE_KIND
    name = network_policy.network_name(team_id, kind)
    encoded = urllib.parse.quote(name, safe="")
    network_status, network = _docker_json(f"/networks/{encoded}")
    if network_status != 200 or not isinstance(network, dict):
        return False
    if not _load_network_members(network, inspections) or not network_policy.network_members_valid(
        network,
        inspections,
        team_id,
        kind,
        # Engine omits an intentionally stopped anchor from network inventory. Its immutable
        # image/resource/endpoint was proved above; only a running anchor must be a live member.
        require_brain=team_id in running_brains,
        require_dependencies=True,
    ):
        return False
    for workload_id, (workload_team_id, expected_kinds, running) in workloads.items():
        if (
            workload_team_id == team_id
            and kind in expected_kinds
            and (
                not network_policy.workload_endpoint_valid(
                    network,
                    inspections[workload_id],
                    team_id,
                    kind,
                )
                or (
                    running
                    and not network_policy.workload_live_membership_valid(
                        network,
                        inspections[workload_id],
                        team_id,
                        kind,
                    )
                )
            )
        ):
            return False
    return True


def network_topology_ready() -> bool:
    """Require exact workload posture and core-network membership for every Team."""
    status, summaries = _docker_json("/containers/json?all=1")
    if status != 200 or not isinstance(summaries, list):
        return False
    try:
        inspected = _inspect_workloads(summaries)
    except dynamic_assistants.DynamicAssistantError:
        return False
    if inspected is None:
        return False
    inspections, team_ids, brains_by_team_id, running_brains, workloads = inspected
    if any(brains_by_team_id.get(team_id) != 1 for team_id in team_ids):
        return False

    return all(_team_network_ready(team_id, inspections, running_brains, workloads) for team_id in team_ids)


def auth_gate_ready() -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{LISTEN_PORT}/v1/teams", timeout=3):
            return False
    except urllib.error.HTTPError as exc:
        return exc.code == 403
    except OSError:
        return False


def main() -> int:
    ready = daemon_isolation_ready() and images_ready() and network_topology_ready() and auth_gate_ready()
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
