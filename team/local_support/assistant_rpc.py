"""Local Assistant RPC transport and fail-stop readiness."""

import socket
import time
from contextlib import suppress
from http import HTTPStatus
from pathlib import Path

import power_execution
from container_policy import local as local_container_policy
from docker.errors import DockerException, NotFound
from local_registry import AssistantSpec

from local_support.errors import ApiProblemError as ApiProblem

MAX_RESPONSE_BYTES = 512 * 1024
RPC_TIMEOUT_SECONDS = 8
HEALTH_TIMEOUT_SECONDS = 15
ASSISTANT_UID = local_container_policy.ASSISTANT_UID
ASSISTANT_WORKDIR = str(Path("/") / "tmp")
POWER_COMMAND = "/usr/local/bin/shimpz-power"


def _close_exec_stream(stream) -> None:
    power_execution.close_exec_stream(stream)


def _fail_stop_power(self, container) -> None:
    """Stop, then kill if needed, and prove an ambiguous local Power cannot keep running."""
    try:
        container.stop(timeout=3)
    except NotFound:
        return
    except DockerException:
        pass
    if self._power_not_running(container):
        return
    try:
        container.kill()
    except NotFound:
        return
    except DockerException:
        pass
    if self._power_not_running(container):
        return
    self._blocked_power_workloads.add(container.id)
    raise ApiProblem(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "Assistant Power termination could not be proved; reinstall the Assistant",
        code="assistant-power-blocked",
    )


def _power_not_running(container) -> bool:
    try:
        container.reload()
    except NotFound:
        return True
    except DockerException:
        return False
    state = container.attrs.get("State")
    return isinstance(state, dict) and state.get("Running") is False


def _read_rpc_frames(self, raw_socket: socket.socket, deadline: float) -> tuple[bytes, bytes]:
    return power_execution.read_rpc_frames(raw_socket, deadline, MAX_RESPONSE_BYTES)


def _rpc(
    self,
    container,
    power_id: str,
    payload: dict,
) -> object:
    try:
        encoded = power_execution.encode_rpc_invocation(payload["input"], payload["accounts"])
    except (KeyError, ValueError) as exc:
        raise ApiProblem(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "request is too large",
            code="body-too-large",
        ) from exc

    def close_stream(stream: object) -> None:
        with suppress(Exception):
            self._close_exec_stream(stream)

    try:
        return power_execution.rpc_exchange(
            container.id,
            [POWER_COMMAND, power_id],
            encoded,
            power_execution.RpcExchangeStrategy(
                api=self.client.api,
                user=ASSISTANT_UID,
                workdir=ASSISTANT_WORKDIR,
                timeout=RPC_TIMEOUT_SECONDS,
                maximum=MAX_RESPONSE_BYTES,
                transport_errors=(DockerException,),
                fail_stop=lambda: self._fail_stop_power(container),
                cancelled=lambda _exc: None,
                close_stream=close_stream,
            ),
        )
    except power_execution.RpcExchangeError as exc:
        message, code = {
            "timeout": ("Assistant Power timed out", "assistant-timeout"),
            "ambiguous": ("Assistant Power status is ambiguous", "assistant-rpc-failed"),
            "failed": ("Assistant Power failed", "assistant-rpc-failed"),
            "invalid-result": ("Assistant Power failed", "assistant-rpc-failed"),
        }.get(exc.kind, (None, None))
        status = power_execution.rpc_failure_status(exc.kind)
        raise ApiProblem(status, message, code=code) from exc


def _wait_ready(self, container, _spec: AssistantSpec) -> None:
    deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        container.reload()
        if container.status == "running":
            return
        if container.status != "created":
            break
        time.sleep(0.2)
    raise ApiProblem(HTTPStatus.BAD_GATEWAY, "Assistant did not become ready", code="assistant-not-ready")
