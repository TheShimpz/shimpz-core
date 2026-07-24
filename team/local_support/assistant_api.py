"""Local Assistant inventory and Help API operations."""

from http import HTTPStatus

import assistant_help
import assistant_secret_flow
from docker.errors import DockerException

from local_support.assistant_rpc import UnsupportedAssistantRpcPathError
from local_support.errors import ApiProblemError as ApiProblem
from local_support.labels import ASSISTANT_LABEL
from local_support.validation import validate_team_id


def list_assistants(self, team_id: str) -> dict[str, list[dict[str, str]]]:
    team_id = validate_team_id(team_id)
    self.assistant_lifecycle._network(team_id)
    output: list[dict[str, str]] = []
    egress_proxy = None

    def current_egress_proxy():
        nonlocal egress_proxy
        if egress_proxy is None:
            egress_proxy = self.assistant_lifecycle._egress_proxy()
        return egress_proxy

    try:
        containers = self.client.containers.list(**self.assistant_lifecycle._assistant_filters(team_id))
    except DockerException as exc:
        raise ApiProblem(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "Docker is unavailable",
            code="docker-unavailable",
        ) from exc
    for container in containers:
        labels = container.labels
        assistant_id = labels.get(ASSISTANT_LABEL)
        spec = self.registry.get(assistant_id)
        if spec is None:
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "an installed Assistant is no longer allowlisted",
                code="assistant-registry-drift",
            )
        config = self.assistant_lifecycle._validate_container_isolation(
            container,
            team_id,
            spec,
            self.assistant_lifecycle._network_name(team_id),
            current_egress_proxy,
        )
        if self.assistant_lifecycle._has_current_assistant_artifact(config, spec):
            self.assistant_lifecycle._admit_assistant_allowed_hosts(container, spec)
            status = container.status
        else:
            status = "outdated"
        output.append({"assistant": assistant_id, "status": status})
    output.sort(key=lambda item: item["assistant"])
    return {"assistants": output}


def assistant_help_markdown(self, team_id: str, assistant_id: str, locale: str = "en") -> dict[str, str]:
    """Read bounded Markdown only from one installed, running Assistant's fixed RPC."""
    team_id = validate_team_id(team_id)
    try:
        locale = assistant_help.validate_locale(locale)
    except ValueError as exc:
        raise ApiProblem(
            HTTPStatus.BAD_REQUEST,
            "Assistant Help locale is not supported",
            code="invalid-help-locale",
        ) from exc
    spec = self.assistant_lifecycle._resolve(assistant_id)
    with self._lock(team_id):
        network = self.assistant_lifecycle._network(team_id)
        container = self.assistant_lifecycle._assistant_container(team_id, assistant_id)
        self.assistant_lifecycle._validate_container(container, team_id, spec, network.name)
        container.reload()
        if container.status != "running":
            raise ApiProblem(HTTPStatus.CONFLICT, "Assistant is not running", code="assistant-not-running")
        try:
            raw_result = self.assistant_lifecycle._rpc(
                container,
                spec,
                "GET",
                f"/v1/help/{locale}",
                assistant_secret_flow.empty_rpc_envelope(),
                detect_unsupported_path=True,
            )
        except UnsupportedAssistantRpcPathError:
            raw_result = self.assistant_lifecycle._rpc(
                container,
                spec,
                "GET",
                "/v1/help",
                assistant_secret_flow.empty_rpc_envelope(),
            )
    try:
        help_payload = assistant_help.validate_payload(raw_result)
    except ValueError as exc:
        raise ApiProblem(
            HTTPStatus.BAD_GATEWAY,
            "Assistant Help returned an invalid result",
            code="invalid-assistant-help",
        ) from exc
    return {"assistant": spec.assistant_id, **help_payload}
