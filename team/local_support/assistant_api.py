"""Local Assistant inventory API operations."""

from http import HTTPStatus

from docker.errors import DockerException

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
