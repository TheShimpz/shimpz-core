"""Hosted Assistant contracts, RPC, private state, and Power execution."""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from http import HTTPStatus
from typing import NoReturn

import assistant_account_flow
import assistant_chat
import assistant_manifest
import audit
import brain_credentials_client
import brain_runtime_client
import chat_orchestrator
import chat_turn_engine
import docker
import docker.errors
import manifests
import marketplace
import oauth_account_store
import oauth_http_client
import power_execution
import power_journal
import team_storage
from container_policy import hosted_apps, hosted_resources
from container_policy import network as network_policy
from http_boundary import runtime_state
from jsonschema import Draft202012Validator

# ── Controller-owned Assistant chat ─────────────────────────────────────────────────────────────
CHAT_OUTPUT_CAP = 60000
MAX_INBOX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILE_BODY_BYTES = MAX_INBOX_FILE_BYTES
MAX_CHAT_FILES = 8
MAX_CHAT_ASSISTANTS = 16
CHAT_PAUSED_STATUSES = chat_turn_engine.CHAT_PAUSED_STATUSES


@dataclass(frozen=True, slots=True)
class _ActiveAssistant:
    assistant_id: str
    contract: marketplace.AssistantContract
    container: object
    image: str = ""


@dataclass(frozen=True, slots=True)
class _HostedAssistantSpec:
    """Small adapter for the closed account contract."""

    assistant_id: str
    name: str
    powers: dict[str, object]
    accounts: dict[str, marketplace.AccountSpec]


@dataclass(frozen=True, slots=True)
class _HostedPowerSpec:
    accounts: tuple[str, ...]
    summary: str


@dataclass(frozen=True, slots=True)
class _HostedAssistantBinding:
    spec: _HostedAssistantSpec


@dataclass(frozen=True, slots=True)
class _PendingHostedChat:
    """Process-local state for one account-gated hosted Team turn."""

    continuation: chat_orchestrator.ChatContinuation
    assistant_ids: tuple[str, ...]
    file_ids: tuple[str, ...]
    owner: str
    identity: tuple[object, ...]


def _hosted_account_spec(active: _ActiveAssistant) -> _HostedAssistantSpec:
    name = active.assistant_id.replace("-", " ").title()
    return _HostedAssistantSpec(
        assistant_id=active.assistant_id,
        name=name,
        powers={
            power_id: _HostedPowerSpec(
                tuple(getattr(power, "accounts", ())),
                str(getattr(power, "summary", "")),
            )
            for power_id, power in active.contract.powers.items()
        },
        accounts=getattr(active.contract, "accounts", {}),
    )


def _account_bindings(
    bindings: dict[str, _ActiveAssistant],
) -> dict[str, _HostedAssistantBinding]:
    return {
        assistant_id: _HostedAssistantBinding(_hosted_account_spec(active)) for assistant_id, active in bindings.items()
    }


def _hosted_power_identity(active: _ActiveAssistant) -> tuple[object, object]:
    config = getattr(active.container, "attrs", {}).get("Config", {})
    image = config.get("Image") if isinstance(config, dict) else None
    if not isinstance(image, str) or not image:
        static = marketplace.APPS.get(active.assistant_id)
        image = active.image or (static.image if static is not None else "")
    return active.container.id, image


def _close_exec_stream(stream) -> None:
    power_execution.close_exec_stream(stream)


def _installed_assistant(
    team_id: str,
    assistant_id: object,
    inspect_memo: dict[str, object] | None = None,
    candidate=None,
    dynamic_bindings: dict[str, object] | None = None,
    egress_store=None,
):
    assistant_id, spec = hosted_apps._resolve_team_app(team_id, assistant_id, dynamic_bindings)
    contract = spec.assistant
    if contract is None:
        raise runtime_state.ApiError(HTTPStatus.NOT_FOUND, f"{assistant_id!r} is not an Assistant")
    container = candidate
    if container is None:
        container = hosted_resources._get_container(manifests.team_app_container_name(team_id, assistant_id))
    if container is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, f"Assistant {assistant_id!r} is not installed in this Team")
    with runtime_state._active_chat_guard:
        if (team_id, container.id) in runtime_state._blocked_power_workloads:
            raise runtime_state.ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "Assistant Power execution is blocked until this Assistant is reinstalled",
            )
    if (
        not network_policy.app_identity_valid(container.attrs, team_id, assistant_id)
        or str(container.attrs.get("Config", {}).get("Image", "")) != spec.image
    ):
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "installed Assistant failed its identity contract")
    hosted_resources._require_running_team_isolation(
        container,
        inspect_memo,
        refreshed=True,
        workload_spec=spec,
    )
    allowed_hosts = hosted_apps._require_assistant_allowed_hosts(spec, container)
    current_egress_store = egress_store if egress_store is not None else hosted_apps._egress_store()
    token = hosted_apps._validate_admitted_egress(team_id, assistant_id, allowed_hosts, current_egress_store)
    hosted_apps._validate_assistant_proxy_environment(container, token, allowed_hosts, current_egress_store)
    return assistant_id, contract, container


def _active_team_assistants(team_id: str) -> tuple[_ActiveAssistant, ...]:
    active: list[_ActiveAssistant] = []
    seen: set[str] = set()
    inspect_memo: dict[str, object] = {}
    try:
        installed = hosted_apps._team_app_containers(team_id)
    except docker.errors.DockerException as exc:
        raise runtime_state.ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE, "installed Assistants could not be listed"
        ) from exc
    candidate_ids = tuple(
        assistant_id
        for candidate in installed
        if isinstance((assistant_id := (candidate.labels or {}).get("team.app")), str)
    )
    dynamic_bindings = hosted_apps._dynamic_binding_snapshot(team_id, candidate_ids)
    egress_store = hosted_apps._egress_store() if candidate_ids else None
    for candidate in installed:
        assistant_id = (candidate.labels or {}).get("team.app")
        if not isinstance(assistant_id, str):
            continue
        try:
            _resolved_id, spec = hosted_apps._resolve_team_app(team_id, assistant_id, dynamic_bindings)
        except marketplace.MarketplaceError:
            continue
        if spec.assistant is None:
            continue
        try:
            candidate.reload()
        except docker.errors.DockerException as exc:
            raise runtime_state.ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE, "installed Assistant could not be inspected"
            ) from exc
        if candidate.status != "running":
            continue
        if assistant_id in seen:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "duplicate installed Assistant identity")
        current_id, contract, container = _installed_assistant(
            team_id,
            assistant_id,
            inspect_memo,
            candidate,
            dynamic_bindings,
            egress_store,
        )
        seen.add(current_id)
        active.append(_ActiveAssistant(current_id, contract, container, spec.image))
    active.sort(key=lambda item: item.assistant_id)
    return tuple(active)


def _chat_assistant_ids(value: object) -> tuple[str, ...]:
    """Return one explicit, bounded Assistant scope; empty means Brain-only."""
    if not isinstance(value, list) or len(value) > MAX_CHAT_ASSISTANTS:
        raise runtime_state.ApiError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            f"assistant_ids must contain at most {MAX_CHAT_ASSISTANTS} ids",
        )
    try:
        assistant_ids = tuple(marketplace.validate_app_id(item) for item in value)
    except marketplace.MarketplaceError:
        raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "assistant_ids contains an invalid id") from None
    if len(set(assistant_ids)) != len(assistant_ids):
        raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "assistant_ids must not contain duplicate ids")
    return tuple(sorted(assistant_ids))


def _select_team_assistants(
    active: tuple[_ActiveAssistant, ...],
    assistant_ids: tuple[str, ...],
) -> tuple[_ActiveAssistant, ...]:
    active_by_id = {assistant.assistant_id: assistant for assistant in active}
    try:
        return tuple(active_by_id[assistant_id] for assistant_id in assistant_ids)
    except KeyError:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "a selected Assistant is unavailable") from None


def _register_active_power(team_id: str, token: str, container) -> None:
    with runtime_state._active_chat_guard:
        if runtime_state._active_chat_tokens.get(team_id) != token or token in runtime_state._cancelled_chat_tokens:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "brain turn stopped")
        if team_id in runtime_state._active_power_container_ids:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Team already has an active Assistant Power")
        runtime_state._active_power_container_ids[team_id] = (token, container.id)


def _release_active_power(team_id: str, token: str, container_id: str) -> None:
    with runtime_state._active_chat_guard:
        if runtime_state._active_power_container_ids.get(team_id) == (token, container_id):
            runtime_state._active_power_container_ids.pop(team_id, None)


def _register_optional_power(team_id: str, token: str | None, container) -> None:
    if token is not None:
        _register_active_power(team_id, token, container)


def _release_optional_power(team_id: str, token: str | None, container_id: str) -> None:
    if token is not None:
        _release_active_power(team_id, token, container_id)


def _raise_if_rpc_cancelled(token: str | None, exc: BaseException | None = None) -> None:
    if token is not None and runtime_state._token_cancelled(token):
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "brain turn stopped") from exc


def _fail_stop_power(team_id: str, container) -> None:
    """Prove an ambiguous Assistant RPC can no longer execute before returning an error."""
    try:
        hosted_resources._fail_stop_team(container, timeout=3)
    except runtime_state.ApiError as exc:
        with runtime_state._active_chat_guard:
            runtime_state._blocked_power_workloads.add((team_id, container.id))
        raise runtime_state.ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE,
            "Assistant Power termination could not be proved; reinstall the Assistant",
        ) from exc


@dataclass(frozen=True, slots=True)
class AssistantRpcRequest:
    team_id: str
    container: object
    power_id: str
    payload: dict
    token: str | None


def _assistant_rpc_exchange(request: AssistantRpcRequest) -> object:
    team_id = request.team_id
    container = request.container
    token = request.token
    try:
        encoded = power_execution.encode_rpc_invocation(
            request.payload["input"],
            request.payload["accounts"],
        )
    except (KeyError, ValueError) as exc:
        raise runtime_state.ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Power input is too large") from exc
    _register_optional_power(team_id, token, container)

    def close_stream(stream: object) -> None:
        with contextlib.suppress(Exception):
            _close_exec_stream(stream)

    try:
        try:
            return power_execution.rpc_exchange(
                container.id,
                [power_execution.POWER_COMMAND, request.power_id],
                encoded,
                power_execution.RpcExchangeStrategy(
                    api=runtime_state._docker.api,
                    user=power_execution.ASSISTANT_RPC_USER,
                    workdir=manifests.CONTAINER_TMP,
                    timeout=power_execution.RPC_TIMEOUT_SECONDS,
                    maximum=power_execution.MAX_RPC_RESPONSE_BYTES,
                    transport_errors=(docker.errors.DockerException,),
                    fail_stop=lambda: _fail_stop_power(team_id, container),
                    cancelled=lambda exc: _raise_if_rpc_cancelled(token, exc),
                    close_stream=close_stream,
                ),
            )
        except power_execution.RpcExchangeError as exc:
            message = power_execution.rpc_failure_message(exc.kind)[0]
            status = power_execution.rpc_failure_status(exc.kind)
            raise runtime_state.ApiError(status, message) from exc
    finally:
        _release_optional_power(team_id, token, container.id)


def _assistant_rpc(
    team_id: str,
    token: str,
    container,
    power_id: str,
    payload: dict,
) -> object:
    return _assistant_rpc_exchange(
        AssistantRpcRequest(
            team_id=team_id,
            container=container,
            power_id=power_id,
            payload=payload,
            token=token,
        )
    )


def _power_account_generations(
    team_id: str,
    active: _ActiveAssistant,
    power_id: str,
) -> tuple[tuple[str, int], ...]:
    try:
        return power_execution.account_generations(
            active.contract.powers,
            getattr(active.contract, "accounts", {}),
            power_id,
            lambda declarations: runtime_state._assistant_accounts.metadata(
                team_id,
                active.assistant_id,
                declarations,
            ),
        )
    except oauth_account_store.OAuthAccountStoreError as exc:
        raise power_journal.PowerJournalConflictError("Power account state is unavailable") from exc


def _refresh_oauth_account(
    provider: str,
    scopes: tuple[str, ...],
    refresh_token: str,
    _broker_lease: str | None,
) -> object:
    try:
        return runtime_state._oauth_http.refresh(
            provider_id=provider,
            client_id=runtime_state._cloudflare_oauth_client_id,
            client_secret=runtime_state._cloudflare_oauth_client_secret,
            refresh_token=refresh_token,
            scopes=scopes,
        )
    except oauth_http_client.OAuthHTTPError as exc:
        raise oauth_account_store.OAuthAccountReauthorizationError("OAuth account requires reauthorization") from exc


def _resolve_power_accounts(
    team_id: str,
    active: _ActiveAssistant,
    power_id: str,
) -> dict[str, dict[str, str]]:
    try:
        return assistant_account_flow.resolve_power_accounts(
            team_id,
            _hosted_account_spec(active),
            power_id,
            runtime_state._assistant_accounts,
            _refresh_oauth_account,
        )
    except assistant_account_flow.AccountFlowError as exc:
        raise runtime_state.ApiError(
            power_execution.ACCOUNT_PRECONDITION_STATUS, "Assistant account is unavailable"
        ) from exc


def _require_hosted_power_rpc_envelope(
    team_id: str,
    bindings: dict[str, _ActiveAssistant],
    request: brain_runtime_client.PowerRequest,
) -> Mapping[str, Mapping[str, object]]:
    active = bindings.get(request.assistant_id)
    if active is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Brain requested an unavailable Assistant")
    try:
        return power_execution.require_rpc_envelope(
            active,
            request,
            lambda binding, power_id: _resolve_power_accounts(team_id, binding, power_id),
        )
    except ValueError as exc:
        raise runtime_state.ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Assistant Power input is too large") from exc


def _assistant_account_inventory(
    team_id: str,
    lease: hosted_resources._AuthorizationLease,
) -> dict[str, object]:
    with runtime_state._lock_for(team_id):
        hosted_resources._require_current_authorization(team_id, lease, require_isolation=False)
        try:
            payload = assistant_account_flow.inventory_payload(
                team_id,
                _installed_assistant_specs(team_id),
                runtime_state._assistant_accounts,
            )
        except oauth_account_store.OAuthAccountStoreError as exc:
            raise runtime_state.ApiError(
                HTTPStatus.SERVICE_UNAVAILABLE, "Assistant account state is unavailable"
            ) from exc
        except assistant_account_flow.AccountFlowError as exc:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Assistant account contract is unavailable") from exc
    return {"team_id": team_id, **payload}


def _installed_assistant_specs(team_id: str) -> tuple[_HostedAssistantSpec, ...]:
    specs: list[_HostedAssistantSpec] = []
    seen: set[str] = set()
    try:
        containers = hosted_apps._team_app_containers(team_id)
    except docker.errors.DockerException as exc:
        raise runtime_state.ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE, "installed Assistants could not be listed"
        ) from exc
    for container in containers:
        assistant_id = (container.labels or {}).get("team.app")
        if not isinstance(assistant_id, str):
            continue
        try:
            _resolved_id, app_spec = hosted_apps._resolve_team_app(team_id, assistant_id)
        except marketplace.MarketplaceError:
            continue
        if app_spec.assistant is None:
            continue
        if assistant_id in seen:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "duplicate installed Assistant identity")
        seen.add(assistant_id)
        specs.append(_hosted_account_spec(_ActiveAssistant(assistant_id, app_spec.assistant, container)))
    return tuple(specs)


@dataclass(frozen=True, slots=True)
class PowerInvocationRequest:
    team_id: str
    token: str
    assistant_id: str
    contract: marketplace.AssistantContract
    container: object
    power: object
    payload: object
    inspect_memo: dict[str, object] | None = None
    validated_assistant: _ActiveAssistant | None = None
    account_values: Mapping[str, Mapping[str, object]] | None = None


def _invoke_assistant_power(request: PowerInvocationRequest) -> dict[str, object]:
    team_id = request.team_id
    assistant_id = request.assistant_id
    contract = request.contract
    container = request.container
    power = request.power
    if (
        not isinstance(power, str)
        or assistant_chat.POWER_ID_RE.fullmatch(power) is None
        or power not in contract.powers
    ):
        raise runtime_state.ApiError(power_execution.UNDECLARED_POWER_STATUS, "Assistant requested an undeclared Power")
    try:
        safe_input = _validate_power_payload(contract, power, request.payload, output=False)
    except ValueError as exc:
        raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)) from exc
    validated = request.validated_assistant
    if validated is None:
        _current_id, current_contract, current_container = _installed_assistant(
            team_id,
            assistant_id,
            request.inspect_memo,
        )
    else:
        _current_id = validated.assistant_id
        current_contract = validated.contract
        current_container = validated.container
    if (
        _current_id != assistant_id
        or current_contract != contract
        or current_container.id != container.id
    ):
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "installed Assistant changed during the chat turn")
    active = _ActiveAssistant(assistant_id, contract, container)
    account_values = (
        _resolve_power_accounts(team_id, active, power)
        if request.account_values is None
        else dict(request.account_values)
    )
    audit.log(
        "assistant_power",
        team_id,
        result="ok",
        phase="started",
        assistant=assistant_id,
        power=power,
    )
    try:
        raw_result = _assistant_rpc(
            team_id,
            request.token,
            container,
            power,
            {
                "input": safe_input,
                "accounts": power_execution.account_access_tokens(account_values),
            },
        )
    except runtime_state.ApiError as exc:
        audit.log(
            "assistant_power",
            team_id,
            result="error",
            assistant=assistant_id,
            power=power,
            status=int(exc.status),
        )
        raise
    try:
        projected = power_execution.project_rpc_result(
            raw_result,
            account_values,
            lambda value: _validate_power_payload(contract, power, value, output=True),
        )
    except power_execution.RpcSecretExposureError:
        audit.log(
            "assistant_power",
            team_id,
            result="error",
            assistant=assistant_id,
            power=power,
            reason="secret-exposure",
        )
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "Assistant Power exposed protected data") from None
    except power_execution.RpcInvalidResultError as exc:
        audit.log(
            "assistant_power",
            team_id,
            result="error",
            assistant=assistant_id,
            power=power,
            reason="invalid-output",
        )
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "Assistant Power returned an invalid result") from exc
    audit.log(
        "assistant_power",
        team_id,
        result="ok",
        phase="completed",
        assistant=assistant_id,
        power=power,
    )
    return {"assistant": assistant_id, "power": power, "result": projected}


def _validate_assistant_power_input(bindings, assistant_id: str, power: str, power_input) -> object:
    """Normalize one hosted Power input without touching Docker or another external system."""
    active = bindings.get(assistant_id)
    if active is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Brain requested an unavailable Assistant")
    try:
        return _validate_power_payload(active.contract, power, power_input, output=False)
    except ValueError as exc:
        raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc)) from exc


def _validate_power_payload(
    contract: marketplace.AssistantContract,
    power_id: str,
    payload: object,
    *,
    output: bool,
) -> dict[str, object]:
    power = contract.powers.get(power_id)
    if power is None:
        raise ValueError("the Power has no declared contract")
    schema = power.output_schema if output else power.input_schema
    return assistant_manifest.validate_schema_payload(
        Draft202012Validator(schema),
        payload,
    )


def _validate_chat_file_ids(file_ids: object) -> list[object]:
    if file_ids is None:
        return []
    if not isinstance(file_ids, list) or len(file_ids) > MAX_CHAT_FILES:
        raise runtime_state.ApiError(HTTPStatus.BAD_REQUEST, f"files must contain at most {MAX_CHAT_FILES} opaque ids")
    return file_ids


def _raise_chat_storage_error(exc: team_storage.StorageError) -> NoReturn:
    if isinstance(exc, team_storage.StorageNotFoundError):
        raise runtime_state.ApiError(HTTPStatus.NOT_FOUND, "selected file not found in this Team") from exc
    if isinstance(exc, team_storage.StorageInputError):
        raise runtime_state.ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
    raise runtime_state.ApiError(HTTPStatus.SERVICE_UNAVAILABLE, "Team storage failed its safety checks") from exc


@contextlib.contextmanager
def _chat_file_metadata_connection(team_id: str, file_ids: object):
    safe_ids = _validate_chat_file_ids(file_ids)
    if not safe_ids:
        yield None
        return
    try:
        with runtime_state._storage().metadata_connection(team_id, safe_ids) as reader:
            yield reader
    except team_storage.StorageError as exc:
        _raise_chat_storage_error(exc)


def _chat_file_metadata(
    team_id: str,
    file_ids: object,
    metadata_connection=None,
) -> list[dict[str, object]]:
    safe_ids = _validate_chat_file_ids(file_ids)
    try:
        return runtime_state._storage().metadata(team_id, safe_ids, metadata_connection)
    except team_storage.StorageError as exc:
        _raise_chat_storage_error(exc)


def _model_credential(
    owner: str,
    provider: str,
    credential_session: brain_credentials_client.BrainCredentialSession | None = None,
) -> tuple[str, int]:
    if not owner:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "this Team has no account owner for model credentials")
    try:
        credential = brain_credentials_client.resolve(owner, provider, credential_session)
    except brain_credentials_client.BrainCredentialError as exc:
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "model credential service is unavailable") from exc
    if credential is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, f"configure the {provider!r} API key before chatting")
    auth_type, api_key, generation = credential
    if auth_type != "api_key":
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "the selected model provider requires an API key")
    return api_key, generation


def _require_model_credential_current(
    owner: str,
    provider: str,
    generation: int,
    credential_session: brain_credentials_client.BrainCredentialSession | None = None,
) -> None:
    try:
        current = brain_credentials_client.generation_is_current(owner, provider, generation, credential_session)
    except brain_credentials_client.BrainCredentialError as exc:
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "model credential could not be verified") from exc
    if not current:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "model credential changed or was revoked; retry")
