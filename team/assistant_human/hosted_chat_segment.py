"""Hosted Team chat segment preparation, execution, and suspension dispatch."""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import NoReturn

import assistant_account_challenges
import assistant_account_flow
import brain_runtime_client
import chat_orchestrator
import chat_turn_engine
import inference_config
import manifests
import marketplace
import oauth_account_store
import power_execution
import power_journal
from container_policy import hosted_apps, hosted_resources
from container_policy import network as network_policy
from http_boundary import runtime_state

from assistant_human import hosted_assistants


def _current_team_anchor(
    team_id: str,
    container_id: str,
    owner: str,
    inspect_memo: dict[str, object] | None = None,
):
    container = hosted_resources._get_container(manifests.team_container_name(team_id))
    if container is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Team identity changed during the chat turn")
    if (
        container.id != container_id
        or not network_policy.brain_identity_valid(container.attrs, team_id)
        or str(container.labels.get("team.owner", "")) != owner
    ):
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Team identity changed during the chat turn")
    hosted_resources._require_running_team_isolation(container, inspect_memo, refreshed=True)
    return container


def _hosted_chat_setup(
    team_id: str,
    file_ids: object,
    assistant_ids: tuple[str, ...],
    container,
    owner: str,
    metadata_connection=None,
    credential_session=None,
) -> tuple[
    str,
    tuple[hosted_assistants._ActiveAssistant, ...],
    list[dict[str, object]],
    inference_config.InferenceConfig,
    str,
    int,
    tuple[object, ...],
]:
    team_name = hosted_resources._team_name_from_anchor(container)
    assistants = hosted_assistants._select_team_assistants(
        hosted_assistants._active_team_assistants(team_id), assistant_ids
    )
    files = hosted_assistants._chat_file_metadata(team_id, file_ids, metadata_connection)
    try:
        config = runtime_state._inference_store.load(team_id)
    except inference_config.InferenceConfigError as exc:
        raise runtime_state.ApiError(
            HTTPStatus.CONFLICT, "configure this Team's model provider before chatting"
        ) from exc
    api_key, generation = hosted_assistants._model_credential(owner, config.provider, credential_session)
    identity = (
        container.id,
        owner,
        team_name,
        tuple((active.assistant_id, active.container.id) for active in assistants),
        files,
        config,
        generation,
    )
    return team_name, assistants, files, config, api_key, generation, identity


def _raise_hosted_chat_problem(reason: str, exc: BaseException | None) -> NoReturn:
    if reason == "invalid-continuation" or reason == "invalid-suspension":
        raise runtime_state.ApiError(
            HTTPStatus.INTERNAL_SERVER_ERROR, f"invalid chat {reason.removeprefix('invalid-')}"
        )
    if reason == "context-changed":
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Team capabilities changed; retry")
    if isinstance(exc, power_journal.PowerJournalError):
        raise runtime_state.ApiError(
            HTTPStatus.SERVICE_UNAVAILABLE, "Team Power execution state is unavailable"
        ) from exc
    if isinstance(exc, chat_orchestrator.ChatStoppedError):
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "brain turn stopped") from exc
    if isinstance(exc, chat_orchestrator.ChatOrchestrationError):
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "Brain could not complete the Assistant turn") from exc
    if isinstance(exc, brain_runtime_client.BrainRuntimeError):
        raise runtime_state.ApiError(HTTPStatus.BAD_GATEWAY, "Brain runtime is unavailable") from exc
    raise AssertionError(f"unknown hosted chat failure: {reason}")


def _hosted_private_requirements(
    team_id: str,
    bindings: dict[str, hosted_assistants._ActiveAssistant],
    requests: tuple[brain_runtime_client.PowerRequest, ...],
) -> tuple[assistant_account_challenges.AccountRequirement, ...]:
    try:
        return assistant_account_flow.requirements_for_batch(
            team_id,
            hosted_assistants._account_bindings(bindings),
            requests,
            runtime_state._assistant_accounts,
        )
    except (
        assistant_account_flow.AccountFlowError,
        oauth_account_store.OAuthAccountStoreError,
    ) as exc:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Assistant account contract is unavailable") from exc


@dataclass(frozen=True, slots=True)
class HostedChatSegmentRequest:
    team_id: str
    file_ids: object
    assistant_ids: tuple[str, ...]
    token: str
    container: object
    owner: str
    message: str | None = None
    continuation: chat_orchestrator.ChatContinuation | None = None
    expected_identity: tuple[object, ...] | None = None


def _hosted_chat_current_identity(
    request: HostedChatSegmentRequest,
    assistants: tuple[hosted_assistants._ActiveAssistant, ...],
    config: inference_config.InferenceConfig | None,
    generation: int,
    inspect_memo: dict[str, object],
    metadata_connection=None,
    credential_session=None,
) -> tuple[object, ...]:
    if config is None:
        raise AssertionError("hosted chat segment was not prepared")
    current_anchor = _current_team_anchor(
        request.team_id,
        request.container.id,
        request.owner,
        inspect_memo,
    )
    team_name = hosted_resources._team_name_from_anchor(current_anchor)
    dynamic_bindings = hosted_apps._dynamic_binding_snapshot(
        request.team_id,
        tuple(active.assistant_id for active in assistants),
    )
    egress_store = hosted_apps._egress_store() if assistants else None
    current_assistants = tuple(
        hosted_assistants._installed_assistant(
            request.team_id,
            active.assistant_id,
            inspect_memo,
            dynamic_bindings=dynamic_bindings,
            egress_store=egress_store,
        )[2]
        for active in assistants
    )
    files = hosted_assistants._chat_file_metadata(request.team_id, request.file_ids, metadata_connection)
    try:
        current_config = runtime_state._inference_store.load(request.team_id)
    except inference_config.InferenceConfigError as exc:
        raise runtime_state.ApiError(
            HTTPStatus.CONFLICT, "configure this Team's model provider before chatting"
        ) from exc
    hosted_assistants._require_model_credential_current(
        request.owner,
        config.provider,
        generation,
        credential_session,
    )
    return (
        current_anchor.id,
        request.owner,
        team_name,
        tuple(
            (active.assistant_id, container.id)
            for active, container in zip(assistants, current_assistants, strict=True)
        ),
        files,
        current_config,
        generation,
    )


def _execute_hosted_power(
    team_id: str,
    token: str,
    bindings: dict[str, hosted_assistants._ActiveAssistant],
    inspect_memo: dict[str, object],
    request: brain_runtime_client.PowerRequest,
) -> object:
    active = bindings.get(request.assistant_id)
    if active is None:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Brain requested an unavailable Assistant")
    invocation = hosted_assistants._invoke_assistant_power(
        hosted_assistants.PowerInvocationRequest(
            team_id=team_id,
            token=token,
            assistant_id=request.assistant_id,
            contract=active.contract,
            container=active.container,
            power=request.power,
            payload=request.input,
            inspect_memo=inspect_memo,
        )
    )
    return invocation["result"]


def _run_hosted_chat_segment(request: HostedChatSegmentRequest) -> chat_turn_engine.SegmentResult:
    with (
        hosted_assistants.brain_credentials_client.BrainCredentialSession() as credential_session,
        hosted_assistants._chat_file_metadata_connection(request.team_id, request.file_ids) as metadata_connection,
    ):
        return _run_hosted_chat_segment_with_metadata(request, metadata_connection, credential_session)


def _run_hosted_chat_segment_with_metadata(
    request: HostedChatSegmentRequest,
    metadata_connection,
    credential_session,
) -> chat_turn_engine.SegmentResult:
    team_id, assistant_ids, token, container, owner = (
        request.team_id,
        request.assistant_ids,
        request.token,
        request.container,
        request.owner,
    )
    bindings: dict[str, hosted_assistants._ActiveAssistant] = {}
    initial_identity: tuple[object, ...] = ()
    config: inference_config.InferenceConfig | None = None
    generation = 0
    prepared_assistants: tuple[hosted_assistants._ActiveAssistant, ...] = ()
    inspect_memo: dict[str, object] = {}
    credential_evidence = False

    def validate_power(assistant_id: str, power: str, power_input) -> object:
        return hosted_assistants._validate_assistant_power_input(bindings, assistant_id, power, power_input)

    def execute_power(request: brain_runtime_client.PowerRequest) -> object:
        nonlocal credential_evidence
        if not credential_evidence:
            raise AssertionError("hosted Power lacks fresh credential evidence")
        credential_evidence = False
        return _execute_hosted_power(team_id, token, bindings, inspect_memo, request)

    def prepare() -> chat_turn_engine.PreparedSegment:
        nonlocal bindings, config, generation, initial_identity, prepared_assistants
        team_name, prepared_assistants, files, config, api_key, generation, initial_identity = _hosted_chat_setup(
            team_id,
            request.file_ids,
            assistant_ids,
            container,
            owner,
            metadata_connection,
            credential_session,
        )
        genesis_by_id = {
            active.assistant_id: hosted_apps._require_assistant_genesis(active.container)
            for active in prepared_assistants
        }
        context = brain_runtime_client.RuntimeContext(
            thread_id=hosted_resources._brain_thread_id(team_id, container.id),
            team_name=team_name,
            assistants=tuple(
                brain_runtime_client.RuntimeAssistant(
                    id=active.assistant_id,
                    genesis=genesis_by_id[active.assistant_id],
                    powers=tuple(
                        brain_runtime_client.RuntimePower(
                            id=power_id,
                            summary=power.summary,
                            input_schema=power.input_schema,
                        )
                        for power_id, power in sorted(active.contract.powers.items())
                    ),
                )
                for active in prepared_assistants
            ),
            provider=config.provider,
            model=config.model,
            api_key=api_key,
        )
        bindings = {active.assistant_id: active for active in prepared_assistants}
        batch = power_execution.PowerBatch(
            runtime_state._power_execution_journal,
            container.id,
            context.thread_id,
            bindings,
            power_execution.PowerBatchStrategy(
                hosted_assistants._hosted_power_identity,
                execute_power,
                lambda request: hosted_assistants._require_hosted_power_rpc_envelope(
                    team_id,
                    bindings,
                    request,
                ),
                lambda request: hosted_assistants._power_account_generations(
                    team_id, bindings[request.assistant_id], request.power
                ),
            ),
        )
        return chat_turn_engine.PreparedSegment(team_name, initial_identity, context, files, batch)

    def pause_for_private_inputs(
        requests: tuple[object, ...],
        requirements: chat_turn_engine.SegmentRequirements,
    ) -> bool:
        requirements.accounts = _hosted_private_requirements(
            team_id,
            bindings,
            requests,
        )
        return bool(requirements.accounts)

    def validate_context() -> None:
        nonlocal credential_evidence, inspect_memo
        inspect_memo = {}
        current_identity = _hosted_chat_current_identity(
            request,
            prepared_assistants,
            config,
            generation,
            inspect_memo,
            metadata_connection,
            credential_session,
        )
        if current_identity != initial_identity:
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Team capabilities changed; retry")
        credential_evidence = True

    team_name, identity, outcome, requirements = chat_turn_engine.run_segment(
        chat_turn_engine.SegmentStrategy(
            runtime=runtime_state._brain_runtime,
            prepare=prepare,
            validate_power=validate_power,
            pause_for_private_inputs=pause_for_private_inputs,
            cancelled=lambda: runtime_state._token_cancelled(token),
            validate_context=validate_context,
            raise_problem=_raise_hosted_chat_problem,
        ),
        message=request.message,
        continuation=request.continuation,
        expected_identity=request.expected_identity,
    )
    return chat_turn_engine.SegmentResult(
        team_name,
        identity,
        outcome,
        requirements.accounts,
    )


def _commit_hosted_suspension(
    team_id: str,
    token: str,
    outcome: chat_orchestrator.ChatSuspension,
    pending: hosted_assistants._PendingHostedChat,
    challenge_store: object,
) -> None:
    chat_turn_engine.commit_suspension(
        outcome.continuation,
        pending.continuation,
        lambda: runtime_state._commit_chat_terminal(team_id, token),
        lambda: challenge_store.cancel_team(team_id),
        lambda: runtime_state.ApiError(HTTPStatus.CONFLICT, "brain turn stopped"),
    )


def _hosted_account_challenge_payload(
    challenge: assistant_account_challenges.PendingAccountChallenge,
) -> dict[str, object]:
    bindings: dict[str, hosted_assistants._HostedAssistantBinding] = {}
    try:
        for requirement in challenge.requirements:
            assistant_id, contract, container = hosted_assistants._installed_assistant(
                challenge.team_id,
                requirement.assistant_id,
            )
            active = hosted_assistants._ActiveAssistant(assistant_id, contract, container)
            bindings[assistant_id] = hosted_assistants._HostedAssistantBinding(
                hosted_assistants._hosted_account_spec(active)
            )
        return assistant_account_flow.challenge_payload(challenge, bindings)
    except (marketplace.MarketplaceError, assistant_account_flow.AccountFlowError) as exc:
        raise runtime_state.ApiError(
            HTTPStatus.CONFLICT, "Assistant account contract changed; retry the message"
        ) from exc


def _pause_hosted_connection(
    team_id: str,
    token: str,
    outcome: chat_orchestrator.ChatSuspension,
    requirements: tuple[assistant_account_challenges.AccountRequirement, ...],
    pending: hosted_assistants._PendingHostedChat,
) -> dict[str, object]:
    try:
        challenge = runtime_state._assistant_account_challenges.create(team_id, requirements, pending)
    except assistant_account_challenges.AccountChallengeError as exc:
        raise runtime_state.ApiError(HTTPStatus.CONFLICT, "Assistant account request is already pending") from exc
    _commit_hosted_suspension(team_id, token, outcome, pending, runtime_state._assistant_account_challenges)
    return _hosted_account_challenge_payload(challenge)


def _hosted_segment_response(
    team_id: str,
    token: str,
    segment: chat_turn_engine.SegmentResult,
    assistant_ids: tuple[str, ...],
    file_ids: tuple[str, ...],
    owner: str,
) -> dict[str, object]:
    def pending(suspension: chat_orchestrator.ChatSuspension) -> hosted_assistants._PendingHostedChat:
        return hosted_assistants._PendingHostedChat(
            continuation=suspension.continuation,
            assistant_ids=assistant_ids,
            file_ids=file_ids,
            owner=owner,
            identity=segment.identity,
        )

    def complete(terminal: chat_orchestrator.ChatOutcome) -> dict[str, object]:
        if not runtime_state._commit_chat_terminal(team_id, token):
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "brain turn stopped")
        return {
            "team_id": team_id,
            "team_name": segment.team_name,
            "reply": terminal.reply[: hosted_assistants.CHAT_OUTPUT_CAP],
        }

    try:
        return chat_turn_engine.dispatch(
            segment.outcome,
            segment.requirement_groups(),
            pending,
            (
                lambda suspension, requirements, state: _pause_hosted_connection(
                    team_id, token, suspension, requirements, state
                ),
            ),
            complete,
        )
    except ValueError as exc:
        raise runtime_state.ApiError(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc)) from exc


def _chat_in_turn(
    team_id: str,
    message: str,
    file_ids: object,
    assistant_ids: tuple[str, ...],
    token: str,
    container,
    owner: str,
) -> dict[str, object]:
    segment = _run_hosted_chat_segment(
        HostedChatSegmentRequest(
            team_id=team_id,
            file_ids=file_ids,
            assistant_ids=assistant_ids,
            token=token,
            container=container,
            owner=owner,
            message=message,
        )
    )
    return _hosted_segment_response(
        team_id,
        token,
        segment,
        assistant_ids,
        tuple(file_ids) if isinstance(file_ids, list) else (),
        owner,
    )
