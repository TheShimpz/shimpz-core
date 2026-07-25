"""Local Assistant Account configuration operations."""

from http import HTTPStatus
from typing import NoReturn

import assistant_account_challenges
import assistant_account_flow
import brain_runtime_client
import oauth_account_service
import oauth_account_store
import power_execution
import power_journal
from docker.errors import DockerException
from local_registry import AssistantSpec

from local_support.chat_types import ActiveAssistant as _ActiveAssistant
from local_support.chat_types import required_active_assistant as _required_active_assistant
from local_support.errors import ApiProblemError as ApiProblem
from local_support.validation import validate_team_id


def _power_account_generations(
    self,
    team_id: str,
    active: _ActiveAssistant,
    power_id: str,
) -> tuple[tuple[str, int], ...]:
    try:
        return power_execution.account_generations(
            active.spec.powers,
            active.spec.accounts,
            power_id,
            lambda declarations: self.assistant_accounts.metadata(
                team_id,
                active.spec.assistant_id,
                declarations,
            ),
        )
    except oauth_account_store.OAuthAccountStoreError as exc:
        raise power_journal.PowerJournalConflictError("Power account state is unavailable") from exc


def _refresh_oauth_account(
    self,
    provider: str,
    scopes: tuple[str, ...],
    refresh_token: str,
    broker_lease: str | None,
) -> object:
    return self.oauth_service.refresh(
        provider,
        scopes,
        refresh_token,
        broker_lease,
    )


def _resolve_power_accounts(
    self,
    team_id: str,
    spec: AssistantSpec,
    power_id: str,
) -> dict[str, dict[str, str]]:
    try:
        return assistant_account_flow.resolve_power_accounts(
            team_id,
            spec,
            power_id,
            self.assistant_accounts,
            self._refresh_oauth_account,
        )
    except assistant_account_flow.AccountFlowError as exc:
        raise ApiProblem(
            power_execution.ACCOUNT_PRECONDITION_STATUS,
            "Assistant account is unavailable",
            code="assistant-account-unavailable",
        ) from exc


def _require_power_rpc_envelope(
    self,
    team_id: str,
    bindings: dict[str, _ActiveAssistant],
    request: brain_runtime_client.PowerRequest,
) -> None:
    active = _required_active_assistant(bindings, request.assistant_id)
    try:
        power_execution.require_rpc_envelope(
            active,
            request,
            lambda binding, power_id: self._resolve_power_accounts(team_id, binding.spec, power_id),
        )
    except ValueError as exc:
        raise ApiProblem(
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            "Assistant Power input is too large",
            code="assistant-power-input-too-large",
        ) from exc


def _raise_account_problem(exc: oauth_account_store.OAuthAccountStoreError) -> NoReturn:
    raise ApiProblem(
        HTTPStatus.SERVICE_UNAVAILABLE,
        "Assistant account state is unavailable",
        code="assistant-account-state-unavailable",
    ) from exc


def list_assistant_accounts(self, team_id: str) -> dict[str, object]:
    team_id = validate_team_id(team_id)
    with self._lock(team_id):
        specs = [
            self.assistant_lifecycle._resolve(assistant_id)
            for assistant_id in self.assistant_lifecycle._assistant_ids(team_id)
        ]
        try:
            payload = assistant_account_flow.inventory_payload(
                team_id,
                specs,
                self.assistant_accounts,
            )
        except oauth_account_store.OAuthAccountStoreError as exc:
            self._raise_account_problem(exc)
        except assistant_account_flow.AccountFlowError as exc:
            raise ApiProblem(
                HTTPStatus.CONFLICT,
                "Assistant account contract is unavailable",
                code="assistant-account-contract-invalid",
            ) from exc
    return {"team_id": team_id, **payload}


def start_assistant_account_authorization(
    self,
    team_id: object,
    challenge_id: object,
    session_binding: object,
) -> dict[str, object]:
    try:
        challenge = self.account_challenges.get(team_id, challenge_id)
        authorization_url = self.oauth_service.authorization_url(
            challenge,
            session_binding,
        )
    except assistant_account_challenges.AccountChallengeError as exc:
        raise ApiProblem(
            HTTPStatus.CONFLICT,
            "Assistant account request expired; retry the message",
            code="assistant-account-challenge-expired",
        ) from exc
    except oauth_account_service.OAuthAccountServiceError as exc:
        raise ApiProblem(
            HTTPStatus.BAD_GATEWAY,
            "Assistant account authorization is unavailable",
            code="assistant-account-oauth-unavailable",
        ) from exc
    return {"authorization_url": authorization_url}


def _current_account_declaration(
    self,
    team_id: str,
    assistant_id: str,
    account_id: str,
) -> object:
    with self._lock(team_id):
        spec = self.assistant_lifecycle._resolve(assistant_id)
        declaration = spec.accounts.get(account_id)
        if (
            assistant_id not in self.assistant_lifecycle._assistant_ids(team_id, running_only=True)
            or declaration is None
        ):
            raise oauth_account_service.OAuthAccountDeclarationError("OAuth account declaration is unavailable")
        try:
            container = self.assistant_lifecycle._assistant_container(team_id, assistant_id)
            container.reload()
        except (ApiProblem, DockerException) as exc:
            raise oauth_account_service.OAuthAccountDeclarationError(
                "OAuth account declaration is unavailable"
            ) from exc
        attrs = container.attrs if isinstance(container.attrs, dict) else {}
        config = attrs.get("Config")
        if not isinstance(config, dict) or not self.assistant_lifecycle._has_current_assistant_artifact(config, spec):
            raise oauth_account_service.OAuthAccountDeclarationError("OAuth account declaration is unavailable")
        return declaration


def complete_cloudflare_oauth_callback(
    self,
    *,
    state: object,
    claim: object,
    session_binding: object,
) -> dict[str, object]:
    try:
        completed = self.oauth_service.complete(
            state,
            claim,
            session_binding,
            self._current_account_declaration,
        )
    except oauth_account_service.OAuthAccountServiceError as exc:
        raise ApiProblem(
            HTTPStatus.BAD_GATEWAY,
            "Assistant account authorization could not be completed",
            code="assistant-account-oauth-unavailable",
        ) from exc
    return {
        "connected": True,
        "team_id": completed.team_id,
        "assistant_id": completed.assistant_id,
        "account_id": completed.account_id,
    }


def disconnect_assistant_account(
    self,
    team_id: object,
    assistant_id: object,
    account_id: object,
) -> dict[str, object]:
    try:
        disconnected = self.oauth_service.disconnect(
            team_id,
            assistant_id,
            account_id,
        )
    except oauth_account_service.OAuthAccountServiceError as exc:
        raise ApiProblem(
            HTTPStatus.BAD_GATEWAY,
            "Assistant account could not be disconnected",
            code="assistant-account-oauth-unavailable",
        ) from exc
    return {"disconnected": disconnected}


def pending_chat_accounts(self, team_id: str) -> dict[str, object]:
    team_id = validate_team_id(team_id)
    self.assistant_lifecycle._network(team_id)
    challenge = self.account_challenges.current(team_id)
    return self._account_response(challenge) if challenge is not None else {"team_id": team_id, "status": "none"}
