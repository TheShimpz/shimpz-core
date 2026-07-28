"""Local chat suspension and challenge response operations."""

from http import HTTPStatus

import chat_orchestrator
import chat_turn_engine
from assistant_human import assistant_account_challenges, assistant_account_flow

from local_support.chat_types import ActiveAssistant as _ActiveAssistant
from local_support.chat_types import PendingLocalChat as _PendingLocalChat
from local_support.errors import ApiProblemError as ApiProblem


def _commit_suspension(
    self,
    team_id: str,
    token: str,
    outcome: chat_orchestrator.ChatSuspension,
    payload: _PendingLocalChat,
    challenge_store: object,
    challenge_id: str,
) -> None:
    chat_turn_engine.commit_suspension(
        outcome.continuation,
        payload.continuation,
        lambda: self._commit_chat_terminal(team_id, token),
        lambda: challenge_store.cancel_team(team_id),
        lambda: ApiProblem(HTTPStatus.CONFLICT, "chat turn stopped", code="chat-stopped"),
        lambda: self._delete_chat_continuation(team_id, challenge_id),
    )


def _account_response(
    self,
    challenge: assistant_account_challenges.PendingAccountChallenge,
) -> dict[str, object]:
    bindings: dict[str, _ActiveAssistant] = {}
    for requirement in challenge.requirements:
        spec = self.assistant_lifecycle._resolve(requirement.assistant_id)
        bindings[spec.assistant_id] = _ActiveAssistant(spec, "")
    try:
        return assistant_account_flow.challenge_payload(challenge, bindings)
    except assistant_account_flow.AccountFlowError as exc:
        raise ApiProblem(
            HTTPStatus.CONFLICT,
            "Assistant account contract changed; retry the message",
            code="assistant-account-contract-invalid",
        ) from exc


def _pause_account(
    self,
    team_id: str,
    token: str,
    outcome: chat_orchestrator.ChatSuspension,
    requirements: tuple[assistant_account_challenges.AccountRequirement, ...],
    payload: _PendingLocalChat,
) -> dict[str, object]:
    try:
        challenge = self.account_challenges.create(team_id, requirements, payload)
    except assistant_account_challenges.AccountChallengeError as exc:
        raise ApiProblem(
            HTTPStatus.CONFLICT,
            "Assistant account request is already pending",
            code="assistant-account-challenge-conflict",
        ) from exc
    try:
        self._persist_chat_continuation("accounts", challenge, requirements, payload)
    except ApiProblem:
        self.account_challenges.cancel_team(team_id)
        raise
    self._commit_suspension(team_id, token, outcome, payload, self.account_challenges, challenge.id)
    return self._account_response(challenge)
