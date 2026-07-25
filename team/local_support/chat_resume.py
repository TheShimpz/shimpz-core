"""Local chat stop API operation."""

from local_support.validation import validate_team_id


def stop_chat(self, team_id: str) -> dict[str, object]:
    team_id = validate_team_id(team_id)
    self.assistant_lifecycle._network(team_id)
    account_cancelled = self.account_challenges.cancel_team(team_id)
    self.oauth_pkce.cancel_team(team_id)
    continuation_cancelled = self._delete_chat_continuation(team_id)
    power_stopped = False
    with self._active_chat_guard:
        token = self._active_chat_tokens.get(team_id)
        if token is not None:
            self._cancelled_chat_tokens.add(token)
        active = self._active_power_containers.get(team_id)
        if token is not None and active is not None and active[0] == token:
            self.assistant_lifecycle._fail_stop_power(active[1])
            power_stopped = True
    accepted = token is not None or account_cancelled or continuation_cancelled
    return {
        "team_id": team_id,
        "requested": accepted,
        "accepted": accepted,
        "confirmed": power_stopped,
        "forced_restart": False,
    }
