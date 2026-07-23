"""Canonical method/path matching for hosted and local Team Controllers."""

from __future__ import annotations

from dataclasses import dataclass

HOSTED = "hosted"
LOCAL = "local"
_BOTH = frozenset({HOSTED, LOCAL})


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    pattern: tuple[str, ...]
    operation: str
    profiles: frozenset[str] = _BOTH


@dataclass(frozen=True, slots=True)
class RouteMatch:
    operation: str
    params: dict[str, str]

    @property
    def group(self) -> str | None:
        fixed = {"health", "registry-list", "team-list", "space-reset", "assistant-account-complete"}
        if self.operation in fixed:
            return "fixed"
        if self.operation in {"team-create", "team-destroy"}:
            return "team"
        for prefix, group in (
            ("file-", "file"),
            ("inference-", "inference"),
            ("chat-", "chat"),
            ("assistant-secret-", "assistant-secret"),
            ("assistant-approval-", "assistant-approval"),
            ("assistant-account-", "assistant-account"),
        ):
            if self.operation.startswith(prefix):
                return group
        return "chat" if self.operation == "chat" else None


def _route(
    method: str,
    path: str,
    operation: str,
    profiles: frozenset[str] = _BOTH,
) -> Route:
    return Route(method, tuple(part for part in path.split("/") if part), operation, profiles)


_HOSTED = frozenset({HOSTED})
_LOCAL = frozenset({LOCAL})
ROUTES = (
    _route("GET", "/v1/teams", "team-list"),
    _route("POST", "/v1/oauth/cloudflare/callback", "assistant-account-complete"),
    _route("POST", "/v1/teams/:team_id/create", "team-create"),
    _route("DELETE", "/v1/teams/:team_id", "team-destroy"),
    _route("GET", "/v1/teams/:team_id/files", "file-list"),
    _route("POST", "/v1/teams/:team_id/files", "file-upload"),
    _route("DELETE", "/v1/teams/:team_id/files/:file_id", "file-delete"),
    _route("GET", "/v1/teams/:team_id/inference", "inference-status"),
    _route("PUT", "/v1/teams/:team_id/inference", "inference-configure"),
    _route("POST", "/v1/teams/:team_id/chat", "chat"),
    _route("GET", "/v1/teams/:team_id/chat/accounts", "chat-account-pending"),
    _route("POST", "/v1/teams/:team_id/chat/accounts", "chat-account-submit"),
    _route("GET", "/v1/teams/:team_id/chat/secrets", "chat-secret-pending"),
    _route("POST", "/v1/teams/:team_id/chat/secrets", "chat-secret-submit"),
    _route("POST", "/v1/teams/:team_id/chat/stop", "chat-stop"),
    _route("GET", "/v1/teams/:team_id/assistant-secrets", "assistant-secret-list"),
    _route("PUT", "/v1/teams/:team_id/assistant-secrets", "assistant-secret-replace"),
    _route("GET", "/v1/teams/:team_id/assistant-accounts", "assistant-account-list"),
    _route(
        "POST",
        "/v1/teams/:team_id/assistant-accounts/challenges/:challenge_id/authorize",
        "assistant-account-authorize",
    ),
    _route(
        "DELETE",
        "/v1/teams/:team_id/assistant-accounts/:assistant_id/:account_id",
        "assistant-account-disconnect",
    ),
    _route("GET", "/v1/teams/:team_id/assistants/:assistant_id/help", "assistant-help"),
    _route("GET", "/v1/teams/:team_id/assistants/:assistant_id/help/:locale", "assistant-help"),
    _route("POST", "/v1/teams/:team_id/chat/stream", "chat-stream", _HOSTED),
    _route("GET", "/v1/teams/:team_id/apps", "app-list", _HOSTED),
    _route("POST", "/v1/teams/:team_id/apps", "app-install", _HOSTED),
    _route("DELETE", "/v1/teams/:team_id/apps/:app_id", "app-uninstall", _HOSTED),
    _route("GET", "/v1/teams/:team_id/status", "team-status", _HOSTED),
    _route("GET", "/v1/teams/:team_id/logs", "team-logs", _HOSTED),
    _route("POST", "/v1/teams/:team_id/stop", "team-stop", _HOSTED),
    _route("POST", "/v1/teams/:team_id/start", "team-start", _HOSTED),
    _route("POST", "/v1/teams/:team_id/restart", "team-restart", _HOSTED),
    _route("GET", "/healthz", "health", _LOCAL),
    _route("GET", "/v1/assistants", "registry-list", _LOCAL),
    _route("DELETE", "/v1/space", "space-reset", _LOCAL),
    _route("GET", "/v1/teams/:team_id/assistants", "assistant-list", _LOCAL),
    _route("POST", "/v1/teams/:team_id/assistants", "assistant-install", _LOCAL),
    _route("DELETE", "/v1/teams/:team_id/assistants/:assistant_id", "assistant-uninstall", _LOCAL),
    _route(
        "POST",
        "/v1/teams/:team_id/assistants/:assistant_id/powers/:power_id",
        "assistant-invoke",
        _LOCAL,
    ),
    _route("GET", "/v1/teams/:team_id/assistant-approvals", "assistant-approval-list", _LOCAL),
    _route("DELETE", "/v1/teams/:team_id/assistant-approvals", "assistant-approval-revoke", _LOCAL),
    _route("GET", "/v1/teams/:team_id/chat/approval", "chat-approval-pending", _LOCAL),
    _route("POST", "/v1/teams/:team_id/chat/approval", "chat-approval-submit", _LOCAL),
)


def resolve(profile: str, method: str, parts: tuple[str, ...]) -> RouteMatch | None:
    """Resolve one exact origin-form path without wildcard suffixes or method fallthrough."""
    if profile not in {HOSTED, LOCAL}:
        raise ValueError("unknown Controller routing profile")
    for route in ROUTES:
        if profile not in route.profiles or method != route.method or len(parts) != len(route.pattern):
            continue
        params: dict[str, str] = {}
        for expected, actual in zip(route.pattern, parts, strict=True):
            if expected.startswith(":"):
                params[expected[1:]] = actual
            elif expected != actual:
                break
        else:
            return RouteMatch(route.operation, params)
    return None
