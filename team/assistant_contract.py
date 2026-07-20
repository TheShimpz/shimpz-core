"""Closed first-party contract for the Shimpz Assistant reference artifact.

The hosted and single-owner controllers deliberately share this module so the
Brain never sees a Power that one runtime validates differently from the other.
Account declarations are public metadata; tokens remain Controller-owned.
"""

from __future__ import annotations

import re
from typing import Any

ASSISTANT_ID = "shimpz-assistant"
ASSISTANT_NAME = "Shimpz Assistant"
ASSISTANT_SUMMARY = "Explore safe OAuth Accounts and just-in-time BYOK Secrets through real X and Mux Powers."
ASSISTANT_RPC_COMMAND = "/usr/local/bin/shimpz-assistant-rpc"
ASSISTANT_ALLOWED_HOSTS = ("api.mux.com", "api.x.com")
MAX_HELP_BYTES = 32 * 1024
HELP_LOCALES = frozenset({"en", "pt", "es", "zh", "fr", "de", "ja", "ar"})
_USERNAME = re.compile(r"[A-Za-z0-9_]{1,15}")
_SNOWFLAKE = re.compile(r"[0-9]{1,19}")
_MUX_UPLOAD_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_MUX_EVENT_TYPE = re.compile(r"[a-z0-9._-]{1,120}")
_MUX_UPLOAD_STATUSES = frozenset({"waiting", "asset_created", "errored", "cancelled", "timed_out"})


def secret_contracts() -> dict[str, dict[str, str]]:
    """Return fresh public metadata for the three controller-custodied Mux Secrets."""
    return {
        "mux-token-id": {
            "name": "Mux Token ID",
            "summary": "The ID half of a Mux access token with Video Read and Write permissions.",
        },
        "mux-token-secret": {
            "name": "Mux Token Secret",
            "summary": "The secret half of the same Mux access token.",
        },
        "mux-webhook-signing-secret": {
            "name": "Mux Webhook Signing Secret",
            "summary": "The signing secret for the exact Mux webhook endpoint whose event is being verified.",
        },
    }


def account_contracts() -> dict[str, dict[str, object]]:
    """Return fresh public OAuth intent; endpoints and credentials stay Controller-owned."""
    return {
        "x": {
            "provider": "x",
            "scopes": ("offline.access", "tweet.read", "tweet.write", "users.read"),
        }
    }


def _user_schema() -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string", "pattern": "^[0-9]{1,19}$"},
            "name": {"type": "string", "minLength": 1, "maxLength": 80},
            "username": {"type": "string", "pattern": "^[A-Za-z0-9_]{1,15}$"},
        },
        "required": ["id", "name", "username"],
        "additionalProperties": False,
    }


def _upload_schema(*, status: object) -> dict[str, object]:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"},
            "status": status,
            "timeout": {"type": "integer", "minimum": 60, "maximum": 604800},
            "asset_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"},
        },
        "required": ["id", "status", "timeout"],
        "additionalProperties": False,
    }


def power_contracts() -> dict[str, dict[str, Any]]:
    """Return fresh closed schemas so callers cannot mutate another registry."""
    return {
        "public-user-lookup": {
            "method": "POST",
            "path": "/v1/powers/public-user-lookup",
            "summary": "Read one public X profile by username.",
            "input_schema": {
                "type": "object",
                "properties": {"username": {"type": "string", "pattern": "^[A-Za-z0-9_]{1,15}$"}},
                "required": ["username"],
                "additionalProperties": False,
            },
            "output_schema": _user_schema(),
            "approval": "none",
            "secrets": (),
            "accounts": ("x",),
        },
        "identity-me": {
            "method": "POST",
            "path": "/v1/powers/identity-me",
            "summary": "Read the identity of the connected X account.",
            "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
            "output_schema": _user_schema(),
            "approval": "none",
            "secrets": (),
            "accounts": ("x",),
        },
        "create-post": {
            "method": "POST",
            "path": "/v1/powers/create-post",
            "summary": "Publish one Post from the connected X account after explicit approval.",
            "input_schema": {
                "type": "object",
                "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 8192}},
                "required": ["text"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "pattern": "^[0-9]{1,19}$"},
                    "text": {"type": "string", "minLength": 1, "maxLength": 8192},
                },
                "required": ["id", "text"],
                "additionalProperties": False,
            },
            "approval": "each-run",
            "secrets": (),
            "accounts": ("x",),
        },
        "delete-post": {
            "method": "POST",
            "path": "/v1/powers/delete-post",
            "summary": "Delete one Post owned by the connected X account after explicit approval.",
            "input_schema": {
                "type": "object",
                "properties": {"id": {"type": "string", "pattern": "^[0-9]{1,19}$"}},
                "required": ["id"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {"deleted": {"const": True}},
                "required": ["deleted"],
                "additionalProperties": False,
            },
            "approval": "each-run",
            "secrets": (),
            "accounts": ("x",),
        },
        "list-direct-uploads": {
            "method": "POST",
            "path": "/v1/powers/list-direct-uploads",
            "summary": "List a bounded page of recent Mux direct uploads.",
            "input_schema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 25}},
                "required": ["limit"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "uploads": {
                        "type": "array",
                        "maxItems": 25,
                        "items": _upload_schema(
                            status={"enum": ["waiting", "asset_created", "errored", "cancelled", "timed_out"]}
                        ),
                    }
                },
                "required": ["uploads"],
                "additionalProperties": False,
            },
            "approval": "none",
            "secrets": ("mux-token-id", "mux-token-secret"),
            "accounts": (),
        },
        "create-test-direct-upload": {
            "method": "POST",
            "path": "/v1/powers/create-test-direct-upload",
            "summary": "Create a short-lived Mux test upload intent without uploading media.",
            "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
            "output_schema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"},
                    "status": {"const": "waiting"},
                    "timeout": {"const": 60},
                    "asset_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"},
                },
                "required": ["id", "status", "timeout"],
                "additionalProperties": False,
            },
            "approval": "each-run",
            "secrets": ("mux-token-id", "mux-token-secret"),
            "accounts": (),
        },
        "cancel-direct-upload": {
            "method": "POST",
            "path": "/v1/powers/cancel-direct-upload",
            "summary": "Cancel one waiting Mux direct upload after explicit approval.",
            "input_schema": {
                "type": "object",
                "properties": {"id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,128}$"}},
                "required": ["id"],
                "additionalProperties": False,
            },
            "output_schema": _upload_schema(status={"const": "cancelled"}),
            "approval": "each-run",
            "secrets": ("mux-token-id", "mux-token-secret"),
            "accounts": (),
        },
        "verify-mux-webhook": {
            "method": "POST",
            "path": "/v1/powers/verify-mux-webhook",
            "summary": "Verify one recent Mux webhook signature locally without network access.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "body": {"type": "string", "minLength": 1, "maxLength": 8192},
                    "signature": {"type": "string", "minLength": 1, "maxLength": 1024},
                },
                "required": ["body", "signature"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "valid": {"const": True},
                    "timestamp": {"type": "integer", "minimum": 0, "maximum": 9999999999},
                    "event_type": {"type": "string", "pattern": "^[a-z0-9._-]{1,120}$"},
                },
                "required": ["valid", "timestamp", "event_type"],
                "additionalProperties": False,
            },
            "approval": "none",
            "secrets": ("mux-webhook-signing-secret",),
            "accounts": (),
        },
    }


def _closed_object(payload: object, allowed: set[str], *, required: set[str]) -> dict[str, object]:
    if not isinstance(payload, dict) or not required <= set(payload) <= allowed:
        raise ValueError("Power payload does not match its declared fields")
    return payload


def _bounded_text(value: object, *, minimum: int, maximum: int, field: str) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum or value.strip() != value:
        raise ValueError(f"{field} is invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} is invalid")
    return value


def _username(value: object) -> str:
    if not isinstance(value, str) or _USERNAME.fullmatch(value) is None:
        raise ValueError("username is invalid")
    return value


def _snowflake(value: object) -> str:
    if not isinstance(value, str) or _SNOWFLAKE.fullmatch(value) is None:
        raise ValueError("id is invalid")
    return value


def _mux_upload_id(value: object) -> str:
    if not isinstance(value, str) or _MUX_UPLOAD_ID.fullmatch(value) is None:
        raise ValueError("Mux upload id is invalid")
    return value


def validate_power_input(assistant_id: str, power: str, payload: object) -> dict[str, object]:
    if assistant_id != ASSISTANT_ID:
        raise ValueError("the Power has no declared input contract")
    if power == "public-user-lookup":
        safe = _closed_object(payload, {"username"}, required={"username"})
        return {"username": _username(safe["username"])}
    if power == "identity-me":
        _closed_object(payload, set(), required=set())
        return {}
    if power == "create-post":
        safe = _closed_object(payload, {"text"}, required={"text"})
        return {"text": _bounded_text(safe["text"], minimum=1, maximum=8192, field="text")}
    if power == "delete-post":
        safe = _closed_object(payload, {"id"}, required={"id"})
        return {"id": _snowflake(safe["id"])}
    if power == "list-direct-uploads":
        safe = _closed_object(payload, {"limit"}, required={"limit"})
        limit = safe["limit"]
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 25:
            raise ValueError("limit is invalid")
        return {"limit": limit}
    if power == "create-test-direct-upload":
        _closed_object(payload, set(), required=set())
        return {}
    if power == "cancel-direct-upload":
        safe = _closed_object(payload, {"id"}, required={"id"})
        return {"id": _mux_upload_id(safe["id"])}
    if power == "verify-mux-webhook":
        safe = _closed_object(payload, {"body", "signature"}, required={"body", "signature"})
        return {
            "body": _bounded_text(safe["body"], minimum=1, maximum=8192, field="body"),
            "signature": _bounded_text(safe["signature"], minimum=1, maximum=1024, field="signature"),
        }
    raise ValueError("the Power has no declared input contract")


def _user(payload: object) -> dict[str, object]:
    safe = _closed_object(payload, {"id", "name", "username"}, required={"id", "name", "username"})
    return {
        "id": _snowflake(safe["id"]),
        "name": _bounded_text(safe["name"], minimum=1, maximum=80, field="name"),
        "username": _username(safe["username"]),
    }


def _upload(payload: object, *, expected_status: str | None = None, timeout: int | None = None) -> dict[str, object]:
    safe = _closed_object(payload, {"id", "status", "timeout", "asset_id"}, required={"id", "status", "timeout"})
    status = safe["status"]
    if not isinstance(status, str) or status not in _MUX_UPLOAD_STATUSES:
        raise ValueError("status is invalid")
    if expected_status is not None and status != expected_status:
        raise ValueError("status is invalid")
    timeout_value = safe["timeout"]
    if (
        isinstance(timeout_value, bool)
        or not isinstance(timeout_value, int)
        or not 60 <= timeout_value <= 604800
        or (timeout is not None and timeout_value != timeout)
    ):
        raise ValueError("timeout is invalid")
    projected: dict[str, object] = {
        "id": _mux_upload_id(safe["id"]),
        "status": status,
        "timeout": timeout_value,
    }
    if "asset_id" in safe:
        projected["asset_id"] = _mux_upload_id(safe["asset_id"])
    return projected


def validate_power_output(assistant_id: str, power: str, payload: object) -> dict[str, object]:
    if assistant_id != ASSISTANT_ID:
        raise ValueError("the Power has no declared output contract")
    if power in {"public-user-lookup", "identity-me"}:
        return _user(payload)
    if power == "create-post":
        safe = _closed_object(payload, {"id", "text"}, required={"id", "text"})
        return {
            "id": _snowflake(safe["id"]),
            "text": _bounded_text(safe["text"], minimum=1, maximum=8192, field="text"),
        }
    if power == "delete-post":
        safe = _closed_object(payload, {"deleted"}, required={"deleted"})
        if safe["deleted"] is not True:
            raise ValueError("deleted is invalid")
        return {"deleted": True}
    if power == "list-direct-uploads":
        safe = _closed_object(payload, {"uploads"}, required={"uploads"})
        uploads = safe["uploads"]
        if not isinstance(uploads, list) or len(uploads) > 25:
            raise ValueError("uploads is invalid")
        return {"uploads": [_upload(item) for item in uploads]}
    if power == "create-test-direct-upload":
        return _upload(payload, expected_status="waiting", timeout=60)
    if power == "cancel-direct-upload":
        return _upload(payload, expected_status="cancelled")
    if power == "verify-mux-webhook":
        safe = _closed_object(
            payload,
            {"valid", "timestamp", "event_type"},
            required={"valid", "timestamp", "event_type"},
        )
        timestamp = safe["timestamp"]
        event_type = safe["event_type"]
        if safe["valid"] is not True:
            raise ValueError("valid is invalid")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or not 0 <= timestamp <= 9999999999:
            raise ValueError("timestamp is invalid")
        if not isinstance(event_type, str) or _MUX_EVENT_TYPE.fullmatch(event_type) is None:
            raise ValueError("event_type is invalid")
        return {"valid": True, "timestamp": timestamp, "event_type": event_type}
    raise ValueError("the Power has no declared output contract")


def validate_help_payload(payload: object) -> dict[str, str]:
    """Accept only one bounded UTF-8 Markdown document from the fixed RPC."""
    if not isinstance(payload, dict) or set(payload) != {"markdown"}:
        raise ValueError("Assistant Help returned an invalid result")
    markdown = payload["markdown"]
    if not isinstance(markdown, str) or not markdown:
        raise ValueError("Assistant Help returned an invalid result")
    try:
        encoded = markdown.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Assistant Help returned an invalid result") from exc
    if len(encoded) > MAX_HELP_BYTES or any(
        (ord(character) < 32 and character not in "\n\t") or 127 <= ord(character) <= 159 for character in markdown
    ):
        raise ValueError("Assistant Help returned an invalid result")
    return {"markdown": markdown}


def validate_help_locale(locale: object) -> str:
    """Accept only the fixed locale identifiers implemented by the Assistant Help RPC."""
    if not isinstance(locale, str) or locale not in HELP_LOCALES:
        raise ValueError("Assistant Help locale is not supported")
    return locale
