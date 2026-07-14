"""Allowlist validation for capsule-driver — runs BEFORE any Docker or pg-driver call.

Nothing here touches Docker; it only decides yes/no and returns a validated capsule id the caller
(app.py) turns into container/network/volume/DB names. Same shape as the other drivers' validate.py
modules — the actual security boundary, not the client that acts on its output.
"""

from __future__ import annotations

import re

# The id becomes the DB project "capsule_<id>"; Postgres identifiers are 63 bytes and dbname/role are
# "proj_capsule_" + this, so cap it well under the limit. It also names the container/network/volumes,
# so keep it to the Docker-safe [a-z0-9_] set.
CAPSULE_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")


class ValidationError(Exception):
    """A capsule-driver request failed the allowlist — nothing was touched."""


def sanitize(name: str) -> str:
    lowered = re.sub(r"[^a-z0-9_]+", "_", str(name).lower())
    return lowered.strip("_")


def validate_capsule_id(name: object) -> str:
    if not isinstance(name, str) or not name:
        raise ValidationError(f"capsule id must be a non-empty string: {name!r}")
    sanitized = sanitize(name)
    if not sanitized or not CAPSULE_ID_RE.match(sanitized):
        raise ValidationError(f"capsule id sanitizes to empty or invalid: {name!r} -> {sanitized!r}")
    return sanitized


MAX_CHAT_MESSAGE = 16000


def validate_chat_message(message: object) -> str:
    """A Captain→brain chat message: non-empty text, size-bounded.

    Content passes through verbatim — it becomes the `claude -p` prompt inside the capsule,
    which is exactly its job.
    """
    if not isinstance(message, str):
        raise ValidationError("message must be a string")
    text = message.strip()
    if not text:
        raise ValidationError("message must be non-empty")
    if len(text) > MAX_CHAT_MESSAGE:
        raise ValidationError(f"message too long (> {MAX_CHAT_MESSAGE} chars)")
    return text


# Claude's real code is `<code>#<state>`, so the charset is "printable ASCII, no whitespace" —
# byte-identical to drivers/apps' LOGIN_CODE_RE and to shimpz-login's own SUBMIT_CODE_RE. The one
# real risk is whitespace/newline (a second stdin line); a `;`/backtick/`$` is inert because the
# code is carried on the private Docker exec stdin stream, never interpreted by a shell.
LOGIN_CODE_RE = re.compile(r"^[!-~]{1,4096}$")


def validate_login_code(code: object) -> str:
    """The Claude-subscription OAuth code forwarded to `shimpz-login submit` over private stdin.

    The refusal message NEVER echoes the code.
    """
    if not isinstance(code, str) or not LOGIN_CODE_RE.match(code):
        raise ValidationError("login code must be printable ASCII with no whitespace (1..4096 chars)")
    return code


# The rid becomes a FILENAME (`<rid>.resp` inside the capsule's ipc dir) — no dots/slashes, ever.
ASK_RID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def validate_ask_rid(rid: object) -> str:
    if not isinstance(rid, str) or not ASK_RID_RE.match(rid):
        raise ValidationError("ask rid must be 1-64 chars of A-Za-z0-9_- (it names the .resp file)")
    return rid


INBOX_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,120}$")


def validate_inbox_filename(name: object) -> str:
    """A safe basename for the capsule's workspace inbox — no separators, no traversal, no dotfiles."""
    base = str(name or "").strip().replace("\\", "/").split("/")[-1]
    if not INBOX_FILENAME_RE.match(base) or ".." in base:
        raise ValidationError(f"bad filename: {name!r}")
    return base
