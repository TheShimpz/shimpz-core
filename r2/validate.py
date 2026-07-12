"""Allowlist validation for r2-driver — runs BEFORE any rclone/filesystem action.

Nothing here touches rclone/R2/the filesystem; it only decides yes/no and returns validated values
the caller (app.py) turns into r2_client.py calls. Same shape as every other driver's own
validate.py — the actual security boundary, not the client that acts on its output.
"""

from __future__ import annotations

import re

# An R2 object key: the bucket-relative path (uploads/2026/07/04/report.pdf). Slashes ARE allowed
# (keys are hierarchical) but no traversal shape (`..`, leading `/`), and a bounded ASCII charset.
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")
# A listing prefix: same charset as a key but MAY be empty (list the whole bucket) and MAY end in `/`.
PREFIX_RE = re.compile(r"^[A-Za-z0-9._/-]{0,1023}$")
# A single upload filename (no path parts) — the basename the object key is built from.
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
# rclone --expire duration: a number + unit (s/m/h/d), e.g. 24h, 168h. Bounded so a caller can't
# pass an arbitrary rclone flag through this field.
EXPIRE_RE = re.compile(r"^[0-9]{1,4}[smhd]$")

# Sanity ceilings, not memory constraints: app.py streams both ways, and this API is on the
# internal shimpz-brain<->sidecar network (no Cloudflare 100 MB proxied-body cap).
UPLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024
DOWNLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024


class ValidationError(Exception):
    """An r2-driver request failed the allowlist — nothing was touched."""


def _traversal(value: str) -> bool:
    return value.startswith("/") or ".." in value.split("/")


def validate_key(value: object) -> str:
    if not isinstance(value, str) or not KEY_RE.match(value) or _traversal(value):
        raise ValidationError(f"key must match {KEY_RE.pattern!r} with no traversal: {value!r}")
    return value


def validate_prefix(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or not PREFIX_RE.match(value) or _traversal(value):
        raise ValidationError(f"prefix must match {PREFIX_RE.pattern!r} with no traversal: {value!r}")
    return value


def validate_filename(value: object) -> str:
    if not isinstance(value, str) or not FILENAME_RE.match(value) or value in (".", ".."):
        raise ValidationError(f"filename must match {FILENAME_RE.pattern!r}: {value!r}")
    return value


def validate_expire(value: object) -> str:
    if value is None:
        return "168h"
    if not isinstance(value, str) or not EXPIRE_RE.match(value):
        raise ValidationError(f"expire must match {EXPIRE_RE.pattern!r} (e.g. 24h, 168h): {value!r}")
    return value


def validate_upload_size(byte_count: int) -> int:
    if byte_count <= 0 or byte_count > UPLOAD_MAX_BYTES:
        raise ValidationError(f"upload size {byte_count} outside 1-{UPLOAD_MAX_BYTES}")
    return byte_count


def validate_download_size(byte_count: int) -> int:
    if byte_count > DOWNLOAD_MAX_BYTES:
        raise ValidationError(f"download size {byte_count} exceeds {DOWNLOAD_MAX_BYTES}")
    return byte_count
