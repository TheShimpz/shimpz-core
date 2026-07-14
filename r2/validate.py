"""Allowlist validation for r2-driver — runs BEFORE any rclone/filesystem action.

Nothing here touches rclone/R2/the filesystem; it only decides yes/no and returns validated values
the caller (app.py) turns into r2_client.py calls. Same shape as every other driver's own
validate.py — the actual security boundary, not the client that acts on its output.
"""

from __future__ import annotations

import datetime as dt
import os
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
# An immutable backup key is derived from the authenticated archive creation time and whole-object
# SHA-256. Recovery reads are confined to this exact namespace and shape; the generic key validator
# remains intentionally broader for the Brain-facing operations.
BACKUP_KEY_RE = re.compile(
    r"^backups/v1/(?P<year>[0-9]{4})/(?P<month>[0-9]{2})/(?P<day>[0-9]{2})/"
    r"(?P<stamp>[0-9]{8}T[0-9]{6}Z)-(?P<sha256>[0-9a-f]{64})[.]sbk$"
)
RESERVED_BACKUP_PREFIX = "backups/v1/"
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]{0,18})$")

# The Brain-facing generic operation stays deliberately small. Approved encrypted backups have a
# distinct configurable ceiling because one archive contains every protected database and volume.
UPLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024
DOWNLOAD_MAX_BYTES = 5 * 1024 * 1024 * 1024
DEFAULT_BACKUP_UPLOAD_MAX_BYTES = 100 * 1024 * 1024 * 1024
# Each recovery response is staged on the ciphertext-only backup spool before any HTTP headers are
# sent. This keeps failure handling atomic while bounding transient disk use independently of object
# size; the HTTP and docker-exec clients still copy it in 1 MiB memory chunks.
DEFAULT_BACKUP_DOWNLOAD_RANGE_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_BACKUP_UPLOAD_TOTAL_TIMEOUT_SECONDS = 48 * 60 * 60


def _backup_upload_limit() -> int:
    raw = os.environ.get("SHIMPZ_R2DRIVER_BACKUP_MAX_BYTES", str(DEFAULT_BACKUP_UPLOAD_MAX_BYTES))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("SHIMPZ_R2DRIVER_BACKUP_MAX_BYTES must be a positive integer") from exc
    if not 1 <= value <= 2**63 - 1:
        raise RuntimeError("SHIMPZ_R2DRIVER_BACKUP_MAX_BYTES must be between 1 and 2^63-1")
    return value


BACKUP_UPLOAD_MAX_BYTES = _backup_upload_limit()


def _backup_download_range_limit() -> int:
    raw = os.environ.get(
        "SHIMPZ_R2DRIVER_BACKUP_RANGE_BYTES",
        str(DEFAULT_BACKUP_DOWNLOAD_RANGE_MAX_BYTES),
    )
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("SHIMPZ_R2DRIVER_BACKUP_RANGE_BYTES must be a positive integer") from exc
    if not 1 <= value <= DEFAULT_BACKUP_DOWNLOAD_RANGE_MAX_BYTES:
        raise RuntimeError("SHIMPZ_R2DRIVER_BACKUP_RANGE_BYTES must be between 1 and the fixed 256 MiB ceiling")
    return value


BACKUP_DOWNLOAD_RANGE_MAX_BYTES = _backup_download_range_limit()


class ValidationError(Exception):
    """An r2-driver request failed the allowlist — nothing was touched."""


def _traversal(value: str) -> bool:
    return value.startswith("/") or ".." in value.split("/")


def validate_key(value: object) -> str:
    if not isinstance(value, str) or not KEY_RE.match(value) or _traversal(value):
        raise ValidationError(f"key must match {KEY_RE.pattern!r} with no traversal: {value!r}")
    if value == RESERVED_BACKUP_PREFIX.rstrip("/") or value.startswith(RESERVED_BACKUP_PREFIX):
        raise ValidationError("the encrypted-backup namespace is not available to generic R2 operations")
    return value


def validate_prefix(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or not PREFIX_RE.match(value) or _traversal(value):
        raise ValidationError(f"prefix must match {PREFIX_RE.pattern!r} with no traversal: {value!r}")
    if value and (RESERVED_BACKUP_PREFIX.startswith(value) or value.startswith(RESERVED_BACKUP_PREFIX)):
        raise ValidationError("the encrypted-backup namespace is not available to generic R2 operations")
    return value


def generic_entry_visible(value: object) -> bool:
    """Keep a root listing useful without disclosing the operator-only backup namespace."""
    return isinstance(value, str) and not (
        value == RESERVED_BACKUP_PREFIX.rstrip("/") or value.startswith(RESERVED_BACKUP_PREFIX)
    )


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


def validate_backup_key(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"backup key must match {BACKUP_KEY_RE.pattern!r}: {value!r}")
    match = BACKUP_KEY_RE.fullmatch(value)
    if match is None:
        raise ValidationError(f"backup key must match {BACKUP_KEY_RE.pattern!r}: {value!r}")
    try:
        created = dt.datetime.strptime(match.group("stamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.UTC)
    except ValueError as exc:
        raise ValidationError(f"backup key contains an invalid UTC timestamp: {value!r}") from exc
    expected_prefix = f"backups/v1/{created:%Y/%m/%d}/"
    if not value.startswith(expected_prefix):
        raise ValidationError(f"backup key date prefix does not match its timestamp: {value!r}")
    return value


def backup_key_sha256(value: object) -> str:
    key = validate_backup_key(value)
    match = BACKUP_KEY_RE.fullmatch(key)
    if match is None:
        raise ValidationError("validated backup key unexpectedly changed")
    return match.group("sha256")


def validate_upload_size(byte_count: int) -> int:
    if byte_count <= 0 or byte_count > UPLOAD_MAX_BYTES:
        raise ValidationError(f"upload size {byte_count} outside 1-{UPLOAD_MAX_BYTES}")
    return byte_count


def validate_backup_upload_size(byte_count: int) -> int:
    if byte_count <= 0 or byte_count > BACKUP_UPLOAD_MAX_BYTES:
        raise ValidationError(f"backup upload size {byte_count} outside 1-{BACKUP_UPLOAD_MAX_BYTES}")
    return byte_count


def validate_backup_deadline(value: object, maximum: int = DEFAULT_BACKUP_UPLOAD_TOTAL_TIMEOUT_SECONDS) -> int:
    if not isinstance(value, str) or not _DECIMAL_RE.fullmatch(value):
        raise ValidationError("private backup deadline must be a canonical positive decimal integer")
    seconds = int(value)
    if not 1 <= seconds <= maximum:
        raise ValidationError(f"private backup deadline {seconds} outside 1-{maximum}")
    return seconds


def validate_backup_download_size(byte_count: int) -> int:
    if byte_count <= 0 or byte_count > BACKUP_UPLOAD_MAX_BYTES:
        raise ValidationError(f"backup download size {byte_count} outside 1-{BACKUP_UPLOAD_MAX_BYTES}")
    return byte_count


def validate_backup_range(offset_value: object, length_value: object, object_size: int) -> tuple[int, int]:
    validate_backup_download_size(object_size)
    if not isinstance(offset_value, str) or not _DECIMAL_RE.fullmatch(offset_value):
        raise ValidationError("backup download offset must be a canonical nonnegative decimal integer")
    if not isinstance(length_value, str) or not _DECIMAL_RE.fullmatch(length_value):
        raise ValidationError("backup download length must be a canonical positive decimal integer")
    offset = int(offset_value)
    length = int(length_value)
    if offset >= object_size:
        raise ValidationError(f"backup download offset {offset} is outside object size {object_size}")
    if not 1 <= length <= BACKUP_DOWNLOAD_RANGE_MAX_BYTES:
        raise ValidationError(f"backup download length {length} outside 1-{BACKUP_DOWNLOAD_RANGE_MAX_BYTES}")
    return offset, min(length, object_size - offset)


def validate_download_size(byte_count: int) -> int:
    if byte_count > DOWNLOAD_MAX_BYTES:
        raise ValidationError(f"download size {byte_count} exceeds {DOWNLOAD_MAX_BYTES}")
    return byte_count
