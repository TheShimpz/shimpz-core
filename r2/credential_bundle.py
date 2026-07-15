"""Standard-library-only validation for the closed Driver Spec v1 R2 form."""

from __future__ import annotations

import re

import driver_manifest

CREDENTIAL_SCHEMA = driver_manifest.load_credentials()

_FORMAT_PATTERNS = {
    "account-id": re.compile(r"^[0-9a-f]{32}$"),
    "access-key-id": re.compile(r"^[A-Za-z0-9_-]{16,128}$"),
    "secret-access-key": re.compile(r"^[0-9a-f]{64}$"),
    "bucket-name": re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$"),
}


class CredentialBundleValidationError(ValueError):
    """A credential profile or complete value bundle violates the packaged form."""


def credential_profile(profile_id: object) -> driver_manifest.CredentialProfile:
    if not isinstance(profile_id, str):
        raise CredentialBundleValidationError("profile_id must name a declared credential profile")
    profiles = {profile.id: profile for profile in CREDENTIAL_SCHEMA.profiles}
    try:
        return profiles[profile_id]
    except KeyError as exc:
        raise CredentialBundleValidationError("profile_id must name a declared credential profile") from exc


def validate_bundle(profile_id: object, values: object) -> dict[str, str]:
    """Validate one complete bundle against the packaged form and R2-specific formats."""
    profile = credential_profile(profile_id)
    if not isinstance(values, dict) or any(not isinstance(key, str) for key in values):
        raise CredentialBundleValidationError("credential values must be an object")
    fields = {field.id: field for field in profile.fields}
    required = {field.id for field in profile.fields if field.required}
    if set(values) != set(fields) or not required.issubset(values):
        raise CredentialBundleValidationError("credential values must contain exactly the declared fields")

    validated: dict[str, str] = {}
    for field in profile.fields:
        value = values[field.id]
        if not isinstance(value, str) or not field.min_length <= len(value) <= field.max_length:
            raise CredentialBundleValidationError(f"{field.id} has an invalid length")
        pattern = _FORMAT_PATTERNS.get(field.format)
        if pattern is None or pattern.fullmatch(value) is None:
            raise CredentialBundleValidationError(f"{field.id} does not match its named R2 format")
        validated[field.id] = value
    return validated
