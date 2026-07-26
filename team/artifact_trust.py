"""Independent Sigstore verification for one published Assistant artifact."""

from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import docker
import registry_auth

SIGNER_IDENTITY = "https://github.com/TheShimpz/shimpz-developers/.github/workflows/build-assistant.yml@refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
TRUST_REPOSITORY = "ghcr.io/theshimpz/shimpz-assistant-trust"
_MAX_OUTPUT_BYTES = 2 * 1024 * 1024
_TIMEOUT_SECONDS = 90


class ArtifactTrustError(RuntimeError):
    """The artifact signature or signed provenance could not be proved."""


class ArtifactTrustVerifier:
    def __init__(
        self,
        docker_client: object,
        binary: str = "/usr/local/bin/cosign",
        *,
        container_id: str | None = None,
        credentials: registry_auth.RegistryAuth,
    ) -> None:
        self._docker = docker_client
        self._binary = binary
        self._container_id = _self_container_id() if container_id is None else container_id
        self._credentials = credentials

    def verify(self, resolution: dict[str, Any]) -> None:
        if resolution["trust"]["signer_identity"] != SIGNER_IDENTITY:
            raise ArtifactTrustError("Assistant signer identity is not trusted")
        image = resolution["image_reference"]
        signature = self._cosign_json(
            "verify",
            "--new-bundle-format=false",
            "--certificate-identity",
            SIGNER_IDENTITY,
            "--certificate-oidc-issuer",
            OIDC_ISSUER,
            "--output",
            "json",
            image,
        )
        _verify_signature_payload(signature, resolution["oci_digest"])
        attestation = self._cosign_json(
            "verify-attestation",
            "--new-bundle-format=false",
            "--certificate-identity",
            SIGNER_IDENTITY,
            "--certificate-oidc-issuer",
            OIDC_ISSUER,
            "--type",
            "slsaprovenance1",
            "--output",
            "json",
            image,
        )
        _verify_provenance(attestation, resolution)
        self._verify_attachment(
            image,
            resolution["trust"]["signature_reference"],
            attestation=False,
        )
        self._verify_attachment(
            image,
            resolution["trust"]["provenance_reference"],
            attestation=True,
        )

    def _verify_attachment(self, image: str, expected: str, *, attestation: bool) -> None:
        arguments = ["triangulate"]
        if attestation:
            arguments.extend(("--type", "attestation"))
        arguments.append(image)
        tag = self._cosign_text(*arguments)
        if not tag.startswith(f"{TRUST_REPOSITORY}:") or "\n" in tag:
            raise ArtifactTrustError("Sigstore attachment location is invalid")
        try:
            registry_data = self._docker.images.get_registry_data(
                tag,
                auth_config=self._credentials.docker_auth_config(),
            )
            digest = registry_data.id
        except (AttributeError, docker.errors.DockerException) as exc:
            raise ArtifactTrustError("Sigstore attachment digest is unavailable") from exc
        if expected != f"{TRUST_REPOSITORY}@{digest}":
            raise ArtifactTrustError("Sigstore attachment digest does not match")

    def _cosign_json(self, *arguments: str) -> object:
        raw = self._run_cosign(arguments)
        try:
            return json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ArtifactTrustError("Cosign returned invalid verification evidence") from exc

    def _cosign_text(self, *arguments: str) -> str:
        raw = self._run_cosign(arguments)
        try:
            value = raw.decode("ascii").strip()
        except UnicodeError as exc:
            raise ArtifactTrustError("Cosign returned invalid attachment evidence") from exc
        if not value:
            raise ArtifactTrustError("Cosign returned empty attachment evidence")
        return value

    def _run_cosign(self, arguments: tuple[str, ...]) -> bytes:
        with (
            tempfile.TemporaryDirectory(prefix="shimpz-cosign-") as directory,
            self._credentials.docker_config() as docker_config,
        ):
            try:
                execution = self._docker.api.exec_create(
                    container=self._container_id,
                    cmd=[self._binary, *arguments],
                    stdout=True,
                    stderr=True,
                    stdin=False,
                    tty=False,
                    user="10001",
                    environment=[
                        f"HOME={directory}",
                        f"PATH={os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')}",
                        f"COSIGN_REPOSITORY={TRUST_REPOSITORY}",
                        f"DOCKER_CONFIG={docker_config}",
                    ],
                )
                execution_id = execution["Id"]
                started = time.monotonic()
                output = bytearray()
                error_bytes = 0
                for stdout, stderr in self._docker.api.exec_start(
                    execution_id,
                    stream=True,
                    demux=True,
                ):
                    if time.monotonic() - started > _TIMEOUT_SECONDS:
                        raise ArtifactTrustError("Cosign verification timed out")
                    output.extend(stdout or b"")
                    error_bytes += len(stderr or b"")
                    if len(output) + error_bytes > _MAX_OUTPUT_BYTES:
                        raise ArtifactTrustError("Cosign verification output is too large")
                result = self._docker.api.exec_inspect(execution_id)
                if result.get("ExitCode") != 0:
                    raise ArtifactTrustError("Cosign verification failed")
                return bytes(output)
            except (KeyError, TypeError, docker.errors.DockerException) as exc:
                raise ArtifactTrustError("Cosign verification is unavailable") from exc


def _self_container_id() -> str:
    try:
        value = Path("/etc/hostname").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("Team Controller container identity is unavailable") from exc
    if not 12 <= len(value) <= 64 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("Team Controller container identity is invalid")
    return value


def _verify_signature_payload(value: object, oci_digest: str) -> None:
    records = value if isinstance(value, list) else []
    if not any(_signature_digest(record) == oci_digest for record in records):
        raise ArtifactTrustError("Cosign signature does not bind the Assistant digest")


def _signature_digest(record: object) -> object:
    if not isinstance(record, dict):
        return None
    critical = record.get("critical", record.get("Critical"))
    if not isinstance(critical, dict):
        return None
    image = critical.get("image", critical.get("Image"))
    if not isinstance(image, dict):
        return None
    return image.get("docker-manifest-digest", image.get("Docker-manifest-digest"))


def _verify_provenance(value: object, resolution: dict[str, Any]) -> None:
    envelopes = (value,) if isinstance(value, dict) else ()
    if not any(_provenance_matches(envelope, resolution) for envelope in envelopes):
        raise ArtifactTrustError("signed provenance does not match the Assistant publication")


def _provenance_matches(envelope: object, resolution: dict[str, Any]) -> bool:
    if not isinstance(envelope, dict) or envelope.get("payloadType") != "application/vnd.in-toto+json":
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return False
    statement = _decode_statement(payload)
    if statement is None:
        return False
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    return (
        isinstance(subjects, list)
        and isinstance(predicate, dict)
        and _subject_matches(subjects, resolution["oci_digest"])
        and statement.get("_type") == "https://in-toto.io/Statement/v0.1"
        and statement.get("predicateType") == "https://slsa.dev/provenance/v1"
        and _predicate_matches(predicate, resolution)
    )


def _decode_statement(payload: str) -> dict[str, Any] | None:
    try:
        statement = json.loads(base64.b64decode(payload, validate=True))
    except ValueError, binascii.Error, UnicodeError, json.JSONDecodeError:
        return None
    return statement if isinstance(statement, dict) else None


def _subject_matches(subjects: list[object], oci_digest: str) -> bool:
    expected = oci_digest.removeprefix("sha256:")
    return any(
        isinstance(subject, dict)
        and isinstance(subject.get("digest"), dict)
        and subject["digest"].get("sha256") == expected
        for subject in subjects
    )


def _predicate_matches(predicate: dict[str, Any], resolution: dict[str, Any]) -> bool:
    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    if not isinstance(build_definition, dict) or not isinstance(run_details, dict):
        return False
    external = build_definition.get("externalParameters")
    builder = run_details.get("builder")
    expected_external = {
        "assistant_id": resolution["assistant_id"],
        "version": resolution["assistant_version"],
        "source_digest": resolution["source_digest"],
        "manifest_digest": resolution["manifest_digest"],
        "machine_contract_digest": resolution["machine_contract_digest"],
    }
    return (
        build_definition.get("buildType") == "https://shimpz.com/build-types/assistant/v1"
        and external == expected_external
        and isinstance(builder, dict)
        and builder.get("id") == SIGNER_IDENTITY
    )
