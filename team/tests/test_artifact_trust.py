"""Independent Assistant signature and provenance verification."""

from __future__ import annotations

import base64
import copy
import json
import tempfile
import types
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

from hosted_install.artifact_trust import SIGNER_IDENTITY, ArtifactTrustError, ArtifactTrustVerifier
from hosted_install.developers_controller_contract import CONTRACT_ROOT

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]
AUTH = types.SimpleNamespace(
    docker_auth_config=lambda: {"username": "registry-reader", "password": "x" * 20},
    docker_config=lambda: nullcontext("/run/shimpz-test-registry"),
)


def _signature(resolution: dict[str, object]) -> list[dict[str, object]]:
    return [{"critical": {"image": {"docker-manifest-digest": resolution["oci_digest"]}}}]


def _attestation(resolution: dict[str, object]) -> list[dict[str, str]]:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [
            {
                "name": "ghcr.io/theshimpz/shimpz-assistants",
                "digest": {"sha256": resolution["oci_digest"].removeprefix("sha256:")},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://shimpz.com/build-types/assistant/v1",
                "externalParameters": {
                    "assistant_id": resolution["assistant_id"],
                    "version": resolution["assistant_version"],
                    "source_digest": resolution["source_digest"],
                    "manifest_digest": resolution["manifest_digest"],
                    "machine_contract_digest": resolution["machine_contract_digest"],
                },
            },
            "runDetails": {"builder": {"id": SIGNER_IDENTITY}},
        },
    }
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
    }


class ArtifactTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary_directory.cleanup)
        self._trust_root = Path(self._temporary_directory.name) / "trust"

    def _verifier(self, resolution: dict[str, object]) -> ArtifactTrustVerifier:
        digests = iter(
            (
                resolution["trust"]["signature_reference"].removeprefix("ghcr.io/theshimpz/shimpz-assistant-trust@"),
                resolution["trust"]["provenance_reference"].removeprefix("ghcr.io/theshimpz/shimpz-assistant-trust@"),
            )
        )
        images = types.SimpleNamespace(
            get_registry_data=lambda _tag, *, auth_config: types.SimpleNamespace(id=next(digests))
        )
        return ArtifactTrustVerifier(
            types.SimpleNamespace(images=images),
            container_id="a" * 64,
            credentials=AUTH,
            trust_root=self._trust_root,
        )

    def test_reuses_private_tuf_cache_but_not_docker_configuration(self) -> None:
        docker_configs: list[str] = []

        class Credentials:
            def docker_config(self) -> object:
                directory = tempfile.TemporaryDirectory()
                docker_configs.append(directory.name)
                return directory

        api = mock.Mock()
        api.exec_create.side_effect = ({"Id": "first"}, {"Id": "second"})
        api.exec_start.return_value = iter(())
        api.exec_inspect.return_value = {"ExitCode": 0}
        verifier = ArtifactTrustVerifier(
            types.SimpleNamespace(api=api),
            container_id="a" * 64,
            credentials=Credentials(),
            trust_root=self._trust_root,
        )

        verifier._run_cosign(("verify", "first"))
        api.exec_start.return_value = iter(())
        verifier._run_cosign(("verify", "second"))

        environments = [call.kwargs["environment"] for call in api.exec_create.call_args_list]
        tuf_roots = [
            next(value for value in environment if value.startswith("TUF_ROOT=")) for environment in environments
        ]
        docker_roots = [
            next(value for value in environment if value.startswith("DOCKER_CONFIG=")) for environment in environments
        ]
        homes = [next(value for value in environment if value.startswith("HOME=")) for environment in environments]
        self.assertEqual(tuf_roots, [f"TUF_ROOT={self._trust_root}"] * 2)
        self.assertNotEqual(docker_roots[0], docker_roots[1])
        self.assertNotEqual(homes[0], homes[1])
        self.assertEqual(self._trust_root.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(not Path(path).exists() for path in docker_configs))
        self.assertTrue(all(not Path(value.removeprefix("HOME=")).exists() for value in homes))

    def test_rejects_a_non_private_tuf_cache(self) -> None:
        self._trust_root.mkdir(mode=0o755)

        with self.assertRaisesRegex(RuntimeError, "not a private"):
            ArtifactTrustVerifier(
                types.SimpleNamespace(),
                container_id="a" * 64,
                credentials=AUTH,
                trust_root=self._trust_root,
            )

    def test_accepts_signature_provenance_and_exact_attachment_digests(self) -> None:
        resolution = copy.deepcopy(RESOLUTION)
        resolution["trust"]["signer_identity"] = SIGNER_IDENTITY
        verifier = self._verifier(resolution)
        outputs = iter(
            (
                json.dumps(_signature(resolution)).encode(),
                json.dumps(_attestation(resolution)).encode(),
                b"ghcr.io/theshimpz/shimpz-assistant-trust:sha256-image.sig\n",
                b"ghcr.io/theshimpz/shimpz-assistant-trust:sha256-image.att\n",
            )
        )

        with mock.patch.object(verifier, "_run_cosign", side_effect=lambda _args: next(outputs)):
            verifier.verify(resolution)

    def test_rejects_each_mismatched_authority(self) -> None:
        base = copy.deepcopy(RESOLUTION)
        base["trust"]["signer_identity"] = SIGNER_IDENTITY
        cases = (
            ("identity", ("trust", "signer_identity"), "https://attacker.example/workflow"),
            ("source", ("source_digest",), "sha256:" + "9" * 64),
            (
                "signature-reference",
                ("trust", "signature_reference"),
                "ghcr.io/theshimpz/shimpz-assistant-trust@sha256:" + "9" * 64,
            ),
        )
        for name, path, value in cases:
            resolution = copy.deepcopy(base)
            target = resolution
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            verifier = self._verifier(base)
            outputs = iter(
                (
                    json.dumps(_signature(base)).encode(),
                    json.dumps(_attestation(base)).encode(),
                    b"ghcr.io/theshimpz/shimpz-assistant-trust:sha256-image.sig\n",
                    b"ghcr.io/theshimpz/shimpz-assistant-trust:sha256-image.att\n",
                )
            )
            with (
                self.subTest(name=name),
                mock.patch.object(
                    verifier,
                    "_run_cosign",
                    side_effect=lambda _args, iterator=outputs: next(iterator),
                ),
                self.assertRaises(ArtifactTrustError),
            ):
                verifier.verify(resolution)


if __name__ == "__main__":
    unittest.main()
