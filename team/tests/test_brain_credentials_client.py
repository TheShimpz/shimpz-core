from __future__ import annotations

import json
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import brain_credentials_client
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _delivery(account_id: str, provider: str, recipient: str, secret: str) -> dict[str, object]:
    recipient_bytes = brain_credentials_client._b64decode(recipient)
    sender = x25519.X25519PrivateKey.generate()
    sender_public = sender.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    salt = secrets.token_bytes(brain_credentials_client.DELIVERY_SALT_BYTES)
    nonce = secrets.token_bytes(brain_credentials_client.DELIVERY_NONCE_BYTES)
    aad = brain_credentials_client._delivery_aad(
        account_id,
        provider,
        "api_key",
        recipient_bytes,
        sender_public,
    )
    shared_key = sender.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_bytes))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=brain_credentials_client.DELIVERY_KEY_BYTES,
        salt=salt,
        info=aad,
    ).derive(shared_key)
    ciphertext = AESGCM(key).encrypt(nonce, secret.encode(), aad)
    return {
        "v": brain_credentials_client.DELIVERY_VERSION,
        "alg": brain_credentials_client.DELIVERY_ALGORITHM,
        "sender_public_key": brain_credentials_client._b64encode(sender_public),
        "salt": brain_credentials_client._b64encode(salt),
        "nonce": brain_credentials_client._b64encode(nonce),
        "ciphertext": brain_credentials_client._b64encode(ciphertext),
    }


class BrainCredentialsClientTests(unittest.TestCase):
    def test_resolve_delivers_only_an_api_key_in_memory(self):
        account_id = "account-1"
        provider = "openai"
        secret = secrets.token_urlsafe(32)
        requests: list[tuple[str, dict]] = []

        def post(_base_url, path, payload, _token_file, _session=None):
            requests.append((path, payload))
            if path == "/v1/internal/brains/resolve":
                return 200, {
                    "auth_type": "api_key",
                    "secret_ref": {"opaque": "envelope"},
                    "generation": 4,
                }
            self.assertEqual(path, "/v1/deliver")
            return 200, {
                "delivery": _delivery(
                    account_id,
                    provider,
                    payload["recipient_public_key"],
                    secret,
                )
            }

        with mock.patch.object(brain_credentials_client, "_post", side_effect=post):
            credential = brain_credentials_client.resolve(account_id, provider)

        self.assertEqual(credential, ("api_key", secret, 4))
        self.assertEqual(
            [path for path, _payload in requests],
            [
                "/v1/internal/brains/resolve",
                "/v1/deliver",
            ],
        )
        self.assertNotIn(secret, json.dumps(requests))

    def test_unsupported_providers_and_oauth_metadata_fail_closed(self):
        for provider in ("claude-code", "codex"):
            with self.subTest(provider=provider), mock.patch.object(brain_credentials_client, "_post") as post:
                with self.assertRaises(brain_credentials_client.BrainCredentialError):
                    brain_credentials_client.resolve("account-1", provider)
                post.assert_not_called()

        metadata = {
            "auth_type": "oauth",
            "secret_ref": {"opaque": "invalid-envelope"},
            "generation": 1,
        }
        with mock.patch.object(brain_credentials_client, "_post", return_value=(200, metadata)) as post:
            with self.assertRaises(brain_credentials_client.BrainCredentialError):
                brain_credentials_client.resolve("account-1", "anthropic")
            post.assert_called_once()

    def test_generation_check_keeps_revocation_authority_in_accounts(self):
        with mock.patch.object(
            brain_credentials_client,
            "_post",
            side_effect=((200, {"valid": True}), (409, {"valid": False})),
        ):
            self.assertTrue(brain_credentials_client.generation_is_current("account-1", "openai", 3))
            self.assertFalse(brain_credentials_client.generation_is_current("account-1", "openai", 3))

        with mock.patch.object(brain_credentials_client, "_post") as post:
            with self.assertRaises(brain_credentials_client.BrainCredentialError):
                brain_credentials_client.generation_is_current("account-1", "codex", 3)
            post.assert_not_called()

    def test_session_reuses_transport_without_reusing_authorization_results(self):
        class Response:
            status = 200

            @staticmethod
            def read(_maximum):
                return b'{"valid":true}'

        class Connection:
            def __init__(self) -> None:
                self.requests = 0
                self.closes = 0

            def request(self, *_args) -> None:
                self.requests += 1

            @staticmethod
            def getresponse():
                return Response()

            def close(self) -> None:
                self.closes += 1

        connection = Connection()
        constructors = mock.Mock(return_value=connection)
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_text("service-token", encoding="utf-8")
            with (
                mock.patch.object(brain_credentials_client.http.client, "HTTPConnection", constructors),
                brain_credentials_client.BrainCredentialSession() as session,
            ):
                first = brain_credentials_client._post(
                    "http://accounts:7079",
                    "/v1/internal/brains/generation-check",
                    {"generation": 1},
                    token_path,
                    session,
                )
                second = brain_credentials_client._post(
                    "http://accounts:7079",
                    "/v1/internal/brains/generation-check",
                    {"generation": 1},
                    token_path,
                    session,
                )

        self.assertEqual(first, (200, {"valid": True}))
        self.assertEqual(second, first)
        constructors.assert_called_once_with("accounts", 7079, timeout=10)
        self.assertEqual(connection.requests, 2)
        self.assertEqual(connection.closes, 1)

    def test_session_retries_once_when_an_idle_connection_was_closed(self):
        class Response:
            status = 200
            will_close = False

            @staticmethod
            def read(_maximum):
                return b'{"valid":true}'

        class Connection:
            def __init__(self, *, fail_on_request: int | None = None) -> None:
                self.fail_on_request = fail_on_request
                self.requests = 0
                self.closes = 0

            def request(self, *_args) -> None:
                self.requests += 1
                if self.requests == self.fail_on_request:
                    raise brain_credentials_client.http.client.RemoteDisconnected("idle close")

            @staticmethod
            def getresponse():
                return Response()

            def close(self) -> None:
                self.closes += 1

        stale = Connection(fail_on_request=2)
        replacement = Connection()
        constructors = mock.Mock(side_effect=(stale, replacement))
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_text("service-token", encoding="utf-8")
            with (
                mock.patch.object(brain_credentials_client.http.client, "HTTPConnection", constructors),
                brain_credentials_client.BrainCredentialSession() as session,
            ):
                first = brain_credentials_client._post(
                    "http://accounts:7079",
                    "/v1/internal/brains/generation-check",
                    {"generation": 1},
                    token_path,
                    session,
                )
                second = brain_credentials_client._post(
                    "http://accounts:7079",
                    "/v1/internal/brains/generation-check",
                    {"generation": 2},
                    token_path,
                    session,
                )

        self.assertEqual(first, (200, {"valid": True}))
        self.assertEqual(second, first)
        self.assertEqual(constructors.call_count, 2)
        self.assertEqual(stale.requests, 2)
        self.assertEqual(stale.closes, 1)
        self.assertEqual(replacement.requests, 1)
        self.assertEqual(replacement.closes, 1)

    def test_token_cache_reopens_metadata_and_rereads_only_after_replacement(self):
        brain_credentials_client._token_cache.clear()
        with tempfile.TemporaryDirectory() as directory:
            token_path = Path(directory) / "token"
            token_path.write_text("first-token", encoding="utf-8")
            original_read = brain_credentials_client.os.read
            with mock.patch.object(brain_credentials_client.os, "read", wraps=original_read) as read:
                self.assertEqual(brain_credentials_client._token(token_path), "first-token")
                self.assertEqual(brain_credentials_client._token(token_path), "first-token")
                first_read_count = read.call_count
                replacement = token_path.with_name("replacement")
                replacement.write_text("second-token", encoding="utf-8")
                replacement.replace(token_path)
                self.assertEqual(brain_credentials_client._token(token_path), "second-token")

        self.assertEqual(first_read_count, 1)
        self.assertEqual(read.call_count, 2)

    def test_volume_archive_helpers_are_not_part_of_the_runtime_contract(self):
        for absent_name in ("credential_file", "credential_archive", "resolve_archive"):
            with self.subTest(name=absent_name):
                self.assertFalse(hasattr(brain_credentials_client, absent_name))


if __name__ == "__main__":
    unittest.main()
