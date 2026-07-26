"""Security contract for Developers-to-Controller Ed25519 delegations."""

from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from developers_controller_contract import CONTRACT_ROOT
from developers_delegation import DevelopersDelegationError, DevelopersDelegationVerifier

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
INSTALL = VECTORS["fixtures"]["assistant_install_delegation"]["value"]
REQUEST = VECTORS["fixtures"]["controller_install_request"]["value"]


def _segment(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class DevelopersDelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.private_key = Ed25519PrivateKey.generate()
        (root / "token").write_text("s" * 48, encoding="ascii")
        (root / "public.pem").write_bytes(
            self.private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        self.verifier = DevelopersDelegationVerifier(root / "token", root / "public.pem")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def _jwt(self, claims: dict[str, object]) -> str:
        header = _segment({"alg": "EdDSA", "kid": "developers-v1", "typ": "JWT"})
        payload = _segment(claims)
        signature = self.private_key.sign(f"{header}.{payload}".encode())
        return f"{header}.{payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

    def _headers(self, claims: dict[str, object]) -> Message:
        headers = Message()
        headers["Authorization"] = f"Bearer {'s' * 48}"
        headers["X-Shimpz-Delegation"] = f"Bearer {self._jwt(claims)}"
        return headers

    def test_accepts_exact_request_bound_install_once(self) -> None:
        claims = copy.deepcopy(INSTALL)

        verified = self.verifier.verify(
            self._headers(claims),
            action="assistant:install",
            request=copy.deepcopy(REQUEST),
            now=1000,
        )

        self.assertEqual(verified, claims)
        with self.assertRaises(DevelopersDelegationError):
            self.verifier.verify(
                self._headers(claims),
                action="assistant:install",
                request=copy.deepcopy(REQUEST),
                now=1000,
            )

    def test_rejects_wrong_service_token_signature_and_request_binding(self) -> None:
        wrong_bearer = self._headers(copy.deepcopy(INSTALL))
        wrong_bearer.replace_header("Authorization", "Bearer " + "x" * 48)
        wrong_signature = self._headers(copy.deepcopy(INSTALL))
        token = wrong_signature["X-Shimpz-Delegation"]
        wrong_signature.replace_header("X-Shimpz-Delegation", f"{token[:-1]}A")
        mismatched_request = {**REQUEST, "team_id": "team_2"}

        for name, headers, request in (
            ("service", wrong_bearer, REQUEST),
            ("signature", wrong_signature, REQUEST),
            ("binding", self._headers(copy.deepcopy(INSTALL)), mismatched_request),
        ):
            with self.subTest(name=name), self.assertRaises(DevelopersDelegationError):
                self.verifier.verify(
                    headers,
                    action="assistant:install",
                    request=copy.deepcopy(request),
                    now=1000,
                )

    def test_rejects_expired_future_duplicate_and_noncanonical_tokens(self) -> None:
        expired = {**INSTALL, "iat": 900, "exp": 960, "jti": "expired"}
        future = {**INSTALL, "iat": 1010, "exp": 1070, "jti": "future"}
        duplicate = self._headers(copy.deepcopy(INSTALL))
        duplicate["Authorization"] = f"Bearer {'s' * 48}"

        for name, headers in (
            ("expired", self._headers(expired)),
            ("future", self._headers(future)),
            ("duplicate-header", duplicate),
        ):
            with self.subTest(name=name), self.assertRaises(DevelopersDelegationError):
                self.verifier.verify(
                    headers,
                    action="assistant:install",
                    request=copy.deepcopy(REQUEST),
                    now=1000,
                )


if __name__ == "__main__":
    unittest.main()
