"""Closed HTTP behavior for Controller-to-Developers decisions."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

from hosted_install.developers_client import (
    AssistantNotInstallableError,
    DevelopersClient,
    DevelopersClientError,
    InstallAuthorizationDeniedError,
)
from hosted_install.developers_controller_contract import CONTRACT_ROOT

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]
AUTHORIZATION_REQUEST = VECTORS["fixtures"]["install_authorization_request"]["value"]
AUTHORIZATION_RECEIPT = VECTORS["fixtures"]["install_authorization_receipt"]["value"]


class _Response:
    def __init__(self, status: int, value: object) -> None:
        self.status = status
        self._body = json.dumps(value, separators=(",", ":")).encode()

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class _Connection:
    response = _Response(500, {})
    requests: ClassVar[list[tuple[object, ...]]] = []

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.arguments = (args, kwargs)

    def request(self, *args: object, **kwargs: object) -> None:
        self.requests.append((*args, kwargs))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        pass


class DevelopersClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        token = Path(self.directory.name) / "token"
        token.write_text("t" * 48, encoding="ascii")
        self.client = DevelopersClient(token)
        _Connection.requests = []

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_resolve_uses_fixed_internal_target_and_validates_response(self) -> None:
        _Connection.response = _Response(200, copy.deepcopy(RESOLUTION))
        with mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection):
            value = self.client.resolve(RESOLUTION["source_digest"])

        self.assertEqual(value, RESOLUTION)
        method, path, request = _Connection.requests[0]
        self.assertEqual((method, path), ("GET", f"/internal/v1/assistants/{RESOLUTION['source_digest']}"))
        self.assertEqual(request["headers"]["Authorization"], f"Bearer {'t' * 48}")

    def test_authorization_request_and_receipt_are_both_closed(self) -> None:
        _Connection.response = _Response(200, copy.deepcopy(AUTHORIZATION_RECEIPT))
        with mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection):
            value = self.client.authorize_install(copy.deepcopy(AUTHORIZATION_REQUEST))

        self.assertEqual(value, AUTHORIZATION_RECEIPT)
        body = _Connection.requests[0][2]["body"]
        self.assertEqual(json.loads(body), AUTHORIZATION_REQUEST)

    def test_safe_statuses_and_malformed_success_fail_closed(self) -> None:
        cases = (
            ("not-installable", 404, AssistantNotInstallableError),
            ("unavailable", 503, DevelopersClientError),
        )
        for name, status, error in cases:
            _Connection.response = _Response(status, {})
            with (
                self.subTest(name=name),
                mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection),
                self.assertRaises(error),
            ):
                self.client.resolve(RESOLUTION["source_digest"])

        _Connection.response = _Response(403, {})
        with (
            mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection),
            self.assertRaises(InstallAuthorizationDeniedError),
        ):
            self.client.authorize_install(copy.deepcopy(AUTHORIZATION_REQUEST))

        malformed = copy.deepcopy(RESOLUTION)
        malformed["image_reference"] = "ghcr.io/attacker/image@sha256:" + "0" * 64
        _Connection.response = _Response(200, malformed)
        with (
            mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection),
            self.assertRaises(DevelopersClientError),
        ):
            self.client.resolve(RESOLUTION["source_digest"])

        mismatched = copy.deepcopy(RESOLUTION)
        mismatched["source_digest"] = "sha256:" + "9" * 64
        _Connection.response = _Response(200, mismatched)
        with (
            mock.patch("hosted_install.developers_client.http.client.HTTPConnection", _Connection),
            self.assertRaises(DevelopersClientError),
        ):
            self.client.resolve(RESOLUTION["source_digest"])


if __name__ == "__main__":
    unittest.main()
