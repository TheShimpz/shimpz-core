"""Characterize the shared hosted/local HTTP boundary decisions."""

from __future__ import annotations

import sys
import unittest
from email.message import Message
from http import HTTPStatus
from io import BytesIO
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import local_app
from test_hosted_app import app


class SharedStrictHttpTest(unittest.TestCase):
    @staticmethod
    def _handler(handler_type: type, body: bytes, headers: tuple[tuple[str, str], ...]):
        handler = object.__new__(handler_type)
        handler.headers = Message()
        for name, value in headers:
            handler.headers.add_header(name, value)
        handler.rfile = BytesIO(body)
        return handler

    def test_hosted_and_local_wrappers_make_the_same_body_decision(self) -> None:
        cases = (
            (b'{"a":1,"a":2}', (("Content-Type", "application/json"),), HTTPStatus.BAD_REQUEST),
            (b'{"a":NaN}', (("Content-Type", "application/json"),), HTTPStatus.BAD_REQUEST),
            (b"[]", (("Content-Type", "application/json"),), HTTPStatus.UNPROCESSABLE_ENTITY),
            (b"{}", (("Transfer-Encoding", "chunked"),), HTTPStatus.BAD_REQUEST),
        )
        for body, extra_headers, expected in cases:
            headers = (("Content-Length", str(len(body))), *extra_headers)
            hosted = self._handler(app.Handler, body, headers)
            local = self._handler(local_app.Handler, body, headers)
            with self.subTest(body=body):
                with self.assertRaises(app.ApiError) as hosted_error:
                    hosted._read_body()
                with self.assertRaises(local_app.ApiProblem) as local_error:
                    local._body()
                self.assertEqual((hosted_error.exception.status, local_error.exception.status), (expected, expected))

    def test_hosted_and_local_wrappers_reject_the_same_encoded_route(self) -> None:
        hosted = self._handler(app.Handler, b"", ())
        hosted.path = "/v1/teams/%74eam_1"
        local = self._handler(local_app.Handler, b"", ())
        local.path = hosted.path

        with self.assertRaises(app.ApiError) as hosted_error:
            hosted._route("GET", ("operator", None))
        with self.assertRaises(local_app.ApiProblem) as local_error:
            local._path_parts()

        self.assertEqual(
            (hosted_error.exception.status, local_error.exception.status),
            (HTTPStatus.BAD_REQUEST, HTTPStatus.BAD_REQUEST),
        )


if __name__ == "__main__":
    unittest.main()
