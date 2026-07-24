"""Fail-closed transport contracts for account-session verification."""

from __future__ import annotations

import json
import socket
import socketserver
import sys
import threading
import unittest
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import accounts_client


class _AccountsHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        token = json.loads(self.rfile.read(length))["token"]
        status, body = {
            "valid": (HTTPStatus.OK, b'{"account_id":"account_1"}'),
            "denied": (HTTPStatus.FORBIDDEN, b'{"account_id":"account_1"}'),
            "empty": (HTTPStatus.OK, b""),
            "array": (HTTPStatus.OK, b'["account_1"]'),
        }[token]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _GarbageStatusHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.recv(4096)
        self.request.sendall(b"this is not HTTP\r\n")


class _TimeoutHandler(socketserver.BaseRequestHandler):
    release = threading.Event()

    def handle(self) -> None:
        self.request.recv(4096)
        self.release.wait(timeout=1)


@contextmanager
def _server(server_type, handler_type):
    server = server_type(("127.0.0.1", 0), handler_type)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        if handler_type is _TimeoutHandler:
            handler_type.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if handler_type is _TimeoutHandler:
            handler_type.release.clear()


class AccountsClientTests(unittest.TestCase):
    def setUp(self) -> None:
        accounts_client._reset_state()

    def tearDown(self) -> None:
        accounts_client._reset_state()

    def test_http_verdicts_and_malformed_shapes_never_escape(self) -> None:
        with (
            _server(ThreadingHTTPServer, _AccountsHandler) as port,
            mock.patch.object(accounts_client, "ACCOUNTS_URL", f"http://127.0.0.1:{port}"),
        ):
            self.assertEqual(accounts_client.verify("valid"), "account_1")
            for token in ("denied", "empty", "array"):
                with self.subTest(token=token):
                    self.assertIsNone(accounts_client.verify(token))

    def test_bad_status_line_fails_closed(self) -> None:
        with (
            _server(socketserver.TCPServer, _GarbageStatusHandler) as port,
            mock.patch.object(accounts_client, "ACCOUNTS_URL", f"http://127.0.0.1:{port}"),
        ):
            self.assertIsNone(accounts_client.verify("token"))

    def test_connection_refusal_fails_closed(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with mock.patch.object(accounts_client, "ACCOUNTS_URL", f"http://127.0.0.1:{port}"):
            self.assertIsNone(accounts_client.verify("token"))

    def test_malformed_accounts_url_fails_closed(self) -> None:
        with mock.patch.object(accounts_client, "ACCOUNTS_URL", "http://accounts:not-a-port"):
            self.assertIsNone(accounts_client.verify("token"))

    def test_timeout_fails_closed(self) -> None:
        with (
            _server(socketserver.TCPServer, _TimeoutHandler) as port,
            mock.patch.object(accounts_client, "ACCOUNTS_URL", f"http://127.0.0.1:{port}"),
            mock.patch.object(accounts_client, "VERIFY_TIMEOUT_SECONDS", 0.05),
        ):
            self.assertIsNone(accounts_client.verify("token"))

    def test_empty_token_never_opens_a_connection(self) -> None:
        with mock.patch.object(accounts_client.http.client, "HTTPConnection") as connection:
            self.assertIsNone(accounts_client.verify(""))
        connection.assert_not_called()

    def test_successes_are_cached_but_failures_are_not(self) -> None:
        response = mock.Mock(status=HTTPStatus.OK)
        response.read.return_value = b'{"account_id":"account_1"}'
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with (
            mock.patch.object(accounts_client, "ACCOUNTS_URL", "http://cache.test:7079"),
            mock.patch.object(accounts_client.http.client, "HTTPConnection", return_value=connection),
        ):
            self.assertEqual(accounts_client.verify("cache-token"), "account_1")
            self.assertEqual(accounts_client.verify("cache-token"), "account_1")

        connection.request.assert_called_once()

        denied = mock.Mock(status=HTTPStatus.FORBIDDEN)
        denied.read.return_value = b"{}"
        connection.getresponse.return_value = denied
        with (
            mock.patch.object(accounts_client, "ACCOUNTS_URL", "http://cache.test:7079"),
            mock.patch.object(accounts_client.http.client, "HTTPConnection", return_value=connection),
        ):
            self.assertIsNone(accounts_client.verify("denied-token"))
            self.assertIsNone(accounts_client.verify("denied-token"))

        self.assertEqual(connection.request.call_count, 3)

    def test_distinct_verifications_reuse_one_pooled_connection(self) -> None:
        responses = []
        for account_id in ("account_1", "account_2"):
            response = mock.Mock(status=HTTPStatus.OK)
            response.read.return_value = json.dumps({"account_id": account_id}).encode()
            responses.append(response)
        connection = mock.Mock()
        connection.getresponse.side_effect = responses
        with (
            mock.patch.object(accounts_client, "ACCOUNTS_URL", "http://pool.test:7079"),
            mock.patch.object(
                accounts_client.http.client,
                "HTTPConnection",
                return_value=connection,
            ) as connection_class,
        ):
            self.assertEqual(accounts_client.verify("first-token"), "account_1")
            self.assertEqual(accounts_client.verify("second-token"), "account_2")

        connection_class.assert_called_once_with("pool.test", 7079, timeout=accounts_client.VERIFY_TIMEOUT_SECONDS)
        self.assertEqual(connection.request.call_count, 2)

    def test_verification_cache_is_ttl_bounded_lru(self) -> None:
        first, second, third = (value.encode() for value in ("first", "second", "third"))
        with mock.patch.object(accounts_client, "VERIFY_CACHE_MAX_ENTRIES", 2):
            accounts_client._cache_verification(first, "account_1", 0)
            accounts_client._cache_verification(second, "account_2", 1)
            self.assertEqual(accounts_client._cached_verification(first, 2), "account_1")
            accounts_client._cache_verification(third, "account_3", 3)

        self.assertIsNone(accounts_client._cached_verification(second, 4))
        self.assertEqual(accounts_client._cached_verification(third, 4), "account_3")
        self.assertIsNone(accounts_client._cached_verification(first, accounts_client.VERIFY_CACHE_TTL_SECONDS))


if __name__ == "__main__":
    unittest.main()
