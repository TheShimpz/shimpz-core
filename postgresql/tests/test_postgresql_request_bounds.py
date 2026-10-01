"""Request deadlines, authentication before any body read, and the bounded linger after a refusal."""

from __future__ import annotations

import contextlib
import socket
import threading
import time
import unittest
from http import HTTPStatus
from unittest import mock

# Imported first: it prepares the file-backed environment the Service modules read at import time.
import test_postgresql_runtime as runtime

import app
import deadline
import stdlib_http


class PostgreSQLRequestBoundsTests(runtime.RuntimeTestCase):
    def test_deadline_reader_bounds_every_receive_by_the_remaining_time(self) -> None:
        connection, peer = socket.socketpair()
        try:
            connection.settimeout(7)
            peer.sendall(b"ab")
            buffer = bytearray(4)
            self.assertEqual(deadline.DeadlineReader(connection, time.monotonic() + 5).readinto(buffer), 2)
            self.assertEqual(bytes(buffer[:2]), b"ab")
            self.assertEqual(connection.gettimeout(), 7)

            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                deadline.DeadlineReader(connection, started + 0.05).readinto(bytearray(1))
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(connection.gettimeout(), 7)

            peer.sendall(b"c")
            expired = deadline.DeadlineReader(connection, time.monotonic() - 1)
            self.assertTrue(expired.readable())
            with self.assertRaisesRegex(TimeoutError, "deadline"):
                expired.readinto(bytearray(1))
            self.assertEqual(connection.recv(1), b"c")
        finally:
            connection.close()
            peer.close()

    def test_request_line_headers_and_body_share_one_absolute_deadline(self) -> None:
        # The idle timeout is far longer than the deadline, so only the absolute deadline can end a trickle.
        handler = type("DeadlineHandler", (app.Handler,), {"request_deadline_seconds": 0.3})
        server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler, max_concurrency=1, connection_timeout=30)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            trickled_headers = [b"GET /healthz HTTP/1.1\r\n", *([b"X-Trickle: 1\r\n"] * 200)]
            elapsed, response = self._trickle(server, trickled_headers)
            self.assertGreaterEqual(elapsed, 0.25)
            self.assertLess(elapsed, 3)
            self.assertEqual(response, b"")
            self._await_idle(server)
            self.assertEqual(self._request(server, "GET", "/healthz"), (HTTPStatus.OK, {"status": "ok"}))

            authenticated = (
                b"POST /v1/teams/finalize HTTP/1.1\r\nContent-Length: 200\r\n"
                + f"Authorization: Bearer {app._provisioner_token}\r\n\r\n".encode()
            )
            with mock.patch.object(app, "_finalize_team") as finalize:
                elapsed, response = self._trickle(server, [authenticated, *([b" "] * 200)])
            finalize.assert_not_called()
            self.assertLess(elapsed, 3)
            self.assertIn(b" 408 ", response.partition(b"\r\n")[0])
            self.assertIn(b"request body read timed out", response)
            self._await_idle(server)
            self.assertEqual(self._request(server, "GET", "/healthz"), (HTTPStatus.OK, {"status": "ok"}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_unauthenticated_mutation_is_refused_before_its_body_is_read(self) -> None:
        # The deadline is long and no body byte is ever sent: a prompt refusal proves the body was never awaited.
        handler = type("DeadlineHandler", (app.Handler,), {"request_deadline_seconds": 30})
        server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), handler, max_concurrency=1)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        refusals = (
            ("/v1/teams/drop", "", b"bearer required"),
            ("/v1/teams/provision", "Authorization: Bearer wrong\r\n", b"provisioner bearer required"),
            ("/v1/teams/drop", f"Authorization: Bearer {'b' * 64}\r\n", b"principal scope denied"),
            # UTF-8 bearer bytes decode as non-ASCII Latin-1 text: refused, never a constant-time comparison error.
            ("/v1/teams/provision", "Authorization: Bearer \u00e9\r\n", b"provisioner bearer required"),
            ("/v1/teams/drop", f"Authorization: Bearer {'\u00e9' * 64}\r\n", b"principal scope denied"),
        )
        try:
            for path, authorization, error in refusals:
                with self.subTest(error=error), mock.patch.object(stdlib_http, "read_json_body") as read_body:
                    head = f"POST {path} HTTP/1.1\r\nContent-Length: 1024\r\n{authorization}\r\n".encode()
                    elapsed, response = self._trickle(server, [head])
                    read_body.assert_not_called()
                    self.assertLess(elapsed, 3)
                    self.assertIn(b" 403 ", response.partition(b"\r\n")[0])
                    self.assertIn(error, response)
            self._await_idle(server)
            self.assertEqual(self._request(server, "GET", "/healthz"), (HTTPStatus.OK, {"status": "ok"}))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_refused_client_that_sent_its_body_still_receives_the_refusal(self) -> None:
        # Closing with an unread body would reset the connection; the bounded linger lets the refusal arrive first.
        server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), app.Handler, max_concurrency=1)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        body = b"x" * (48 * 1024)
        head = f"POST /v1/teams/provision HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        try:
            with mock.patch.object(stdlib_http, "read_json_body") as read_body:
                for attempt in range(50):
                    self._await_idle(server)
                    with socket.create_connection(server.server_address, timeout=5) as client:
                        client.sendall(head + body)
                        response = bytearray()
                        while chunk := client.recv(65536):
                            response.extend(chunk)
                    with self.subTest(attempt=attempt):
                        self.assertIn(b" 403 ", bytes(response).partition(b"\r\n")[0])
                        self.assertIn(b"bearer required", response)
            read_body.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_linger_close_discards_only_a_bounded_unread_remainder(self) -> None:
        connection, peer = socket.socketpair()
        try:
            peer.sendall(b"unread")
            peer.shutdown(socket.SHUT_WR)
            deadline.linger_close(connection, time.monotonic() + 5)
            self.assertEqual(peer.recv(1), b"")
        finally:
            connection.close()
            peer.close()

        connection, peer = socket.socketpair()
        try:
            peer.setblocking(False)
            sent = 0
            with contextlib.suppress(BlockingIOError):
                while sent < 4 * deadline.LINGER_MAX_BYTES:
                    sent += peer.send(b"x" * 4096)
            self.assertGreater(sent, deadline.LINGER_MAX_BYTES)
            deadline.linger_close(connection, time.monotonic() + 5)
            remaining = 0
            connection.setblocking(False)
            with contextlib.suppress(BlockingIOError):
                while chunk := connection.recv(65536):
                    remaining += len(chunk)
            self.assertEqual(remaining, sent - deadline.LINGER_MAX_BYTES)
        finally:
            connection.close()
            peer.close()

        for expires, linger in ((time.monotonic() - 1, 5.0), (time.monotonic() + 30, 0.05)):
            connection, peer = socket.socketpair()
            try:
                started = time.monotonic()
                with mock.patch.object(deadline, "LINGER_SECONDS", linger):
                    deadline.linger_close(connection, expires)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(peer.recv(1), b"")
            finally:
                connection.close()
                peer.close()

    @staticmethod
    def _await_idle(server: app.BoundedThreadingHTTPServer) -> None:
        """Wait until the previous connection released its worker slot, so the next one is never shed."""
        if not server._request_slots.acquire(timeout=5):
            raise AssertionError("the previous connection never released its worker slot")
        server._request_slots.release()

    @staticmethod
    def _trickle(server: app.BoundedThreadingHTTPServer, parts: list[bytes]) -> tuple[float, bytes]:
        """Send each part 20 ms apart until the server answers or closes; return the elapsed time and response."""
        PostgreSQLRequestBoundsTests._await_idle(server)
        started = time.monotonic()
        response = bytearray()
        with socket.create_connection(server.server_address, timeout=0.02) as client:
            for part in parts:
                try:
                    client.sendall(part)
                    chunk = client.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    break
                response.extend(chunk)
                break
            client.settimeout(5)
            with contextlib.suppress(OSError):
                while chunk := client.recv(65536):
                    response.extend(chunk)
        return time.monotonic() - started, bytes(response)


if __name__ == "__main__":
    unittest.main()
