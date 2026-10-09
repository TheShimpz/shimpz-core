"""Absolute request deadlines for the PostgreSQL Service's stdlib HTTP boundary."""

import contextlib
import io
import socket
import time
from http import HTTPStatus
from typing import BinaryIO

from stdlib_http import HttpError

LINGER_SECONDS = 1.0
LINGER_MAX_BYTES = 64 * 1024


class DeadlineReader(io.RawIOBase):
    """Receive one connection's request bytes only until an absolute monotonic deadline.

    Each receive waits at most for the deadline's remainder, so bytes trickling inside every socket timeout cannot
    stretch the request line, headers, or body past the deadline. The socket's own timeout is restored after each
    receive so the response is still written under the ordinary connection timeout.
    """

    def __init__(self, connection: socket.socket, deadline: float) -> None:
        super().__init__()
        self._connection = connection
        self._deadline = deadline
        self._timeout = connection.gettimeout()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self._connection.settimeout(remaining)
        try:
            return self._connection.recv_into(buffer)
        finally:
            self._connection.settimeout(self._timeout)


class ExactBody:
    """Read a declared body completely or fail typed: 408 past the deadline, 400 when the peer sends fewer bytes."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self.complete = False

    def read(self, length: int) -> bytes:
        try:
            raw = self._stream.read(length)
        except TimeoutError as exc:
            raise HttpError(HTTPStatus.REQUEST_TIMEOUT, "request body read timed out") from exc
        if len(raw) != length:
            raise HttpError(HTTPStatus.BAD_REQUEST, "request body is incomplete")
        self.complete = True
        return raw


def linger_close(connection: socket.socket, expires: float) -> None:
    """Half-close after a response that left a body unread, then discard a bounded remainder before the close.

    Closing a socket that still holds unread request bytes makes the kernel reset the connection, which can destroy a
    refusal the peer has not read yet. The discarded bytes are never parsed, at most LINGER_MAX_BYTES are read, and the
    wait ends at the earlier of the request deadline and LINGER_SECONDS from now, so lingering cannot extend a trickle.
    """
    with contextlib.suppress(OSError):
        connection.shutdown(socket.SHUT_WR)
        reader = DeadlineReader(connection, min(expires, time.monotonic() + LINGER_SECONDS))
        buffer = memoryview(bytearray(LINGER_MAX_BYTES))
        discarded = 0
        while discarded < LINGER_MAX_BYTES and (received := reader.readinto(buffer[discarded:])):
            discarded += received
