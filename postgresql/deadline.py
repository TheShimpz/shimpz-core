"""Absolute request deadlines for the PostgreSQL Service's stdlib HTTP boundary."""

from __future__ import annotations

import io
import socket
import time
from http import HTTPStatus
from typing import BinaryIO

from stdlib_http import HttpError


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

    def read(self, length: int) -> bytes:
        try:
            raw = self._stream.read(length)
        except TimeoutError as exc:
            raise HttpError(HTTPStatus.REQUEST_TIMEOUT, "request body read timed out") from exc
        if len(raw) != length:
            raise HttpError(HTTPStatus.BAD_REQUEST, "request body is incomplete")
        return raw
