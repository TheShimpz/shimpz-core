"""Process-wide admission for the disk-heavy private backup transfer plane."""

from __future__ import annotations

import threading
from contextlib import contextmanager


class BackupTransferBusyError(RuntimeError):
    """Another private upload or recovery range owns the single spool budget."""


class BackupTransferGate:
    """Admit exactly one private transfer without making an HTTP worker wait."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    @contextmanager
    def claim(self):
        if not self._lock.acquire(blocking=False):
            raise BackupTransferBusyError("another private backup transfer is active")
        try:
            yield
        finally:
            self._lock.release()
