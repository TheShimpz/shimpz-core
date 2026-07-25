"""Bounded cache for Assistant guidance stored in `shimpz.toml`."""

from __future__ import annotations

import threading
from collections import OrderedDict

import assistant_manifest

GENESIS_PATH = assistant_manifest.MANIFEST_PATH
DEFAULT_CACHE_ENTRIES = 256


class GenesisError(RuntimeError):
    """An immutable Assistant manifest did not expose safe model guidance."""


def read_container_genesis(container) -> str:
    """Read `genesis` from the fixed, read-only Spec v1 manifest."""
    try:
        return assistant_manifest.read_container_manifest_genesis(container)
    except assistant_manifest.ManifestError as exc:
        raise GenesisError("Assistant Genesis is invalid") from exc


class GenesisCache:
    """Read Genesis once per immutable container generation with a bounded LRU."""

    def __init__(self, max_entries: int = DEFAULT_CACHE_ENTRIES) -> None:
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
            raise ValueError("Genesis cache size must be positive")
        self._max_entries = max_entries
        self._entries: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, container) -> str:
        container_id = getattr(container, "id", None)
        if (
            not isinstance(container_id, str)
            or not container_id
            or len(container_id) > 256
            or any(not character.isalnum() and character not in {"-", "_", "."} for character in container_id)
        ):
            raise GenesisError("Assistant container identity is invalid")
        with self._lock:
            cached = self._entries.get(container_id)
            if cached is not None:
                self._entries.move_to_end(container_id)
                return cached
            genesis = read_container_genesis(container)
            self._entries[container_id] = genesis
            self._entries.move_to_end(container_id)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
            return genesis

    def discard(self, container_id: object) -> None:
        if isinstance(container_id, str):
            with self._lock:
                self._entries.pop(container_id, None)
