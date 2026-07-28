from __future__ import annotations

import io
import tarfile
import unittest

from assistant_human import assistant_genesis


def manifest(genesis: str = "Use only the declared Powers.") -> bytes:
    return f"""
spec = 1
id = "fixture"
version = "0.1.0"
name = "Fixture"
summary = "Exercise Genesis admission."
creators = ["@fixture"]
github = "https://github.com/TheShimpz/fixture"
allowed_hosts = []
genesis = \"\"\"
{genesis}
\"\"\"
""".encode()


def archive(content: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as bundle:
        member = tarfile.TarInfo("shimpz.toml")
        member.size = len(content)
        member.mode = 0o444
        bundle.addfile(member, io.BytesIO(content))
    return output.getvalue()


class Container:
    def __init__(self, container_id: str, content: bytes) -> None:
        self.id = container_id
        self.content = content
        self.reads = 0

    def get_archive(self, path: str):
        self.reads += 1
        if path != assistant_genesis.GENESIS_PATH:
            raise AssertionError(path)
        payload = archive(self.content)
        return iter((payload,)), {
            "name": "shimpz.toml",
            "size": len(self.content),
            "mode": 0o444,
        }


class AssistantGenesisTests(unittest.TestCase):
    def test_reads_genesis_from_the_spec_v1_manifest(self) -> None:
        container = Container("generation", manifest("Inspect DNS safely.\n"))

        self.assertEqual(assistant_genesis.read_container_genesis(container), "Inspect DNS safely.")
        self.assertEqual(container.reads, 1)

    def test_invalid_manifest_fails_without_echoing_it(self) -> None:
        private = "private-value-123456789"
        container = Container("generation", manifest(private) + b"unknown = true\n")

        with self.assertRaises(assistant_genesis.GenesisError) as caught:
            assistant_genesis.read_container_genesis(container)
        self.assertNotIn(private, str(caught.exception))

    def test_cache_reads_each_immutable_generation_once(self) -> None:
        first = Container("first", manifest("First."))
        second = Container("second", manifest("Second."))
        cache = assistant_genesis.GenesisCache(max_entries=1)

        self.assertEqual(cache.get(first), "First.")
        self.assertEqual(cache.get(first), "First.")
        self.assertEqual(first.reads, 1)
        self.assertEqual(cache.get(second), "Second.")
        self.assertEqual(cache.get(first), "First.")
        self.assertEqual(first.reads, 2)


if __name__ == "__main__":
    unittest.main()
