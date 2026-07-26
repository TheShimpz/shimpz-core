from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from registry_auth import RegistryAuth, RegistryAuthError


class RegistryAuthTests(unittest.TestCase):
    def test_loads_secrets_and_creates_private_ephemeral_docker_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            username_path = root / "username"
            token_path = root / "token"
            username_path.write_text("registry-reader\n", encoding="ascii")
            token_path.write_text(f"{'x' * 32}\n", encoding="ascii")

            credentials = RegistryAuth.from_files(username_path, token_path)

            self.assertEqual(
                credentials.docker_auth_config(),
                {"username": "registry-reader", "password": "x" * 32},
            )
            self.assertNotIn("x" * 32, repr(credentials))
            with credentials.docker_config() as config_root:
                config_path = Path(config_root, "config.json")
                document = json.loads(config_path.read_bytes())
                encoded = document["auths"]["ghcr.io"]["auth"]
                self.assertEqual(
                    base64.b64decode(encoded),
                    f"registry-reader:{'x' * 32}".encode(),
                )
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(Path(config_root).exists())

    def test_rejects_missing_multiline_or_non_ascii_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            username_path = root / "username"
            token_path = root / "token"
            cases = (
                ("missing", None, "x" * 32),
                ("multiline", "registry-reader", "x" * 20 + "\nextra"),
                ("non-ascii", "registry-reader", "é" * 20),
            )
            for name, username, token in cases:
                username_path.unlink(missing_ok=True)
                token_path.unlink(missing_ok=True)
                if username is not None:
                    username_path.write_text(username, encoding="ascii")
                token_path.write_text(token, encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(RegistryAuthError):
                    RegistryAuth.from_files(username_path, token_path)


if __name__ == "__main__":
    unittest.main()
