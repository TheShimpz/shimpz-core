from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import assistant_manifest
import local_registry
import marketplace


class LocalRegistryConnectionTests(unittest.TestCase):
    def test_x_oauth_intent_matches_the_first_party_contract(self) -> None:
        digest = "127.0.0.1:5000/shimpz/shimpz-assistant@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps({"schema": 1, "shimpz_assistant_image": digest}),
                encoding="utf-8",
            )
            spec = local_registry.load_registry(path)["shimpz-assistant"]

        self.assertEqual(spec.secrets, {})
        self.assertEqual(spec.connections["x"].provider, "x")
        self.assertEqual(
            spec.connections["x"].scopes,
            ("offline.access", "tweet.read", "tweet.write", "users.read"),
        )
        for power in spec.powers.values():
            self.assertEqual(power.secrets, ())
            self.assertEqual(power.connections, ("x",))

        hosted = marketplace.APPS["shimpz-assistant"]
        self.assertEqual(
            assistant_manifest.reviewed_manifest_contract(
                allowed_hosts=spec.allowed_hosts,
                secrets=spec.secrets,
                powers=spec.powers,
                connections=spec.connections,
            ),
            assistant_manifest.reviewed_manifest_contract(
                allowed_hosts=hosted.allowed_hosts,
                secrets=hosted.assistant.secrets,
                powers=hosted.assistant.powers,
                connections=hosted.assistant.connections,
            ),
        )


if __name__ == "__main__":
    unittest.main()
