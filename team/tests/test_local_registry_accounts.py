from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import assistant_manifest
import local_registry
import marketplace


class LocalRegistryAccountTests(unittest.TestCase):
    def test_x_oauth_intent_matches_the_first_party_contract(self) -> None:
        digest = "127.0.0.1:5000/shimpz/shimpz-assistant@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps({"schema": 1, "shimpz_assistant_image": digest}),
                encoding="utf-8",
            )
            spec = local_registry.load_registry(path)["shimpz-assistant"]

        self.assertEqual(
            set(spec.secrets),
            {"mux-token-id", "mux-token-secret", "mux-webhook-signing-secret"},
        )
        self.assertEqual(spec.accounts["x"].provider, "x")
        self.assertEqual(
            spec.accounts["x"].scopes,
            ("offline.access", "tweet.read", "tweet.write", "users.read"),
        )
        x_powers = {"public-user-lookup", "identity-me", "create-post", "delete-post"}
        mux_api_powers = {"list-direct-uploads", "create-test-direct-upload", "cancel-direct-upload"}
        for power_id, power in spec.powers.items():
            self.assertEqual(power.accounts, ("x",) if power_id in x_powers else ())
            self.assertEqual(
                power.secrets,
                ("mux-token-id", "mux-token-secret")
                if power_id in mux_api_powers
                else ("mux-webhook-signing-secret",)
                if power_id == "verify-mux-webhook"
                else (),
            )

        hosted = marketplace.APPS["shimpz-assistant"]
        self.assertEqual(
            assistant_manifest.reviewed_manifest_contract(
                allowed_hosts=spec.allowed_hosts,
                secrets=spec.secrets,
                powers=spec.powers,
                accounts=spec.accounts,
            ),
            assistant_manifest.reviewed_manifest_contract(
                allowed_hosts=hosted.allowed_hosts,
                secrets=hosted.assistant.secrets,
                powers=hosted.assistant.powers,
                accounts=hosted.assistant.accounts,
            ),
        )


if __name__ == "__main__":
    unittest.main()
