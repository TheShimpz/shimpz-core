from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import inference_config


class InferenceConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "inference"
        self.store = inference_config.InferenceConfigStore(self.root)

    def test_defaults_are_provider_metadata_not_a_capsule_image(self):
        config = inference_config.normalize()

        self.assertEqual(config.provider, "openai")
        self.assertEqual(config.model, "gpt-5.6-terra")
        self.assertNotIn("image", inference_config.PROVIDERS[config.provider])

    def test_exact_provider_catalog_is_accepted(self):
        expected = {
            "openai": {"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"},
            "anthropic": {
                "claude-fable-5",
                "claude-opus-4-8",
                "claude-sonnet-5",
                "claude-haiku-4-5-20251001",
            },
        }

        self.assertEqual(
            {provider: set(definition["models"]) for provider, definition in inference_config.PROVIDERS.items()},
            expected,
        )
        for provider, models in expected.items():
            for model in models:
                with self.subTest(provider=provider, model=model):
                    self.assertEqual(inference_config.normalize(provider, model).model, model)

    def test_save_and_load_preserve_only_provider_and_model(self):
        expected = inference_config.normalize("anthropic", "claude-sonnet-5")

        self.store.save("capsule_1", expected)
        actual = self.store.load("capsule_1")

        self.assertEqual(actual, expected)
        files = list(self.root.glob("*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(b"api_key", files[0].read_bytes())

    def test_replace_is_atomic_and_delete_is_idempotent(self):
        self.store.save("capsule_1", inference_config.normalize("openai", "gpt-5.5"))
        self.store.save("capsule_1", inference_config.normalize("anthropic", "claude-sonnet-5"))

        self.assertEqual(self.store.load("capsule_1").provider, "anthropic")
        self.assertEqual(list(self.root.glob("*.tmp")), [])
        self.store.delete("capsule_1")
        self.store.delete("capsule_1")
        with self.assertRaises(inference_config.InferenceConfigError):
            self.store.load("capsule_1")

    def test_unknown_cross_provider_and_unsafe_models_fail_closed(self):
        with self.assertRaises(inference_config.InferenceConfigError):
            inference_config.normalize("codex", "gpt-test")
        for provider, model in (
            ("openai", "gpt-999"),
            ("openai", "claude-sonnet-5"),
            ("anthropic", "gpt-5.6-terra"),
            ("openai", "../../model"),
        ):
            with self.subTest(provider=provider, model=model), self.assertRaises(inference_config.InferenceConfigError):
                inference_config.normalize(provider, model)
        with self.assertRaises(inference_config.InferenceConfigError):
            self.store.save("../capsule", inference_config.normalize())

    def test_persisted_model_outside_catalog_fails_closed(self):
        self.root.mkdir(parents=True)
        self.store._path("capsule_1").write_text(
            json.dumps(
                {
                    "schema": inference_config.SCHEMA,
                    "capsule": "capsule_1",
                    "provider": "openai",
                    "model": "gpt-999",
                }
            ),
            encoding="utf-8",
        )

        with self.assertRaises(inference_config.InferenceConfigError):
            self.store.load("capsule_1")


if __name__ == "__main__":
    unittest.main()
