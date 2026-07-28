"""Exact container envelope for published direct-runtime Assistants."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import manifests
from hosted_install.developers_controller_contract import CONTRACT_ROOT
from hosted_install.dynamic_assistants import DynamicAssistantStore, app_spec

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]


class DynamicAssistantRuntimeTests(unittest.TestCase):
    def test_direct_runtime_is_digest_only_nonroot_readonly_and_mountless(self) -> None:
        resolution = copy.deepcopy(RESOLUTION)
        power = resolution["machine_contract"]["powers"][0]
        power["input_schema"]["additionalProperties"] = False
        power["output_schema"]["additionalProperties"] = False
        with tempfile.TemporaryDirectory() as directory:
            store = DynamicAssistantStore(Path(directory) / "bindings.json")
            spec = app_spec(store.put("team_1", resolution))

        kwargs = manifests.build_dynamic_assistant_kwargs(
            "team_1",
            "hello-world",
            spec,
            owner="creator_1",
            source_digest=RESOLUTION["source_digest"],
        )

        self.assertEqual(kwargs["image"], RESOLUTION["image_reference"])
        self.assertEqual(kwargs["runtime"], "runsc")
        self.assertEqual(kwargs["user"], "10001:10001")
        self.assertTrue(kwargs["read_only"])
        self.assertEqual(
            kwargs["tmpfs"],
            {manifests.CONTAINER_TMP: "size=64m,mode=1777"},
        )
        self.assertEqual(kwargs["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", kwargs["security_opt"])
        self.assertFalse(kwargs["privileged"])
        self.assertNotIn("volumes", kwargs)
        self.assertNotIn("mounts", kwargs)
        self.assertNotIn("ports", kwargs)
        self.assertNotIn("command", kwargs)
        self.assertNotIn("entrypoint", kwargs)
        self.assertNotIn("PORT", kwargs["environment"])
        self.assertNotIn("DATABASE_URL", kwargs["environment"])
        self.assertEqual(kwargs["labels"]["team.app.dynamic"], "1")
        self.assertEqual(kwargs["labels"]["team.app.source"], RESOLUTION["source_digest"])


if __name__ == "__main__":
    unittest.main()
