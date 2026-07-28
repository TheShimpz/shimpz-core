"""Hosted and local Assistant writable-temp parity."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import manifests
from assistant_human import marketplace
from local_controller_harness import LocalContractCase


class AssistantTmpfsParity(LocalContractCase):
    def test_local_and_hosted_assistants_share_the_same_tmpfs(self):
        hosted = manifests.build_team_app_kwargs(
            "team_1",
            "shimpz-cloudflare",
            marketplace.APPS["shimpz-cloudflare"],
        )["tmpfs"]
        controller, _existing, _events = self._lifecycle_controller()
        captured = {}
        created = SimpleNamespace(
            id="new",
            attrs={"Image": "img-id"},
            reload=lambda: None,
            start=lambda: None,
        )
        controller.assistant_lifecycle.client.containers.create = lambda **kwargs: captured.update(kwargs) or created
        controller.assistant_lifecycle._admit_assistant_allowed_hosts = lambda *_args: ()
        controller.assistant_lifecycle._validate_container = lambda *_args: None
        controller.assistant_lifecycle._wait_ready = lambda *_args: None
        controller.assistant_lifecycle._active_assistant_genesis = lambda *_args: None
        spec = controller.registry["shimpz-cloudflare"]
        network = controller.assistant_lifecycle._network("team_1")

        controller.assistant_lifecycle._create_assistant_container(
            "team_1",
            spec,
            network,
            SimpleNamespace(id="img-id"),
        )

        self.assertEqual(captured["tmpfs"], hosted)
        self.assertEqual(hosted, {manifests.CONTAINER_TMP: "size=256m"})
