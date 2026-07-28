from __future__ import annotations

import types
import unittest
from collections import Counter
from unittest import mock

from hosted_app_fixture import (
    ANCHOR_ID,
    hosted_apps,
    hosted_assistants,
    hosted_chat_segment,
    hosted_resources,
    runtime_state,
)

dynamic_assistants = hosted_resources.dynamic_assistants
manifests = hosted_resources.manifests
marketplace = hosted_assistants.marketplace
network_policy = hosted_resources.network_policy

TEAM_ID = "team_1"
OWNER = "account_1"
ASSISTANT_IDS = ("dynamic-one", "dynamic-two")
TOKEN = "a" * 32


class CountingContainer:
    def __init__(self, identity: str, labels: dict[str, str], image: str, calls: Counter) -> None:
        self.id = identity
        self.name = identity
        self.labels = labels
        self.status = "running"
        self.attrs = {
            "Config": {
                "Env": [
                    f"HTTPS_PROXY=http://{TOKEN}@app-egress-proxy:8889",
                    f"https_proxy=http://{TOKEN}@app-egress-proxy:8889",
                    "NO_PROXY=localhost,127.0.0.1,::1,postgres,.team",
                    "no_proxy=localhost,127.0.0.1,::1,postgres,.team",
                ],
                "Image": image,
                "Labels": labels,
            },
            "HostConfig": {"Runtime": manifests.RUNTIME},
            "State": {"Running": True},
        }
        self._calls = calls

    def reload(self) -> None:
        self._calls["container.reload"] += 1


class CountingNetwork:
    def __init__(self, member_ids: tuple[str, ...], calls: Counter) -> None:
        self.id = "core-network-id"
        self.attrs = {"Containers": dict.fromkeys(member_ids)}
        self._calls = calls

    def reload(self) -> None:
        self._calls["network.reload"] += 1


class CountingDynamicStore:
    def __init__(self, bindings: dict[str, object], calls: Counter) -> None:
        self._bindings = bindings
        self._calls = calls

    def get(self, team_id: str, assistant_id: str):
        self._calls["registry.read"] += 1
        return self._bindings.get(assistant_id) if team_id == TEAM_ID else None

    def list(self, team_id: str):
        self._calls["registry.read"] += 1
        return tuple(self._bindings.values()) if team_id == TEAM_ID else ()


class CountingEgressStore:
    def __init__(self, calls: Counter) -> None:
        self._calls = calls

    def validate(self, _identity: str, _hosts: tuple[str, ...]) -> str:
        self._calls["egress.file-read"] += 2
        return TOKEN

    @staticmethod
    def proxy_environment(_token: str) -> dict[str, str]:
        proxy = f"http://{TOKEN}@app-egress-proxy:8889"
        no_proxy = "localhost,127.0.0.1,::1,postgres,.team"
        return {
            "HTTPS_PROXY": proxy,
            "https_proxy": proxy,
            "NO_PROXY": no_proxy,
            "no_proxy": no_proxy,
        }


class HostedCheckHarness:
    def __init__(self, assistant_count: int, member_count: int) -> None:
        self.calls: Counter = Counter()
        self.spec = marketplace.APPS["shimpz-cloudflare"]
        self.config = types.SimpleNamespace(provider="openai", model="gpt-test")
        self.files = [{"id": "f" * 32, "name": "brief.txt", "media_type": "text/plain", "size": 5}]
        selected_ids = ASSISTANT_IDS[:assistant_count]
        self.anchor = CountingContainer(
            ANCHOR_ID,
            {"team.id": TEAM_ID, "team.brain": "runtime", "team.name": "Marketing", "team.owner": OWNER},
            manifests.BRAINS["runtime"]["image"],
            self.calls,
        )
        self.assistants = tuple(
            hosted_assistants._ActiveAssistant(
                assistant_id,
                self.spec.assistant,
                CountingContainer(
                    str(index + 1) * 64,
                    {"team.id": TEAM_ID, "team.app": assistant_id},
                    self.spec.image,
                    self.calls,
                ),
                self.spec.image,
            )
            for index, assistant_id in enumerate(selected_ids)
        )
        members = (self.anchor, *(active.container for active in self.assistants))
        extras = tuple(
            CountingContainer(f"member-{index}", {"team.id": TEAM_ID}, self.spec.image, self.calls)
            for index in range(max(0, member_count - len(members)))
        )
        self.members = (*members, *extras)[:member_count]
        self.network = CountingNetwork(tuple(member.id for member in self.members), self.calls)
        self.bindings = {
            active.assistant_id: types.SimpleNamespace(
                team_id=TEAM_ID,
                assistant_id=active.assistant_id,
                binding_digest=f"sha256:{str(index + 1) * 64}",
            )
            for index, active in enumerate(self.assistants)
        }

    def _container(self, identity: str):
        self.calls["docker.containers.get"] += 1
        by_identity = {
            manifests.team_container_name(TEAM_ID): self.anchor,
            self.anchor.id: self.anchor,
            **{
                manifests.team_app_container_name(TEAM_ID, active.assistant_id): active.container
                for active in self.assistants
            },
            **{member.id: member for member in self.members},
        }
        return by_identity[identity]

    def _network(self, _identity: str):
        self.calls["docker.networks.get"] += 1
        return self.network

    def _image(self, _identity: str):
        self.calls["docker.images.get"] += 1
        return types.SimpleNamespace(id="sha256:" + "e" * 64)

    def _egress_store(self):
        self.calls["egress.store"] += 1
        return CountingEgressStore(self.calls)

    def _storage(self):
        def metadata(_team_id, _file_ids):
            self.calls["sqlite.connect"] += 1
            self.calls["sqlite.query"] += 1
            return self.files

        return types.SimpleNamespace(metadata=metadata)

    def _inference(self, _team_id: str):
        self.calls["inference.read"] += 1
        return self.config

    def _credential(self, *_args) -> None:
        self.calls["credential.query"] += 1

    def _app_spec(self, _binding):
        self.calls["registry.validate"] += 1
        return self.spec

    def run(self) -> tuple[object, ...]:
        engine = types.SimpleNamespace(
            containers=types.SimpleNamespace(get=self._container),
            networks=types.SimpleNamespace(get=self._network),
            images=types.SimpleNamespace(get=self._image),
        )
        request = hosted_chat_segment.HostedChatSegmentRequest(
            TEAM_ID,
            ["f" * 32],
            tuple(active.assistant_id for active in self.assistants),
            "turn-token",
            self.anchor,
            OWNER,
        )
        with (
            mock.patch.object(runtime_state, "_docker", engine),
            mock.patch.object(runtime_state, "_dynamic_assistants", CountingDynamicStore(self.bindings, self.calls)),
            mock.patch.object(runtime_state, "_storage", side_effect=self._storage),
            mock.patch.object(runtime_state, "_inference_store", types.SimpleNamespace(load=self._inference)),
            mock.patch.object(dynamic_assistants, "app_spec", side_effect=self._app_spec),
            mock.patch.object(hosted_apps, "_egress_store", side_effect=self._egress_store),
            mock.patch.object(hosted_apps, "_require_assistant_allowed_hosts", return_value=("api.example.test",)),
            mock.patch.object(
                hosted_assistants,
                "_require_model_credential_current",
                side_effect=self._credential,
            ),
            mock.patch.multiple(
                network_policy,
                app_identity_valid=lambda *_args: True,
                brain_identity_valid=lambda attrs, _team_id: "team.brain"
                in attrs.get("Config", {}).get("Labels", {}),
                network_members_valid=lambda *_args, **_kwargs: True,
                workload_endpoint_valid=lambda *_args: True,
                workload_live_membership_valid=lambda *_args: True,
                workload_security_valid=lambda *_args, **_kwargs: True,
            ),
        ):
            return hosted_chat_segment._hosted_chat_current_identity(
                request,
                self.assistants,
                self.config,
                7,
                {},
            )


class HostedChatEfficiencyContractTests(unittest.TestCase):
    def test_one_context_check_reuses_only_intraboundary_evidence(self) -> None:
        assistants = 2
        members = 3
        harness = HostedCheckHarness(assistants, members)

        identity = harness.run()

        self.assertEqual(identity[0], ANCHOR_ID)
        self.assertEqual(harness.calls["docker.containers.get"], 1 + assistants + members)
        self.assertEqual(harness.calls["container.reload"], 0)
        self.assertEqual(harness.calls["docker.images.get"], 1 + assistants)
        self.assertEqual(harness.calls["docker.networks.get"], 1)
        self.assertEqual(harness.calls["network.reload"], 1)
        self.assertEqual(
            sum(
                value
                for name, value in harness.calls.items()
                if name.startswith(("docker.", "container.", "network."))
            ),
            4 + members + 2 * assistants,
        )
        self.assertEqual(harness.calls["registry.read"], 1)
        self.assertEqual(harness.calls["registry.validate"], assistants)
        self.assertEqual(harness.calls["egress.store"], 1)
        self.assertEqual(harness.calls["egress.file-read"], 2 * assistants)
        self.assertEqual(harness.calls["sqlite.connect"], 1)
        self.assertEqual(harness.calls["sqlite.query"], 1)
        self.assertEqual(harness.calls["inference.read"], 1)
        self.assertEqual(harness.calls["credential.query"], 1)

    def test_live_evidence_is_collected_again_on_the_next_context_check(self) -> None:
        harness = HostedCheckHarness(2, 3)
        evidence = (
            "docker.containers.get",
            "docker.images.get",
            "docker.networks.get",
            "network.reload",
            "registry.read",
            "egress.file-read",
            "sqlite.query",
            "inference.read",
            "credential.query",
        )

        harness.run()
        first = {name: harness.calls[name] for name in evidence}
        harness.run()

        self.assertTrue(all(harness.calls[name] == 2 * first[name] for name in evidence))


if __name__ == "__main__":
    unittest.main()
