"""Decision-parity contracts for the shared hosted/local Controller router."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import controller_routing


def _parts(path: str) -> tuple[str, ...]:
    return tuple(part for part in path.split("/") if part)


class ControllerRoutingTests(unittest.TestCase):
    def test_common_routes_resolve_to_the_same_operation_and_parameters(self) -> None:
        common = (
            ("GET", "/v1/teams", "team-list", {}),
            ("POST", "/v1/teams/team_1/chat", "chat", {"team_id": "team_1"}),
            (
                "POST",
                "/v1/teams/team_1/assistant-accounts/challenges/challenge-1/authorize",
                "assistant-account-authorize",
                {"team_id": "team_1", "challenge_id": "challenge-1"},
            ),
            (
                "GET",
                "/v1/teams/team_1/assistants/helper/help/pt-BR",
                "assistant-help",
                {"team_id": "team_1", "assistant_id": "helper", "locale": "pt-BR"},
            ),
        )
        for method, path, operation, params in common:
            with self.subTest(method=method, path=path):
                hosted = controller_routing.resolve(controller_routing.HOSTED, method, _parts(path))
                local = controller_routing.resolve(controller_routing.LOCAL, method, _parts(path))
                self.assertEqual(hosted, local)
                self.assertEqual(hosted, controller_routing.RouteMatch(operation, params))

    def test_profile_only_routes_fail_closed_on_the_other_controller(self) -> None:
        cases = (
            (controller_routing.HOSTED, "POST", "/v1/teams/team_1/chat/stream", "chat-stream"),
            (controller_routing.LOCAL, "GET", "/v1/teams/team_1/chat/approval", "chat-approval-pending"),
        )
        for profile, method, path, operation in cases:
            with self.subTest(profile=profile, path=path):
                match = controller_routing.resolve(profile, method, _parts(path))
                other = controller_routing.LOCAL if profile == controller_routing.HOSTED else controller_routing.HOSTED
                self.assertEqual(match.operation, operation)
                self.assertIsNone(controller_routing.resolve(other, method, _parts(path)))

    def test_wrong_methods_suffixes_and_profiles_do_not_fall_through(self) -> None:
        self.assertIsNone(controller_routing.resolve(controller_routing.HOSTED, "GET", _parts("/v1/teams/t/chat")))
        self.assertIsNone(
            controller_routing.resolve(controller_routing.LOCAL, "POST", _parts("/v1/teams/t/files/id/extra"))
        )
        with self.assertRaises(ValueError):
            controller_routing.resolve("unknown", "GET", _parts("/v1/teams"))


if __name__ == "__main__":
    unittest.main()
