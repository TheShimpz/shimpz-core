from __future__ import annotations

import sys
import time
import unittest
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import assistant_connection_challenges
import assistant_connection_flow
import brain_runtime_client
from local_registry import AssistantSpec, ConnectionSpec, PowerSpec


@dataclass(frozen=True)
class _Active:
    spec: AssistantSpec


@dataclass(frozen=True)
class _Account:
    id: str
    username: str | None = None
    name: str | None = None


@dataclass(frozen=True)
class _Metadata:
    id: str
    provider: str
    scopes: tuple[str, ...]
    status: str
    account: _Account | None
    expires_at: int | None
    generation: int
    access_token: str = "-".join(("must", "never", "be", "public"))
    refresh_token: str = "-".join(("must", "never", "be", "public"))


class _Store:
    def __init__(
        self,
        rows: dict[tuple[str, str], _Metadata],
        tokens: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self.rows = rows
        self.tokens = tokens or {}
        self.resolved: list[tuple[object, ...]] = []

    def metadata(self, team_id: object, assistant_id: object, declarations: object) -> tuple[_Metadata, ...]:
        assert isinstance(assistant_id, str)
        assert isinstance(declarations, dict)
        return tuple(self.rows[(assistant_id, connection_id)] for connection_id in declarations)

    def resolve(
        self,
        team_id: object,
        assistant_id: object,
        connection_id: object,
        provider: object,
        scopes: object,
        refresh_callback: object,
    ) -> str:
        assert isinstance(assistant_id, str)
        assert isinstance(connection_id, str)
        assert callable(refresh_callback)
        self.resolved.append((team_id, assistant_id, connection_id, provider, scopes, refresh_callback))
        return self.tokens[(assistant_id, connection_id)]


def _spec() -> AssistantSpec:
    read_scopes = ("tweet.read", "users.read")
    write_scopes = ("offline.access", "tweet.read", "tweet.write", "users.read")
    return AssistantSpec(
        assistant_id="x-assistant",
        name="X Assistant",
        summary="test",
        image="example.invalid/x@sha256:" + ("a" * 64),
        rpc_command="/app/rpc",
        health_path="/healthz",
        powers={
            "read-profile": PowerSpec(
                "POST",
                "/read-profile",
                "Read one public X profile.",
                {},
                {},
                "none",
                (),
                ("x-read",),
            ),
            "publish-post": PowerSpec(
                "POST",
                "/publish-post",
                "Publish one approved X Post.",
                {},
                {},
                "each-run",
                (),
                ("x-write",),
            ),
        },
        secrets={},
        allowed_hosts=("api.x.com",),
        connections={
            "x-read": ConnectionSpec("x", read_scopes),
            "x-write": ConnectionSpec("x", write_scopes),
        },
    )


def _request(power: str, interrupt_id: str) -> brain_runtime_client.PowerRequest:
    return brain_runtime_client.PowerRequest(interrupt_id, "x-assistant", power, {}, "none")


class AssistantConnectionFlowTests(unittest.TestCase):
    def test_batch_collects_every_unusable_connection_before_any_power(self) -> None:
        expiry = int(time.time()) + 3600
        spec = _spec()
        store = _Store(
            {
                ("x-assistant", "x-read"): _Metadata(
                    "x-read",
                    "x",
                    tuple(sorted(spec.connections["x-read"].scopes)),
                    "connected",
                    _Account("123", "reader", "Reader"),
                    expiry,
                    1,
                ),
                ("x-assistant", "x-write"): _Metadata(
                    "x-write",
                    "x",
                    tuple(sorted(spec.connections["x-write"].scopes)),
                    "refresh-required",
                    _Account("123", "reader", "Reader"),
                    expiry,
                    2,
                ),
            }
        )

        requirements = assistant_connection_flow.requirements_for_batch(
            "team_1",
            {"x-assistant": _Active(spec)},
            (_request("read-profile", "one"), _request("publish-post", "two")),
            store,
        )

        self.assertEqual(len(requirements), 1)
        self.assertEqual(requirements[0].power_ids, ("publish-post",))
        self.assertEqual(
            requirements[0].connections,
            (("x-write", "x", ("offline.access", "tweet.read", "tweet.write", "users.read")),),
        )

    def test_challenge_is_exact_bounded_public_metadata(self) -> None:
        spec = _spec()
        requirement = assistant_connection_challenges.ConnectionRequirement(
            "x-assistant",
            "X Assistant",
            ("publish-post",),
            (("x-write", "x", ("offline.access", "tweet.read", "tweet.write", "users.read")),),
        )
        challenge = assistant_connection_challenges.PendingConnectionChallenge(
            "a" * 32,
            "team_1",
            time.monotonic() + 300,
            (requirement,),
            {"input": "must-never-be-public"},
        )

        payload = assistant_connection_flow.challenge_payload(
            challenge,
            {"x-assistant": _Active(spec)},
        )

        self.assertEqual(
            set(payload),
            {"team_id", "status", "turn_id", "challenge_id", "expires_in", "requirements"},
        )
        self.assertEqual(payload["status"], "connections-required")
        self.assertIn(payload["expires_in"], {299, 300})
        self.assertEqual(
            payload["requirements"],
            [
                {
                    "assistant_id": "x-assistant",
                    "assistant_name": "X Assistant",
                    "connection_id": "x-write",
                    "provider": "x",
                    "name": "X",
                    "summary": "Connect your X account so this Assistant can use only its reviewed X permissions.",
                    "scopes": ["offline.access", "tweet.read", "tweet.write", "users.read"],
                    "powers": [
                        {
                            "id": "publish-post",
                            "name": "Publish Post",
                            "summary": "Publish one approved X Post.",
                        }
                    ],
                }
            ],
        )
        self.assertNotIn("must-never-be-public", repr(payload))
        self.assertNotIn("access_token", repr(payload))

    def test_inventory_flattens_status_without_token_or_generation_fields(self) -> None:
        spec = _spec()
        expiry = 1_800_000_000
        store = _Store(
            {
                ("x-assistant", "x-read"): _Metadata(
                    "x-read",
                    "x",
                    tuple(sorted(spec.connections["x-read"].scopes)),
                    "missing",
                    None,
                    None,
                    0,
                ),
                ("x-assistant", "x-write"): _Metadata(
                    "x-write",
                    "x",
                    tuple(sorted(spec.connections["x-write"].scopes)),
                    "refresh-required",
                    _Account("123", "juliano", "Juliano"),
                    expiry,
                    4,
                ),
            }
        )

        payload = assistant_connection_flow.inventory_payload("team_1", [spec], store)

        self.assertEqual(set(payload), {"connections"})
        self.assertEqual(payload["connections"][0]["status"], "missing")
        self.assertEqual(payload["connections"][1]["status"], "expired")
        self.assertEqual(
            payload["connections"][1]["account"],
            {"id": "123", "name": "Juliano", "username": "juliano"},
        )
        self.assertEqual(
            payload["connections"][1]["expires_at"],
            datetime.fromtimestamp(expiry, UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        )
        encoded = repr(payload)
        for forbidden in ("access_token", "refresh_token", "must-never-be-public", "generation"):
            self.assertNotIn(forbidden, encoded)

    def test_private_resolution_returns_only_the_selected_power_connection(self) -> None:
        spec = _spec()
        token = "-".join(("private", "access", "token", "123456"))
        store = _Store({}, {("x-assistant", "x-write"): token})
        refresh_calls: list[tuple[str, tuple[str, ...], str]] = []

        connections = assistant_connection_flow.resolve_power_connections(
            "team_1",
            spec,
            "publish-post",
            store,
            lambda provider, scopes, refresh: refresh_calls.append((provider, scopes, refresh)),
        )

        self.assertEqual(
            connections,
            {"x-write": {"type": "oauth2-bearer", "access_token": token}},
        )
        self.assertEqual(len(store.resolved), 1)
        callback = store.resolved[0][-1]
        callback("private-refresh-token-123")
        self.assertEqual(
            refresh_calls,
            [("x", ("offline.access", "tweet.read", "tweet.write", "users.read"), "private-refresh-token-123")],
        )

    def test_flow_fails_closed_on_drift_sensitive_public_fields_and_invalid_tokens(self) -> None:
        spec = _spec()
        drifted = _Store(
            {
                ("x-assistant", "x-read"): _Metadata(
                    "x-read",
                    "x",
                    ("tweet.read",),
                    "connected",
                    None,
                    int(time.time()) + 60,
                    1,
                )
            }
        )
        with self.assertRaises(assistant_connection_flow.ConnectionFlowError):
            assistant_connection_flow.requirements_for_batch(
                "team_1",
                {"x-assistant": _Active(spec)},
                (_request("read-profile", "one"),),
                drifted,
            )
        with self.assertRaises(assistant_connection_flow.ConnectionFlowError):
            assistant_connection_flow._assert_public_payload({"access_token": "private"})

        invalid_token_store = _Store({}, {("x-assistant", "x-read"): "short"})
        with self.assertRaises(assistant_connection_flow.ConnectionFlowError):
            assistant_connection_flow.resolve_power_connections(
                "team_1",
                spec,
                "read-profile",
                invalid_token_store,
                lambda _provider, _scopes, _refresh: object(),
            )


if __name__ == "__main__":
    unittest.main()
