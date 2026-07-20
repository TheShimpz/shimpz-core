from __future__ import annotations

import contextlib
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

import test_r2_bridge as harness

app = harness.app
_patched = harness._patched

TEAM_ID = "team_1"
ASSISTANT_ID = app.assistant_contract.ASSISTANT_ID
SCOPES = ("tweet.read", "users.read")
ACCESS_TOKEN = "-".join(("hosted", "access", "token", "value", "123456789"))
ANCHOR_ID = "a" * 64


class _Runtime:
    def __init__(self) -> None:
        self.start_calls = 0
        self.resume_calls = 0
        self.request = app.brain_runtime_client.PowerRequest(
            "lookup",
            ASSISTANT_ID,
            "public-user-lookup",
            {"username": "XDevelopers"},
            "none",
        )

    def start(self, _context, _message):
        self.start_calls += 1
        return app.brain_runtime_client.RuntimeTurn("power-required", "", (self.request,))

    def resume(self, _context, results):
        self.resume_calls += 1
        if set(results) != {"lookup"}:
            raise AssertionError("the admitted Power must resume once")
        return app.brain_runtime_client.RuntimeTurn("completed", "Connected lookup complete.", ())


class HostedOAuthConnectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.store = app.oauth_connection_store.OAuthConnectionStore(
            root / "state" / "connections.json",
            root / "key" / "aes256.key",
        )
        trusted = app.marketplace.APPS[ASSISTANT_ID].assistant
        assert trusted is not None
        self.contract = replace(
            trusted,
            powers={
                power_id: replace(
                    power,
                    secrets=(),
                    connections=("x",) if power_id == "public-user-lookup" else (),
                )
                for power_id, power in trusted.powers.items()
            },
            secrets={},
            connections={"x": app.marketplace.ConnectionSpec("x", SCOPES)},
        )
        self.container = types.SimpleNamespace(id="b" * 64)
        self.active = app._ActiveAssistant(ASSISTANT_ID, self.contract, self.container)

    def _connect(self) -> None:
        self.store.put(
            TEAM_ID,
            ASSISTANT_ID,
            "x",
            "x",
            SCOPES,
            app.oauth_http_client.OAuthTokenSet(ACCESS_TOKEN, "refresh-token-value-123456789", SCOPES, 3600),
        )

    def test_inventory_is_status_only_and_private_token_reaches_only_declared_power(self) -> None:
        self._connect()
        captured: list[dict[str, object]] = []

        def rpc(_team_id, _token, _container, _command, _method, _path, payload):
            captured.append(payload)
            return {"id": "123", "name": "X Developers", "username": "XDevelopers"}

        with _patched(
            _assistant_connections=self.store,
            _installed_assistant=lambda *_args: (ASSISTANT_ID, self.contract, self.container),
            _assistant_rpc=rpc,
        ):
            result = app._invoke_assistant_power(
                TEAM_ID,
                "turn-token",
                ASSISTANT_ID,
                self.contract,
                self.container,
                "public-user-lookup",
                {"username": "XDevelopers"},
            )
            payload = app.assistant_connection_flow.inventory_payload(
                TEAM_ID,
                [app._hosted_secret_spec(self.active)],
                self.store,
            )

        self.assertEqual(result["result"]["username"], "XDevelopers")
        self.assertEqual(
            captured,
            [
                {
                    "input": {"username": "XDevelopers"},
                    "secrets": {},
                    "connections": {
                        "x": {"type": "oauth2-bearer", "access_token": ACCESS_TOKEN},
                    },
                }
            ],
        )
        serialized = app.json.dumps(payload)
        self.assertNotIn(ACCESS_TOKEN, serialized)
        self.assertNotIn("refresh-token", serialized)
        self.assertNotIn("generation", serialized)
        self.assertEqual(payload["connections"][0]["status"], "connected")

    def test_connection_token_exposure_is_rejected_without_echoing_it(self) -> None:
        self._connect()
        with (
            _patched(
                _assistant_connections=self.store,
                _installed_assistant=lambda *_args: (ASSISTANT_ID, self.contract, self.container),
                _assistant_rpc=lambda *_args, **_kwargs: {"id": "123", "name": ACCESS_TOKEN},
            ),
            self.assertRaises(app.ApiError) as caught,
        ):
            app._invoke_assistant_power(
                TEAM_ID,
                "turn-token",
                ASSISTANT_ID,
                self.contract,
                self.container,
                "public-user-lookup",
                {"username": "XDevelopers"},
            )

        self.assertEqual(caught.exception.status, app.HTTPStatus.BAD_GATEWAY)
        self.assertNotIn(ACCESS_TOKEN, caught.exception.message)

    def test_admitted_contract_prunes_removed_connections_and_cancels_paused_turn(self) -> None:
        self._connect()
        challenge_store = app.assistant_connection_challenges.ConnectionChallengeStore()
        requirement = app.assistant_connection_challenges.ConnectionRequirement(
            ASSISTANT_ID,
            "Shimpz Assistant",
            ("public-user-lookup",),
            (("x", "x", SCOPES),),
        )
        challenge_store.create(TEAM_ID, (requirement,), object())
        without_connections = replace(
            app.marketplace.APPS[ASSISTANT_ID],
            assistant=replace(self.contract, connections={}),
        )

        with _patched(
            _assistant_connections=self.store,
            _assistant_connection_challenges=challenge_store,
        ):
            app._retain_admitted_assistant_connections(TEAM_ID, ASSISTANT_ID, without_connections)

        self.assertIsNone(challenge_store.current(TEAM_ID))
        self.assertEqual(self.store.metadata(TEAM_ID, ASSISTANT_ID, {}), ())
        self.assertNotIn(ACCESS_TOKEN, self.store.state_path.read_text(encoding="utf-8"))

    def test_connection_resume_can_pause_for_secrets_before_any_power_runs(self) -> None:
        private_contract = replace(
            self.contract,
            powers={
                power_id: replace(
                    power,
                    secrets=("lookup-key",) if power_id == "public-user-lookup" else (),
                )
                for power_id, power in self.contract.powers.items()
            },
            secrets={"lookup-key": app.marketplace.SecretSpec("Lookup key", "Required for this lookup.")},
        )
        active = app._ActiveAssistant(ASSISTANT_ID, private_contract, self.container)
        anchor = types.SimpleNamespace(
            id=ANCHOR_ID,
            labels={"team.name": "Marketing", "team.owner": "account_1"},
        )
        runtime = _Runtime()
        connection_challenges = app.assistant_connection_challenges.ConnectionChallengeStore()
        secret_challenges = app.assistant_secret_challenges.SecretChallengeStore()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret_store = app.assistant_secret_store.AssistantSecretStore(
                root / "secret-state" / "secrets.json",
                root / "secret-key" / "aes256.key",
            )
            journal = app.power_journal.PowerJournal(root / "journal" / "journal.sqlite3")
            self.addCleanup(journal.close)
            rpc_calls: list[dict[str, object]] = []

            def rpc(_team_id, _token, _container, _command, _method, _path, payload):
                rpc_calls.append(payload)
                return {"id": "123", "name": "X Developers", "username": "XDevelopers"}

            @contextlib.contextmanager
            def exclusive(_team_id, _lease):
                yield "resumed-turn", anchor

            with _patched(
                _active_team_assistants=lambda _team_id: (active,),
                _require_assistant_genesis=lambda _container: "Use only the declared X Power.",
                _chat_file_metadata=lambda _team_id, _files: [],
                _inference_store=types.SimpleNamespace(
                    load=lambda _team_id: types.SimpleNamespace(provider="openai", model="gpt-test")
                ),
                _model_credential=lambda _owner, _provider: ("model-key-value", 7),
                _require_model_credential_current=lambda *_args: None,
                _current_team_anchor=lambda *_args: anchor,
                _brain_runtime=runtime,
                _power_execution_journal=lambda: journal,
                _assistant_connections=self.store,
                _assistant_connection_challenges=connection_challenges,
                _assistant_secrets=secret_store,
                _assistant_secret_challenges=secret_challenges,
                _installed_assistant=lambda *_args: (ASSISTANT_ID, private_contract, self.container),
                _assistant_rpc=rpc,
                _commit_chat_terminal=lambda *_args: True,
            ):
                connection_prompt = app._chat_in_turn(
                    TEAM_ID,
                    "Look up XDevelopers.",
                    [],
                    (ASSISTANT_ID,),
                    "initial-turn",
                    anchor,
                    "account_1",
                )
                self.assertEqual(connection_prompt["status"], "connections-required")
                self.assertEqual(runtime.start_calls, 1)
                self.assertEqual(runtime.resume_calls, 0)
                self.assertEqual(rpc_calls, [])

                self._connect()
                with _patched(_exclusive_chat_turn=exclusive):
                    secret_prompt = app._resume_chat_connections(
                        TEAM_ID,
                        connection_prompt["challenge_id"],
                        app._AuthorizationLease(
                            TEAM_ID,
                            ANCHOR_ID,
                            "account_1",
                            ("account", "account_1"),
                        ),
                    )

            self.assertEqual(secret_prompt["status"], "secrets-required")
            self.assertEqual(runtime.start_calls, 1)
            self.assertEqual(runtime.resume_calls, 0)
            self.assertEqual(rpc_calls, [])
            self.assertIsNone(connection_challenges.current(TEAM_ID))
            self.assertIsNotNone(secret_challenges.current(TEAM_ID))

    def test_authorize_and_callback_expose_no_oauth_private_material(self) -> None:
        challenge_store = app.assistant_connection_challenges.ConnectionChallengeStore()
        continuation = app.chat_orchestrator.ChatContinuation(
            app.brain_runtime_client.RuntimeTurn("power-required", "", ()),
            (),
            (),
            0,
        )
        pending = app._PendingHostedChat(
            continuation,
            (ASSISTANT_ID,),
            (),
            "account_1",
            ("identity",),
        )
        challenge = challenge_store.create(
            TEAM_ID,
            (
                app.assistant_connection_challenges.ConnectionRequirement(
                    ASSISTANT_ID,
                    "Shimpz Assistant",
                    ("public-user-lookup",),
                    (("x", "x", SCOPES),),
                ),
            ),
            pending,
        )
        fake_service = types.SimpleNamespace(
            authorization_url=lambda current, session: (
                "https://x.com/i/oauth2/authorize?state=opaque"
                if current is challenge and session == "browser-session-binding-value"
                else None
            ),
            complete=lambda state, code, session, resolver: types.SimpleNamespace(
                team_id=TEAM_ID,
                assistant_id=ASSISTANT_ID,
                connection_id="x",
                provider="x",
                scopes=SCOPES,
                generation=9,
            ),
            disconnect=lambda *_args: True,
        )
        lease = app._AuthorizationLease(
            TEAM_ID,
            ANCHOR_ID,
            "account_1",
            ("account", "account_1"),
        )
        with _patched(
            _assistant_connection_challenges=challenge_store,
            _oauth_connections=fake_service,
            _require_current_authorization=lambda *_args, **_kwargs: object(),
            _authorize=lambda *_args, **_kwargs: lease,
        ):
            started = app._start_oauth_connection(
                TEAM_ID,
                challenge.id,
                "browser-session-binding-value",
                lease,
            )
            completed = app._complete_oauth_connection(
                {
                    "state": "provider-state-value",
                    "code": "provider-code-value",
                    "session_binding": "browser-session-binding-value",
                },
                ("account", "account_1"),
            )
            with self.assertRaises(app.ApiError) as extra_field:
                app._complete_oauth_connection(
                    {
                        "state": "provider-state-value",
                        "code": "provider-code-value",
                        "session_binding": "browser-session-binding-value",
                        "redirect": "https://attacker.test",
                    },
                    ("account", "account_1"),
                )

        self.assertEqual(started, {"authorization_url": "https://x.com/i/oauth2/authorize?state=opaque"})
        self.assertEqual(extra_field.exception.status, app.HTTPStatus.UNPROCESSABLE_ENTITY)
        self.assertEqual(
            completed,
            {
                "connected": True,
                "team_id": TEAM_ID,
                "assistant_id": ASSISTANT_ID,
                "connection_id": "x",
                "provider": "x",
                "scopes": list(SCOPES),
                "challenge_id": challenge.id,
            },
        )
        serialized = app.json.dumps({"started": started, "completed": completed})
        for forbidden in (
            "provider-code-value",
            "browser-session-binding-value",
            "access_token",
            "refresh_token",
            "code_verifier",
            "client_id",
            "generation",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_team_teardown_cancels_connection_turn_and_purges_tokens(self) -> None:
        self._connect()
        challenges = app.assistant_connection_challenges.ConnectionChallengeStore()
        challenges.create(
            TEAM_ID,
            (
                app.assistant_connection_challenges.ConnectionRequirement(
                    ASSISTANT_ID,
                    "Shimpz Assistant",
                    ("public-user-lookup",),
                    (("x", "x", SCOPES),),
                ),
            ),
            object(),
        )
        with _patched(
            _assistant_connections=self.store,
            _assistant_connection_challenges=challenges,
        ):
            self.assertTrue(app._teardown_assistant_connections(TEAM_ID))

        self.assertIsNone(challenges.current(TEAM_ID))
        self.assertEqual(self.store.metadata(TEAM_ID, ASSISTANT_ID, self.contract.connections)[0].status, "missing")


if __name__ == "__main__":
    unittest.main()
