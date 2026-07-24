from __future__ import annotations

import json
import os
import sys
import tempfile
from email.message import Message
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))
import inference_config
import local_app
import local_chat_continuation_store
import local_healthcheck
import local_registry
import local_token_store
from local_controller_harness import LocalContractCase
from local_support import assistant_lifecycle
from local_support import audit as local_audit
from local_support import http as local_http
from local_support.validation import validate_model_credential_headers

LOOKUP_INPUT = {"page": 1, "per_page": 25}
LOOKUP_RESULT = {
    "zones": [],
    "pagination": {"page": 1, "per_page": 25, "count": 0, "total_count": 0, "total_pages": 0},
}
DNS_INPUT = {"zone_id": "a" * 32, "page": 1, "per_page": 25}
DNS_RESULT = {
    "records": [],
    "pagination": {"page": 1, "per_page": 25, "count": 0, "total_count": 0, "total_pages": 0},
}
TEST_SECRET_VALUES = {
    "service-token": "service-test-credential-123456789",
    "client-key": "client-key-test-credential-123456789",
    "client-secret": "client-secret-test-credential-123456789",
    "session-token": "session-token-test-credential-123456789",
    "session-secret": "session-secret-test-credential-123456789",
}
TEST_ACCOUNT_ACCESS_TOKEN = "-".join(("oauth", "access", "test", "token", "123456789"))
TEST_ACCOUNT_REFRESH_TOKEN = "-".join(("oauth", "refresh", "test", "token", "123456789"))
CURRENT_ASSISTANT_IMAGE = "ghcr.io/theshimpz/shimpz-space@sha256:" + "b" * 64
OUTDATED_ASSISTANT_IMAGE = "ghcr.io/theshimpz/shimpz-space@sha256:" + "a" * 64


class LocalContractTests(LocalContractCase):
    def test_local_state_defaults_match_the_installer_mount_contract(self) -> None:
        self.assertEqual(local_token_store.TOKEN_PATH, Path("/run/shimpz-local/token"))
        self.assertEqual(local_healthcheck.TOKEN_PATH, local_token_store.TOKEN_PATH)
        self.assertEqual(local_audit.AUDIT_PATH, Path("/var/log/shimpz-local/audit.jsonl"))
        self.assertEqual(local_app.STORAGE_ROOT, Path("/var/lib/shimpz-local/storage"))
        self.assertEqual(local_app.INFERENCE_ROOT, Path("/var/lib/shimpz-local/inference"))
        self.assertEqual(
            local_app.LOCAL_POWER_JOURNAL_PATH,
            Path("/var/lib/shimpz-local/power-journal/journal.sqlite3"),
        )
        self.assertEqual(
            local_app.LOCAL_CHAT_CONTINUATIONS_STATE_PATH,
            local_chat_continuation_store.STATE_PATH,
        )
        self.assertEqual(
            local_app.LOCAL_CHAT_CONTINUATIONS_KEY_PATH,
            local_chat_continuation_store.KEY_PATH,
        )

    def test_registry_accepts_only_a_non_placeholder_digest(self) -> None:
        digest = "127.0.0.1:5000/shimpz/shimpz-cloudflare@sha256:" + "a" * 64
        registry = self._registry(digest)
        self.assertEqual(registry["shimpz-cloudflare"].image, digest)
        self.assertEqual(registry["shimpz-cloudflare"].name, "Shimpz Cloudflare")
        self.assertEqual(
            set(registry["shimpz-cloudflare"].powers),
            {"list-zones", "list-dns-records"},
        )
        self.assertEqual(
            registry["shimpz-cloudflare"].powers["list-zones"].path,
            "/v1/powers/list-zones",
        )
        self.assertEqual(
            registry["shimpz-cloudflare"].allowed_hosts,
            ("api.cloudflare.com",),
        )
        invalid = (
            "ghcr.io/theshimpz/shimpz-space:latest",
            "ghcr.io/theshimpz/shimpz-space@sha256:" + "0" * 64,
            "https://ghcr.io/theshimpz/hello@sha256:" + "a" * 64,
        )
        for image in invalid:
            with self.subTest(image=image), self.assertRaises(local_registry.RegistryError):
                self._registry(image)

    def test_registry_shape_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 2,
                        "images": {"shimpz-cloudflare": "x"},
                        "command": ["/bin/sh"],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(local_registry.RegistryError):
                local_registry.load_registry(path)

    def test_cloudflare_assistant_contract_is_read_only_closed_and_bounded(self) -> None:
        registry = self._registry(CURRENT_ASSISTANT_IMAGE)
        spec = registry["shimpz-cloudflare"]
        self.assertEqual(spec.allowed_hosts, ("api.cloudflare.com",))
        self.assertEqual(spec.health_path, "/healthz")
        self.assertEqual(set(spec.powers), {"list-zones", "list-dns-records"})
        self.assertTrue(all(not hasattr(power, "approval") for power in spec.powers.values()))
        self.assertTrue(all(power.accounts == ("cloudflare",) for power in spec.powers.values()))
        self.assertEqual(
            local_registry.validate_power_input(
                "shimpz-cloudflare",
                "list-dns-records",
                {"zone_id": "a" * 32, "page": 1, "per_page": 100},
            ),
            {"zone_id": "a" * 32, "page": 1, "per_page": 100},
        )
        zones = {
            "zones": [
                {
                    "id": "a" * 32,
                    "name": "example.com",
                    "status": "active",
                    "type": "full",
                    "paused": False,
                    "account": {"id": "b" * 32, "name": "Shimpz"},
                }
            ],
            "pagination": {"page": 1, "per_page": 100, "count": 1, "total_count": 1, "total_pages": 1},
        }
        self.assertEqual(
            local_registry.validate_power_output("shimpz-cloudflare", "list-zones", zones),
            zones,
        )
        with self.assertRaises(ValueError):
            local_registry.validate_power_output(
                "shimpz-cloudflare",
                "list-zones",
                zones | {"access_token": "must-not-cross"},
            )
        for invalid in (
            {"page": 0, "per_page": 100},
            {"page": 1, "per_page": 101},
            {"zone_id": "../zone", "page": 1, "per_page": 10},
            {"page": 1, "per_page": 10, "access_token": "must-not-cross"},
        ):
            power = "list-dns-records" if "zone_id" in invalid else "list-zones"
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                local_registry.validate_power_input("shimpz-cloudflare", power, invalid)

    def test_identifiers_are_strict_and_bounded(self) -> None:
        self.assertEqual(local_app.validate_team_id("demo_team"), "demo_team")
        for invalid in ("Demo", "-demo", "demo-1", "a" * 41, "demo space", ""):
            with self.subTest(invalid=invalid), self.assertRaises(local_app.ApiProblem) as caught:
                local_app.validate_team_id(invalid)
            self.assertEqual(caught.exception.status, HTTPStatus.UNPROCESSABLE_ENTITY)

    def test_local_thread_identity_is_scoped_to_the_network_generation(self) -> None:
        first = local_app._brain_thread_id("local-space", "team_1", "a" * 64)
        second = local_app._brain_thread_id("local-space", "team_1", "b" * 64)

        self.assertEqual(first, f"local:local-space:team_1:{'a' * 64}:default")
        self.assertNotEqual(first, second)
        for space_id, team_id, network_id in (
            ("bad space", "team_1", "a" * 64),
            ("local-space", "bad-team", "a" * 64),
            ("local-space", "team_1", "not-a-docker-id"),
        ):
            with (
                self.subTest(
                    space_id=space_id,
                    team_id=team_id,
                    network_id=network_id,
                ),
                self.assertRaises(local_app.ApiProblem) as caught,
            ):
                local_app._brain_thread_id(space_id, team_id, network_id)
            self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_team_name_matches_the_admin_contract(self) -> None:
        self.assertEqual(local_app.validate_team_name("My Team"), "My Team")
        for invalid in ("", " padded", "padded ", "x\n", "x" * 81, None):
            with self.subTest(invalid=invalid), self.assertRaises(local_app.ApiProblem):
                local_app.validate_team_name(invalid)

    def test_container_limits_and_stateless_recovery_are_intentionally_narrow(self) -> None:
        self.assertEqual(assistant_lifecycle.ASSISTANT_NANO_CPUS, 250_000_000)
        self.assertEqual(assistant_lifecycle.ASSISTANT_MEMORY, 128 * 1024 * 1024)
        self.assertEqual(assistant_lifecycle.ASSISTANT_PIDS, 64)
        self.assertEqual(local_app.half_cpu_set(96), "0-47")
        self.assertEqual(local_app.half_cpu_set(8), "0-3")
        self.assertEqual(local_app.half_cpu_set(1), "0")
        readiness = local_app.ApiProblem(HTTPStatus.BAD_GATEWAY, "not ready", code="assistant-not-ready")
        ownership = local_app.ApiProblem(HTTPStatus.CONFLICT, "drift", code="ownership-conflict")
        self.assertTrue(assistant_lifecycle._is_replaceable_readiness_failure("shimpz-cloudflare", readiness))
        self.assertFalse(assistant_lifecycle._is_replaceable_readiness_failure("future-stateful-assistant", readiness))
        self.assertFalse(assistant_lifecycle._is_replaceable_readiness_failure("shimpz-cloudflare", ownership))

    def test_local_controller_bootstraps_tokens_before_serving(self) -> None:
        events: list[str] = []
        client = SimpleNamespace(close=lambda: events.append("client-close"))
        server = SimpleNamespace(
            serve_forever=lambda **_kwargs: events.append("serve"),
            server_close=lambda: events.append("server-close"),
        )

        with (
            mock.patch.dict(os.environ, {"SHIMPZ_SPACE_ID": "local-space"}),
            mock.patch.object(local_app, "load_registry", side_effect=lambda: events.append("registry") or {}),
            mock.patch.object(
                local_app.local_token_store,
                "ensure_token",
                side_effect=lambda: events.append("controller-token") or "a" * 64,
            ),
            mock.patch.object(
                local_app.brain_runtime_token_store,
                "ensure",
                side_effect=lambda: events.append("runtime-token") or "b" * 64,
            ),
            mock.patch.object(
                local_app.docker,
                "from_env",
                side_effect=lambda **_kwargs: events.append("docker") or client,
            ),
            mock.patch.object(
                local_app.team_storage,
                "TeamStorage",
                side_effect=lambda _path: events.append("storage") or SimpleNamespace(),
            ),
            mock.patch.object(
                local_app,
                "LocalController",
                side_effect=lambda *_args: events.append("controller") or SimpleNamespace(),
            ),
            mock.patch.object(
                local_app,
                "BoundedServer",
                side_effect=lambda *_args: events.append("server") or server,
            ),
            mock.patch.object(local_app.local_audit, "record", side_effect=lambda *_args, **_kwargs: "trace"),
        ):
            result = local_app.main()

        self.assertEqual(result, 0)
        self.assertEqual(
            events,
            [
                "registry",
                "controller-token",
                "runtime-token",
                "docker",
                "storage",
                "controller",
                "server",
                "serve",
                "server-close",
                "client-close",
            ],
        )

    def test_local_controller_accepts_an_injected_power_journal(self) -> None:
        image = "127.0.0.1:5000/shimpz/shimpz-cloudflare@sha256:" + "a" * 64
        injected = SimpleNamespace()
        approval_grants = SimpleNamespace()
        client = SimpleNamespace(
            info=lambda: {"SecurityOptions": ["name=seccomp"], "NCPU": 2},
        )

        controller = local_app.LocalController(
            client,
            "local-space",
            self._registry(image),
            SimpleNamespace(),
            local_app.LocalControllerDependencies(
                brain_runtime=SimpleNamespace(),
                power_state=injected,
                approval_grants=approval_grants,
            ),
        )

        self.assertIs(controller.power_state, injected)
        self.assertIs(controller.approval_grants, approval_grants)
        self.assertIsInstance(controller.assistant_lifecycle, local_app.AssistantLifecycle)
        self.assertIsInstance(controller.chat_turn_service, local_app.ChatTurnService)
        self.assertEqual(local_app.LocalController.__bases__, (object,))
        self.assertEqual(local_app.AssistantLifecycle.__bases__, (object,))
        self.assertEqual(local_app.ChatTurnService.__bases__, (object,))
        self.assertFalse(hasattr(local_app.LocalController, "__getattr__"))
        self.assertIsNot(controller.assistant_lifecycle.__dict__, controller.__dict__)
        self.assertIsNot(controller.chat_turn_service.__dict__, controller.__dict__)
        self.assertIsNot(controller.assistant_lifecycle.__dict__, controller.chat_turn_service.__dict__)
        self.assertIs(controller.assistant_lifecycle.chat_turn_service, controller.chat_turn_service)
        self.assertIs(controller.chat_turn_service.assistant_lifecycle, controller.assistant_lifecycle)
        explicit_registry = object()
        explicit_storage = object()
        standalone_lifecycle = local_app.AssistantLifecycle(
            local_app.AssistantLifecycleDependencies(registry=explicit_registry)
        )
        standalone_chat = local_app.ChatTurnService(local_app.ChatTurnDependencies(storage=explicit_storage))
        self.assertIs(standalone_lifecycle.registry, explicit_registry)
        self.assertIs(standalone_chat.storage, explicit_storage)
        for module in (
            local_app.local_assistant_lifecycle,
            local_app.local_assistant_resources,
            local_app.local_assistant_rpc,
            local_app.local_chat_api,
            local_app.local_chat_execution,
            local_app.local_chat_pause,
            local_app.local_chat_private,
            local_app.local_chat_resume,
            local_app.local_chat_segment,
            local_app.local_chat_state,
            local_app.local_chat_submission,
            local_app.local_egress,
            local_app.local_team_lifecycle,
        ):
            self.assertFalse(any(name.endswith("Mixin") for name in vars(module)))
        self.assertEqual(
            local_app.LOCAL_POWER_JOURNAL_PATH,
            Path("/var/lib/shimpz-local/power-journal/journal.sqlite3"),
        )

    def test_ambiguous_power_rpc_is_fail_stopped_or_permanently_blocked(self) -> None:
        controller = object.__new__(local_app.LocalController)
        controller._wire_collaborators()

        class Stoppable:
            id = "stoppable"
            status = "running"

            def __init__(self) -> None:
                self.attrs = {"State": {"Running": True}}

            def stop(self, *, timeout: int) -> None:
                self.status = "exited"
                self.attrs["State"]["Running"] = False

            def reload(self) -> None:
                return None

            def kill(self) -> None:
                raise AssertionError("a proved stop must not be killed")

        stopped = Stoppable()
        controller.assistant_lifecycle._fail_stop_power(stopped)
        self.assertEqual(stopped.status, "exited")
        self.assertNotIn(stopped.id, controller.assistant_lifecycle._blocked_power_workloads)

        class Paused:
            id = "paused"
            status = "paused"
            killed = False

            def __init__(self) -> None:
                self.attrs = {"State": {"Running": True}}

            def stop(self, *, timeout: int) -> None:
                return None

            def reload(self) -> None:
                return None

            def kill(self) -> None:
                self.killed = True
                self.attrs["State"]["Running"] = False

        paused = Paused()
        controller.assistant_lifecycle._fail_stop_power(paused)
        self.assertTrue(paused.killed)
        self.assertNotIn(paused.id, controller.assistant_lifecycle._blocked_power_workloads)

    def test_unprovable_power_stop_is_permanently_blocked(self) -> None:
        controller = object.__new__(local_app.LocalController)
        controller._wire_collaborators()

        class Ambiguous:
            id = "ambiguous"

            def stop(self, *, timeout: int) -> None:
                raise local_app.DockerException("ambiguous stop")

            def reload(self) -> None:
                raise local_app.DockerException("ambiguous inspect")

            def kill(self) -> None:
                raise local_app.DockerException("ambiguous kill")

        ambiguous = Ambiguous()
        with self.assertRaises(local_app.ApiProblem) as caught:
            controller.assistant_lifecycle._fail_stop_power(ambiguous)
        self.assertEqual(caught.exception.code, "assistant-power-blocked")
        self.assertIn(ambiguous.id, controller.assistant_lifecycle._blocked_power_workloads)

        class Malformed:
            id = "malformed"

            def __init__(self) -> None:
                self.attrs = {"State": {}}

            def stop(self, *, timeout: int) -> None:
                return None

            def reload(self) -> None:
                return None

            def kill(self) -> None:
                return None

        malformed = Malformed()
        with self.assertRaises(local_app.ApiProblem):
            controller.assistant_lifecycle._fail_stop_power(malformed)
        self.assertIn(malformed.id, controller.assistant_lifecycle._blocked_power_workloads)

    def test_large_upload_admission_is_single_slot(self) -> None:
        self.assertTrue(local_http._FILE_UPLOAD_SLOTS.acquire(blocking=False))
        try:
            self.assertFalse(local_http._FILE_UPLOAD_SLOTS.acquire(blocking=False))
        finally:
            local_http._FILE_UPLOAD_SLOTS.release()

    def test_inference_configuration_persists_only_provider_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            controller = object.__new__(local_app.LocalController)
            controller._locks = tuple(__import__("threading").RLock() for _ in range(64))
            controller.inference_store = inference_config.InferenceConfigStore(Path(directory) / "inference")
            controller._wire_collaborators()
            controller.assistant_lifecycle._network = lambda _team_id: object()

            configured = controller.configure_inference(
                "team_1",
                {"provider": "openai", "model": "gpt-5.5"},
            )

            self.assertEqual(
                configured,
                {"team_id": "team_1", "provider": "openai", "model": "gpt-5.5"},
            )
            self.assertEqual(controller.inference_status("team_1"), configured)
            stored = next((Path(directory) / "inference").iterdir()).read_text(encoding="utf-8")
            self.assertNotIn("api_key", stored)
            with self.assertRaises(local_app.ApiProblem):
                controller.configure_inference(
                    "team_1",
                    {"provider": "openai", "model": "gpt-5.5", "api_key": "never"},
                )

    def test_private_model_headers_are_closed_and_never_echoed(self) -> None:
        key = "sk-test-0123456789"
        self.assertEqual(
            validate_model_credential_headers(["openai"], [key]),
            ("openai", key),
        )
        invalid = (
            ([], [key]),
            (["openai", "openai"], [key]),
            (["unsupported"], [key]),
            (["openai"], []),
            (["openai"], [key, key]),
            (["openai"], ["short"]),
            (["openai"], ["x" * 16 + "\n"]),
        )
        for providers, keys in invalid:
            with self.subTest(providers=providers, keys=len(keys)), self.assertRaises(local_app.ApiProblem) as caught:
                validate_model_credential_headers(providers, keys)
            self.assertNotIn(key, str(caught.exception))

    def test_private_chat_route_reads_key_from_header_not_json(self) -> None:
        key = "sk-test-0123456789"
        body = json.dumps({"message": "Hello", "files": [], "assistant_ids": ["shimpz-cloudflare"]}).encode()
        captured: dict[str, object] = {}

        class Controller:
            chat_turn_service = SimpleNamespace(
                chat=lambda team_id, payload, provider, api_key: (
                    captured.update(
                        team_id=team_id,
                        payload=payload,
                        provider=provider,
                        api_key=api_key,
                    )
                    or {"team_name": "Marketing", "reply": "Hello!"}
                )
            )

        token_value = "a" * 32
        handler = object.__new__(local_app.Handler)
        handler.command = "POST"
        handler.server = SimpleNamespace(controller=Controller(), token=token_value)
        handler.headers = Message()
        handler.headers["Authorization"] = f"Bearer {token_value}"
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = str(len(body))
        handler.headers["X-Shimpz-Model-Provider"] = "openai"
        handler.headers["X-Shimpz-Model-Api-Key"] = key
        handler.rfile = BytesIO(body)

        self.assertTrue(handler._authorized())
        status, response, *_audit = handler._chat_route(["v1", "teams", "team_1", "chat"])

        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(
            captured["payload"],
            {"message": "Hello", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
        )
        self.assertEqual(captured["provider"], "openai")
        self.assertEqual(captured["api_key"], key)
        self.assertNotIn(key, json.dumps(response))

    def test_power_rpc_receives_only_the_validated_input_and_private_envelopes(self) -> None:
        captured: list[object] = []
        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, object())

            def rpc(_container, spec, method, path, payload):
                captured.append((spec.assistant_id, method, path, payload))
                return LOOKUP_RESULT

            controller.assistant_lifecycle._rpc = rpc
            audit = mock.patch.object(local_app.local_audit, "record", return_value="trace")
            audit.start()
            self.addCleanup(audit.stop)
            with mock.patch.object(local_app.local_audit, "record", return_value="trace"):
                response = controller.invoke(
                    "team_1",
                    "shimpz-cloudflare",
                    "list-zones",
                    LOOKUP_INPUT,
                )

        self.assertEqual(
            captured,
            [
                (
                    "shimpz-cloudflare",
                    "POST",
                    "/v1/powers/list-zones",
                    {
                        "input": LOOKUP_INPUT,
                        "secrets": {},
                        "accounts": {
                            "cloudflare": {
                                "type": "oauth2-bearer",
                                "access_token": TEST_ACCOUNT_ACCESS_TOKEN,
                            }
                        },
                        "answers": [],
                    },
                )
            ],
        )
        self.assertEqual(response["result"], LOOKUP_RESULT)

    def test_power_rpc_surfaces_a_human_suspension_before_output_validation(self) -> None:
        suspension = local_app.power_execution.RpcSuspension(
            {
                "ordinal": 0,
                "kind": "request",
                "request_type": "str",
                "title": "Name",
                "summary": "Choose a name.",
                "docs": None,
                "options": [],
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, object())
            controller.assistant_lifecycle._rpc = lambda *_args: suspension
            with mock.patch.object(local_app.local_audit, "record", return_value="trace"):
                response = controller.invoke(
                    "team_1",
                    "shimpz-cloudflare",
                    "list-zones",
                    LOOKUP_INPUT,
                )

        self.assertEqual(response["suspend"], suspension.payload)
        self.assertNotIn("result", response)

    def test_power_output_containing_a_secret_is_blocked_and_redacted(self) -> None:
        raw_secret = TEST_ACCOUNT_ACCESS_TOKEN
        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, object())
            controller.assistant_lifecycle._rpc = lambda *_args: {
                "id": "123456789",
                "name": f"unsafe {raw_secret}",
                "username": "OpenAI",
            }
            with (
                mock.patch.object(local_app.local_audit, "record", return_value="trace"),
                self.assertRaises(local_app.ApiProblem) as leaked,
            ):
                controller.invoke(
                    "team_1",
                    "shimpz-cloudflare",
                    "list-zones",
                    LOOKUP_INPUT,
                )

        self.assertEqual(leaked.exception.code, "assistant-secret-exposure")
        self.assertNotIn(raw_secret, str(leaked.exception))
