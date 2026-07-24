from __future__ import annotations

import contextlib
import os
import tempfile
import types
import unittest
from dataclasses import replace
from email.message import Message
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from unittest import mock

from hosted_app_fixture import (
    app,
    hosted_apps,
    hosted_chat_segment,
    hosted_controller,
    hosted_resources,
    runtime_state,
)

assistant_account_challenges = runtime_state.assistant_account_challenges
assistant_manifest = hosted_apps.assistant_manifest
assistant_secret_challenges = runtime_state.assistant_secret_challenges
brain_runtime_client = runtime_state.brain_runtime_client
chat_orchestrator = hosted_chat_segment.chat_orchestrator
manifests = hosted_apps.manifests
marketplace = hosted_apps.marketplace
network_policy = hosted_resources.network_policy
oauth_account_store = runtime_state.oauth_account_store
oauth_http_client = runtime_state.oauth_http_client
power_journal = runtime_state.power_journal
hosted_egress_policy = hosted_apps.egress_policy


class _RouteHarness:
    def __init__(self, body: dict | None = None) -> None:
        self.body = body
        self.read_count = 0
        self.sent: list[tuple[HTTPStatus, dict]] = []

    def _read_driver_body(self, keys: set[str]) -> dict:
        self.read_count += 1
        if self.body is None or set(self.body) != keys:
            raise AssertionError("unexpected body contract")
        return self.body

    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        self.sent.append((status, payload))


class HostedHttpBoundaryTests(unittest.TestCase):
    def test_every_hosted_operation_has_one_dispatch_handler(self) -> None:
        strict_http = hosted_controller.strict_http
        hosted_operations = {
            route.operation
            for route in strict_http.CONTROLLER_ROUTES
            if strict_http.HOSTED_CONTROLLER in route.profiles
        }
        dispatch_groups = (
            set(hosted_controller._GLOBAL_ROUTES),
            set(hosted_controller._PREAUTHORIZED_ROUTES),
            set(hosted_controller._AUTHORIZED_ROUTES),
        )
        self.assertEqual(set().union(*dispatch_groups), hosted_operations)
        self.assertEqual(sum(map(len, dispatch_groups)), len(hosted_operations))

    @staticmethod
    def _handler(body: bytes, *headers: tuple[str, str]) -> app.Handler:
        handler = object.__new__(app.Handler)
        handler.headers = Message()
        for name, value in headers:
            handler.headers.add_header(name, value)
        handler.rfile = BytesIO(body)
        return handler

    def test_operator_bearer_is_constant_time_and_duplicate_headers_fail_closed(self) -> None:
        accepted = self._handler(b"", ("Authorization", "Bearer operator-token"))
        wrong = self._handler(b"", ("Authorization", "Bearer operator-tokee"))
        duplicate = self._handler(
            b"",
            ("Authorization", "Bearer operator-token"),
            ("Authorization", "Bearer operator-token"),
        )

        with mock.patch.object(
            hosted_controller.strict_http.hmac,
            "compare_digest",
            wraps=hosted_controller.strict_http.hmac.compare_digest,
        ) as compare:
            self.assertEqual(accepted._principal(), ("operator", None))
            self.assertIsNone(wrong._principal())
            self.assertIsNone(duplicate._principal())

        self.assertEqual(compare.call_count, 2)

    def test_read_body_accepts_one_strict_json_object(self) -> None:
        body = b'{"team_name":"Marketing"}'
        handler = self._handler(
            body,
            ("Content-Length", str(len(body))),
            ("Content-Type", "application/json; charset=utf-8"),
        )

        self.assertEqual(handler._read_body(), {"team_name": "Marketing"})

    def test_read_body_rejects_ambiguous_or_non_object_documents(self) -> None:
        cases = (
            (b"{}", (("Transfer-Encoding", "chunked"), ("Content-Type", "application/json")), HTTPStatus.BAD_REQUEST),
            (b'{"a":1,"a":2}', (("Content-Type", "application/json"),), HTTPStatus.BAD_REQUEST),
            (b'{"a":NaN}', (("Content-Type", "application/json"),), HTTPStatus.BAD_REQUEST),
            (b"[]", (("Content-Type", "application/json"),), HTTPStatus.UNPROCESSABLE_ENTITY),
            (b"{}", (), HTTPStatus.UNSUPPORTED_MEDIA_TYPE),
            (b"{}", (("Content-Type", "text/plain"),), HTTPStatus.UNSUPPORTED_MEDIA_TYPE),
        )

        for body, extra_headers, expected_status in cases:
            headers = (("Content-Length", str(len(body))), *extra_headers)
            handler = self._handler(body, *headers)
            with self.subTest(body=body, headers=headers), self.assertRaises(runtime_state.ApiError) as caught:
                handler._read_body()
            self.assertEqual(caught.exception.status, expected_status)


class HostedAllowedHostsAdmissionTests(unittest.TestCase):
    @staticmethod
    def _container_with_environment(environment: dict[str, str]):
        return types.SimpleNamespace(
            attrs={"Config": {"Env": [f"{key}={value}" for key, value in environment.items()]}},
        )

    def test_manifest_must_match_reviewed_hosts_before_admission(self) -> None:
        spec = marketplace.APPS["shimpz-cloudflare"]
        container = types.SimpleNamespace(id="assistant-generation")
        reviewed_contracts: list[assistant_manifest.ManifestContract] = []

        def admit(_container, reviewed):
            reviewed_contracts.append(reviewed)
            return reviewed

        cache = types.SimpleNamespace(
            get=admit,
        )
        machine_cache = types.SimpleNamespace(get=lambda _container, _accounts, reviewed: reviewed)
        with (
            mock.patch.multiple(
                runtime_state,
                _assistant_allowed_hosts_cache=cache,
                _assistant_machine_contract_cache=machine_cache,
            ),
            mock.patch.object(
                hosted_apps,
                "_require_assistant_genesis",
                return_value="Use reviewed Powers.",
            ),
        ):
            self.assertEqual(hosted_apps._admit_app_contract(spec, container), tuple(sorted(spec.allowed_hosts)))
        self.assertEqual(len(reviewed_contracts), 1)
        self.assertEqual(
            {account.id: (account.provider, account.scopes) for account in reviewed_contracts[0].accounts},
            {
                account_id: (account.provider, tuple(sorted(account.scopes)))
                for account_id, account in spec.assistant.accounts.items()
            },
        )
        exact = reviewed_contracts[0]
        account = exact.accounts[0]
        drifted = (
            replace(exact, accounts=(replace(account, provider="other"),)),
            replace(exact, accounts=(replace(account, scopes=("tweet.read",)),)),
        )
        with (
            mock.patch.multiple(
                runtime_state,
                _assistant_allowed_hosts_cache=assistant_manifest.ManifestContractCache(),
                _assistant_machine_contract_cache=machine_cache,
            ),
            mock.patch.object(assistant_manifest, "read_container_manifest_contract", return_value=exact),
        ):
            self.assertEqual(hosted_apps._require_assistant_allowed_hosts(spec, container), exact.allowed_hosts)
        for declared in drifted:
            with (
                self.subTest(declared=declared),
                mock.patch.multiple(
                    runtime_state,
                    _assistant_allowed_hosts_cache=assistant_manifest.ManifestContractCache(),
                    _assistant_machine_contract_cache=machine_cache,
                ),
                mock.patch.object(
                    assistant_manifest,
                    "read_container_manifest_contract",
                    return_value=declared,
                ),
                self.assertRaises(runtime_state.ApiError) as drift,
            ):
                hosted_apps._require_assistant_allowed_hosts(spec, container)
            self.assertEqual(drift.exception.status, HTTPStatus.CONFLICT)

        def reject(_container, _reviewed):
            raise assistant_manifest.ManifestError("mismatch")

        with (
            mock.patch.multiple(
                runtime_state,
                _assistant_allowed_hosts_cache=types.SimpleNamespace(get=reject),
                _assistant_machine_contract_cache=machine_cache,
            ),
            self.assertRaises(runtime_state.ApiError) as caught,
        ):
            hosted_apps._admit_app_contract(spec, container)
        self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_manifest_mismatch_rolls_back_before_policy_proxy_or_start(self) -> None:
        events: list[object] = []
        spec = marketplace.APPS["shimpz-cloudflare"]
        state = {"created": False}
        container = types.SimpleNamespace(
            id="assistant-generation",
            attrs={},
            labels={"team.app.db": "0"},
            reload=lambda: None,
        )
        network = types.SimpleNamespace(
            disconnect=lambda target: events.append(("disconnect", target.id)),
            connect=lambda target, *, aliases: events.append(("connect-app", target.id, tuple(aliases))),
        )

        def create(**_kwargs):
            state["created"] = True
            events.append("create")
            return container

        engine = types.SimpleNamespace(containers=types.SimpleNamespace(create=create))

        def reject(_spec, _container):
            events.append("admit")
            raise runtime_state.ApiError(HTTPStatus.CONFLICT, "allowed_hosts mismatch")

        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o770)
            with (
                mock.patch.multiple(
                    runtime_state,
                    _lock_for=lambda _team_id: contextlib.nullcontext(),
                    _docker=engine,
                    APP_EGRESS_POLICY_DIR=Path(directory),
                    APP_EGRESS_POLICY_GID=os.getgid(),
                ),
                mock.patch.multiple(
                    hosted_resources,
                    _require_current_authorization=lambda *_args, **_kwargs: types.SimpleNamespace(
                        labels={"team.name": "Marketing"}
                    ),
                    _prepare_marketplace_image=lambda _spec: None,
                    _get_container=lambda _name: container if state["created"] else None,
                    _reserve_capacity=lambda *_args, **_kwargs: contextlib.nullcontext(),
                    _require_team_runtime=lambda: None,
                    _ensure_team_network=lambda _team_id: network,
                    _safe_connect=lambda *_args, **_kwargs: events.append("connect-proxy"),
                    _start_team_with_isolation=lambda _container: events.append("start"),
                    _remove_team_container=lambda target: events.append(("remove-container", target.id)) or True,
                ),
                mock.patch.object(hosted_apps, "_admit_app_contract", side_effect=reject),
                mock.patch.object(
                    hosted_apps,
                    "_write_egress_policy",
                    side_effect=lambda *_args: events.append("write-policy"),
                ),
                mock.patch.object(hosted_apps, "_team_app_containers", return_value=[]),
                mock.patch.object(manifests, "build_team_app_kwargs", return_value={}),
                mock.patch.object(network_policy, "app_identity_valid", return_value=True),
                self.assertRaises(runtime_state.ApiError) as caught,
            ):
                hosted_apps._install_app(
                    "team_1",
                    "shimpz-cloudflare",
                    spec,
                    "account_1",
                    types.SimpleNamespace(owner="account_1"),
                )
            self.assertEqual(list(Path(directory).rglob("*")), [Path(directory) / ".tokens"])

        self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)
        self.assertEqual(
            events,
            [
                "create",
                ("disconnect", "assistant-generation"),
                ("connect-app", "assistant-generation", ("shimpz-cloudflare", "shimpz-cloudflare.team")),
                "admit",
                ("remove-container", "assistant-generation"),
            ],
        )

    def test_existing_policy_bytes_must_match_the_admitted_hosts(self) -> None:
        hosts = ("api.open-meteo.com", "geocoding-api.open-meteo.com")
        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o770)
            with mock.patch.multiple(
                runtime_state,
                APP_EGRESS_POLICY_DIR=Path(directory),
                APP_EGRESS_POLICY_GID=os.getgid(),
            ):
                token = hosted_apps._app_egress_token("team_1", "shimpz-cloudflare")
                assert token is not None
                hosted_apps._write_egress_policy(token, hosts)
                self.assertEqual(
                    hosted_apps._validate_egress_policy("team_1", "shimpz-cloudflare", hosts),
                    token,
                )

                (Path(directory) / f"{token}.json").write_text('["evil.example"]', encoding="ascii")
                with self.assertRaises(runtime_state.ApiError) as caught:
                    hosted_apps._validate_egress_policy("team_1", "shimpz-cloudflare", hosts)
        self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_egress_reservation_constructs_one_store_for_the_operation(self) -> None:
        hosts = ("api.open-meteo.com",)
        with tempfile.TemporaryDirectory() as directory:
            policy_root = Path(directory)
            policy_root.chmod(0o770)
            with (
                mock.patch.multiple(
                    runtime_state,
                    APP_EGRESS_POLICY_DIR=policy_root,
                    APP_EGRESS_POLICY_GID=os.getgid(),
                ),
                mock.patch.object(
                    hosted_egress_policy,
                    "EgressPolicyStore",
                    wraps=hosted_egress_policy.EgressPolicyStore,
                ) as store_constructor,
            ):
                token, environment = hosted_apps._reserve_egress_environment(
                    "team_1",
                    "shimpz-cloudflare",
                    hosts,
                )

        self.assertIsNotNone(token)
        self.assertEqual(environment, hosted_apps._egress_proxy_environment(token))
        store_constructor.assert_called_once_with(
            policy_root,
            os.getgid(),
            "localhost,127.0.0.1,::1,postgres,.team",
        )

    def test_nonempty_hosts_require_the_exact_admitted_proxy_token(self) -> None:
        token = "a" * 32
        hosts = ("api.open-meteo.com",)
        expected = hosted_apps._egress_proxy_environment(token)
        hosted_apps._validate_assistant_proxy_environment(
            self._container_with_environment(expected),
            token,
            hosts,
        )

        drifted_environments = {
            "wrong-token": {**expected, "HTTPS_PROXY": expected["HTTPS_PROXY"].replace(token, "b" * 32)},
            "missing-lowercase": {key: value for key, value in expected.items() if key != "https_proxy"},
            "http-proxy": {**expected, "HTTP_PROXY": "http://app-egress-proxy:8889"},
            "all-proxy": {**expected, "all_proxy": "http://app-egress-proxy:8889"},
        }
        for name, environment in drifted_environments.items():
            with self.subTest(name=name), self.assertRaises(runtime_state.ApiError) as caught:
                hosted_apps._validate_assistant_proxy_environment(
                    self._container_with_environment(environment),
                    token,
                    hosts,
                )
            self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_empty_hosts_forbid_every_proxy_environment_variable(self) -> None:
        hosted_apps._validate_assistant_proxy_environment(
            self._container_with_environment({"SHIMPZ_TEAM_ID": "team_1"}),
            None,
            (),
        )

        for key in ("HTTPS_PROXY", "http_proxy", "ALL_PROXY", "no_proxy", "FTP_PROXY", "custom_proxy"):
            with self.subTest(key=key), self.assertRaises(runtime_state.ApiError) as caught:
                hosted_apps._validate_assistant_proxy_environment(
                    self._container_with_environment({key: "unexpected"}),
                    None,
                    (),
                )
            self.assertEqual(caught.exception.status, HTTPStatus.CONFLICT)

    def test_empty_hosts_build_no_proxy_environment(self) -> None:
        spec = marketplace.APPS["shimpz-cloudflare"]
        kwargs = manifests.build_team_app_kwargs("team_1", "shimpz-cloudflare", spec)
        environment = kwargs["environment"]

        self.assertFalse({key for key in environment if key.upper().endswith("_PROXY")})
