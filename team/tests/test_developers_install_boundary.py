"""Hosted Controller boundary for delegated Developers installation."""

from __future__ import annotations

import copy
import json
import time
import types
import unittest
from http import HTTPStatus
from unittest import mock

from hosted_app_fixture import hosted_apps, hosted_controller, hosted_lifecycle, hosted_resources, runtime_state

CONTRACT_ROOT = (
    __import__("pathlib").Path(__file__).resolve().parents[1]
    / "contracts"
    / "developers-controller"
    / "v1"
)
VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
REQUEST = VECTORS["fixtures"]["controller_install_request"]["value"]
CLAIMS = VECTORS["fixtures"]["assistant_install_delegation"]["value"]
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]


class _Delegation:
    def verify(self, _headers, *, action: str, request=None):
        expected_action = "teams:list" if request is None else "assistant:install"
        if action != expected_action:
            raise AssertionError("wrong delegation action")
        return copy.deepcopy(CLAIMS)


class _Client:
    def __init__(self) -> None:
        self.authorization = None

    def resolve(self, source_digest: str):
        if source_digest != RESOLUTION["source_digest"]:
            raise AssertionError("wrong source digest")
        return copy.deepcopy(RESOLUTION)

    def authorize_install(self, request):
        self.authorization = request
        issued_at = int(time.time())
        return {
            "version": 1,
            "authorization_id": "authorization_1",
            **{key: value for key, value in request.items() if key != "version"},
            "issued_at": issued_at,
            "expires_at": issued_at + 60,
        }


class DevelopersInstallBoundaryTests(unittest.TestCase):
    def _handler(self):
        handler = object.__new__(hosted_controller.Handler)
        handler.headers = object()
        handler._read_driver_body = mock.Mock(return_value=copy.deepcopy(REQUEST))
        handler._send_json = mock.Mock()
        return handler

    def test_install_binds_owner_trust_final_authorization_and_response(self) -> None:
        handler = self._handler()
        client = _Client()
        trust = types.SimpleNamespace(verify=mock.Mock())
        delegation = _Delegation()
        lease = types.SimpleNamespace(owner=CLAIMS["account_id"])

        def install(team_id, binding, owner, supplied_lease, *, authorize_start):
            self.assertEqual(team_id, REQUEST["team_id"])
            self.assertEqual(owner, CLAIMS["account_id"])
            self.assertIs(supplied_lease, lease)
            authorize_start()
            return {
                "source_digest": binding.resolution["source_digest"],
                "oci_digest": binding.resolution["oci_digest"],
                "binding_digest": binding.binding_digest,
            }

        with (
            mock.patch.multiple(
                runtime_state,
                _developers_delegation=delegation,
                _developers_client=client,
                _artifact_trust=trust,
                _enforce_rate=lambda *_args: None,
            ),
            mock.patch.object(hosted_resources, "_authorize", return_value=lease) as authorize,
            mock.patch.object(hosted_apps, "_install_dynamic_assistant", side_effect=install),
        ):
            handler._route_developers_install()

        authorize.assert_called_once_with(
            REQUEST["team_id"],
            ("account", CLAIMS["account_id"]),
        )
        trust.verify.assert_called_once_with(RESOLUTION)
        self.assertEqual(client.authorization["delegation_jti"], CLAIMS["jti"])
        status, response = handler._send_json.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(response["status"], "installed")
        self.assertEqual(response["assistant_id"], RESOLUTION["assistant_id"])
        self.assertEqual(response["source_digest"], REQUEST["source_digest"])

    def test_team_listing_exposes_only_contract_fields(self) -> None:
        handler = self._handler()
        handler.headers = types.SimpleNamespace(get_all=lambda *_args, **_kwargs: [])
        listing = {
            "teams": [
                {
                    "team_id": "team_1",
                    "team_name": "First Team",
                    "owner": CLAIMS["account_id"],
                    "container": "secret-internal-name",
                }
            ]
        }
        with (
            mock.patch.multiple(
                runtime_state,
                _developers_delegation=_Delegation(),
                _developers_client=_Client(),
                _artifact_trust=types.SimpleNamespace(),
            ),
            mock.patch.object(hosted_controller.strict_http, "reject_body"),
            mock.patch.object(hosted_lifecycle, "_list", return_value=listing) as list_teams,
        ):
            handler._route_developers_teams()

        list_teams.assert_called_once_with(owner=CLAIMS["account_id"])
        self.assertEqual(
            handler._send_json.call_args.args,
            (HTTPStatus.OK, {"version": 1, "teams": [{"id": "team_1", "name": "First Team"}]}),
        )


if __name__ == "__main__":
    unittest.main()
