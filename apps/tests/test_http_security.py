from __future__ import annotations

import ast
import importlib.util
import io
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

APP_SOURCE = Path(__file__).resolve().parents[1] / "app.py"


def _handler_method(name: str) -> ast.FunctionDef:
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    handler = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Handler")
    return next(node for node in handler.body if isinstance(node, ast.FunctionDef) and node.name == name)


def _load_app():
    apps_dir = APP_SOURCE.parent
    sys.path.insert(0, str(apps_dir))
    import docker
    import egress_lock
    import manifests
    import token_store

    spec = importlib.util.spec_from_file_location("app_http_security_subject", APP_SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load app driver")
    module = importlib.util.module_from_spec(spec)
    with (
        mock.patch.object(egress_lock, "require_enabled"),
        mock.patch.object(docker, "from_env", return_value=object()),
        mock.patch.object(token_store, "ensure_token", return_value="test-token"),
        mock.patch.object(manifests, "resolve_host_projects_root", return_value=Path("/workspace/projects")),
    ):
        spec.loader.exec_module(module)
    return module


class HttpSecurityStaticTests(unittest.TestCase):
    def test_rejects_excess_connections_without_starting_threads(self) -> None:
        module = _load_app()
        server = module.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            module.Handler,
            max_concurrency=1,
        )
        accepted, peer = socket.socketpair()
        try:
            self.assertTrue(server._request_slots.acquire(blocking=False))
            server.process_request(accepted, ("127.0.0.1", 1))
            self.assertEqual(peer.recv(1), b"")
        finally:
            peer.close()
            server._request_slots.release()
            server.server_close()

    def test_bearer_authorization_uses_constant_time_comparison(self) -> None:
        authorized = _handler_method("_authed")
        returned = next(node for node in authorized.body if isinstance(node, ast.Return))

        self.assertEqual(ast.unparse(returned.value), "stdlib_http.bearer_authorized(self.headers, _token)")

    def test_caddy_reconcile_loop_catches_only_docker_failures(self) -> None:
        loop = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
        function = next(
            node for node in loop.body if isinstance(node, ast.FunctionDef) and node.name == "_caddy_reconcile_loop"
        )
        caught_types = [ast.unparse(node.type) for node in ast.walk(function) if isinstance(node, ast.ExceptHandler)]

        self.assertEqual(caught_types, ["docker.errors.DockerException"])


class HttpBodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = _load_app()

    def test_oversized_body_is_rejected_before_it_is_read(self) -> None:
        handler = object.__new__(self.app.Handler)
        handler.headers = {"Content-Length": str(self.app.MAX_BODY_BYTES + 1)}
        handler.rfile = mock.Mock()

        with self.assertRaises(self.app.ApiError) as caught:
            handler._body()

        self.assertEqual(caught.exception.status, self.app.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        handler.rfile.read.assert_not_called()

    def test_invalid_and_negative_content_lengths_fail_closed(self) -> None:
        for raw_length, expected_status in (
            ("invalid", self.app.HTTPStatus.BAD_REQUEST),
            ("-1", self.app.HTTPStatus.REQUEST_ENTITY_TOO_LARGE),
        ):
            with self.subTest(raw_length=raw_length):
                handler = object.__new__(self.app.Handler)
                handler.headers = {"Content-Length": raw_length}
                handler.rfile = io.BytesIO(b"")
                with self.assertRaises(self.app.ApiError) as caught:
                    handler._body()
                self.assertEqual(caught.exception.status, expected_status)

    def test_query_parser_defaults_bare_lines_and_matches_exact_purge_key(self) -> None:
        handler = object.__new__(self.app.Handler)
        handler._send_json = mock.Mock()

        handler.path = "/v1/apps/example/logs?lines"
        with mock.patch.object(self.app, "_logs", return_value={"logs": ""}) as logs:
            handler._route("GET")
        logs.assert_called_once_with("example", 80)

        handler.path = "/v1/apps/example?not_purge_volume=1"
        with mock.patch.object(self.app, "_remove", return_value={"status": "removed"}) as remove:
            handler._route("DELETE")
        remove.assert_called_once_with("example", False)

    def test_candidate_cutover_rolls_back_both_names_on_rename_failure(self) -> None:
        old = mock.Mock()
        candidate = mock.Mock()
        candidate.rename.side_effect = self.app.docker.errors.APIError("rename failed")

        with (
            mock.patch.object(self.app, "_get_or_none", return_value=old),
            mock.patch.object(self.app.audit, "log"),
            self.assertRaises(self.app.ApiError) as caught,
        ):
            self.app._cutover_candidate("example", candidate, "app_example", "app_example__retiring")

        self.assertEqual(caught.exception.status, self.app.HTTPStatus.INTERNAL_SERVER_ERROR)
        self.assertEqual(old.rename.call_args_list, [mock.call("app_example__retiring"), mock.call("app_example")])
        candidate.remove.assert_called_once_with(force=True)
        old.remove.assert_not_called()

    def test_egress_state_is_atomic_canonical_and_removed_with_the_app(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_dir = root / ".tokens"
            token_dir.mkdir()
            token_path = token_dir / "example.token"
            token_path.write_text("../invalid-token", encoding="utf-8")

            with mock.patch.object(self.app, "APP_EGRESS_POLICY_DIR", root):
                token = self.app._egress_token("example")
                self.assertIsNotNone(self.app.EGRESS_TOKEN.fullmatch(token))
                self.assertEqual(token_path.read_text(encoding="ascii"), token)
                self.assertEqual(token_path.stat().st_mode & 0o777, 0o600)

                self.app._write_egress_policy(token, ["z.example", "a.example"])
                policy_path = root / f"{token}.json"
                first_inode = policy_path.stat().st_ino
                self.assertEqual(policy_path.read_text(encoding="utf-8"), '["a.example","z.example"]')

                self.app._write_egress_policy(token, ["new.example"])
                self.assertNotEqual(policy_path.stat().st_ino, first_inode)
                self.assertEqual(policy_path.read_text(encoding="utf-8"), '["new.example"]')
                self.assertEqual(list(root.glob(".*.tmp")), [])

                self.app._remove_egress_state("example")
                self.assertFalse(policy_path.exists())
                self.assertFalse(token_path.exists())

    def test_remove_revokes_egress_state_before_reporting_success(self) -> None:
        with (
            mock.patch.object(self.app, "_get_or_none", return_value=None),
            mock.patch.object(self.app, "_teardown_app_network"),
            mock.patch.object(self.app, "_remove_egress_state") as remove_egress,
            mock.patch.object(self.app.audit, "log", return_value="trace"),
        ):
            result = self.app._remove("example", False)

        remove_egress.assert_called_once_with("example")
        self.assertEqual(result, {"status": "removed", "trace_id": "trace"})


if __name__ == "__main__":
    unittest.main()
