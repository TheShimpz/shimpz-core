from __future__ import annotations

import grp
import hmac
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from hashlib import sha256
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

POSTGRESQL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(POSTGRESQL))

MODULE_STATE = tempfile.TemporaryDirectory(prefix="postgresql-service-module-test-")
PASSWORD_FILE = Path(MODULE_STATE.name) / "postgres-password"
PASSWORD_FILE.write_text("test-superuser-secret-long-enough\n", encoding="ascii")
os.environ.setdefault("SHIMPZ_POSTGRESQL_DSN", "postgresql://shimpz-brain@postgres:5432/postgres")
os.environ["SHIMPZ_POSTGRESQL_PASSWORD_FILE"] = str(PASSWORD_FILE)
os.environ["SHIMPZ_POSTGRESQL_SERVICE_TOKEN_FILE"] = str(Path(MODULE_STATE.name) / "token")
os.environ["SHIMPZ_POSTGRESQL_SERVICE_TOKEN_GROUP"] = grp.getgrgid(os.getgid()).gr_name
os.environ["SHIMPZ_POSTGRESQL_SERVICE_PRINCIPALS_FILE"] = str(Path(MODULE_STATE.name) / "principals.json")
os.environ["SHIMPZ_POSTGRESQL_SERVICE_AUDIT_LOG"] = str(Path(MODULE_STATE.name) / "audit.jsonl")

import app
import postgresql_client
import principal_store
import service_manifest
import validate


class PostgreSQLServiceTests(unittest.TestCase):
    def test_administrator_password_is_file_backed_and_strict(self) -> None:
        self.assertEqual(postgresql_client.PGPASSWORD, "test-superuser-secret-long-enough")
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            postgresql_client._load_password(Path(self.temporary.name) / "missing")
        short = Path(self.temporary.name) / "short"
        short.write_text("too-short\n", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "invalid"):
            postgresql_client._load_password(short)

    def test_rejects_excess_connections_without_starting_threads(self) -> None:
        server = app.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            app.Handler,
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

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="postgresql-service-test-")
        principal_store.STATE_PATH = Path(self.temporary.name) / "principals.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_project_validation_matches_postgres_identifier_limits(self) -> None:
        cases = {
            "Laudoctor": "laudoctor",
            "my project!!": "my_project",
            "  leading-trailing  ": "leading_trailing",
            "UP--PER": "up_per",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(validate.validate_project(raw), expected)

        for invalid in ("", None, 123, "!!!", "a" * 59):
            with self.subTest(invalid=invalid), self.assertRaises(validate.ValidationError):
                validate.validate_project(invalid)

    def test_team_and_principal_identifiers_are_server_derived(self) -> None:
        self.assertEqual(validate.team_project("captain_01"), "team_captain_01")

        token = "a" * 64
        self.assertEqual(validate.validate_principal_token(token), token)
        self.assertTrue(validate.tokens_equal(token, token))
        self.assertFalse(validate.tokens_equal(token, "b" * 64))
        for invalid in ("", "a" * 63, "A" * 64, "z" * 64, None):
            with self.subTest(invalid=invalid), self.assertRaises(validate.ValidationError):
                validate.validate_principal_token(invalid)

    def test_database_credentials_are_deterministic_and_keyed(self) -> None:
        password = postgresql_client.role_password("website")
        expected = hmac.new(
            postgresql_client.PGPASSWORD.encode(),
            postgresql_client.dbname("website").encode(),
            sha256,
        ).hexdigest()[:32]

        self.assertEqual(password, expected)
        self.assertEqual(len(password), 32)
        self.assertNotEqual(password, postgresql_client.role_password("other"))
        self.assertEqual(
            postgresql_client.database_url("website"),
            f"postgresql://proj_website:{password}@postgres:5432/proj_website",
        )

    def test_database_failures_do_not_reflect_commands_sql_or_stderr(self) -> None:
        completed = mock.Mock(returncode=23, stdout="", stderr="database-secret")
        with (
            mock.patch.object(postgresql_client.subprocess, "run", return_value=completed) as run,
            self.assertRaisesRegex(postgresql_client.PostgreSQLError, r"^Postgres command failed \(rc=23\)$") as raised,
        ):
            postgresql_client._run(["psql", "command-secret"], stdin="sql-secret")

        detail = str(raised.exception)
        for secret in ("command-secret", "sql-secret", "database-secret"):
            self.assertNotIn(secret, detail)
        self.assertEqual(run.call_args.kwargs["input"], "sql-secret")

    def test_psql_sends_sql_on_stdin_with_fail_fast_literal_variables(self) -> None:
        with mock.patch.object(postgresql_client, "_run", return_value="ok") as run:
            result = postgresql_client._psql(
                "postgres",
                "SELECT 1 WHERE rolname = :'role_name'",
                {"role_name": "proj_website"},
            )

        self.assertEqual(result, "ok")
        command = run.call_args.args[0]
        self.assertNotIn("SELECT 1 WHERE rolname = :'role_name'", command)
        self.assertIn("ON_ERROR_STOP=1", command)
        self.assertEqual(command[-2:], ["-f", "-"])
        self.assertEqual(run.call_args.kwargs["stdin"], "SELECT 1 WHERE rolname = :'role_name'\n")
        self.assertIn("role_name=proj_website", command)

    def test_principal_registry_hashes_tokens_and_enforces_one_exact_database(self) -> None:
        token_a, token_b = "a" * 64, "b" * 64
        main_database = "proj_team_alpha"
        principal_store.register("alpha", token_a, main_database)

        stored = principal_store.STATE_PATH.read_text(encoding="utf-8")
        self.assertNotIn(token_a, stored)
        self.assertEqual(principal_store.STATE_PATH.stat().st_mode & 0o777, 0o600)
        self.assertEqual(principal_store.database(token_a, "alpha"), main_database)
        self.assertTrue(principal_store.owns_database("alpha", main_database))
        self.assertFalse(principal_store.owns_database("alpha", "proj_team_other"))
        with self.assertRaises(principal_store.PrincipalError):
            principal_store.database(token_b, "alpha")
        with self.assertRaises(principal_store.PrincipalError):
            principal_store.database(token_a, "other")

        principal_store.register("alpha", token_b, main_database)
        with self.assertRaises(principal_store.PrincipalError):
            principal_store.database(token_a, "alpha")
        self.assertEqual(principal_store.database(token_b, "alpha"), main_database)

        principal_store.register("beta", token_a, "proj_team_beta")
        with self.assertRaises(principal_store.PrincipalStoreError):
            principal_store.register("beta", token_a, main_database)
        with self.assertRaises(principal_store.PrincipalStoreError):
            principal_store.register("gamma", "c" * 64, "unscoped")

    def test_retired_multi_database_registry_shape_is_rejected(self) -> None:
        principal_store.STATE_PATH.write_text(
            json.dumps(
                {
                    "a" * 64: {
                        "team_id": "alpha",
                        "databases": ["proj_team_alpha"],
                        "database_namespace": "b" * 12,
                        "retired": False,
                    }
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(principal_store.PrincipalStoreError):
            principal_store._read()

    def test_team_drop_is_idempotent_until_finalization(self) -> None:
        token = "c" * 64
        main_database = "proj_team_alpha"
        principal_store.register("alpha", token, main_database)

        with mock.patch.object(
            postgresql_client,
            "drop_db_and_role",
            side_effect=lambda project: {"dropped": f"proj_{project}"},
        ) as drop:
            first = app._drop_team({"team_id": "alpha"}, token)
            retry = app._drop_team({"team_id": "alpha"}, token)

        self.assertEqual(first["dropped"], [main_database])
        self.assertEqual(retry["dropped"], [main_database])
        self.assertEqual(drop.call_count, 2)
        self.assertEqual(principal_store.database(token, "alpha", allow_retired=True), main_database)
        with self.assertRaises(principal_store.PrincipalError):
            principal_store.database(token, "alpha")
        self.assertEqual(app._finalize_team({"team_id": "alpha"}), {"finalized": True})
        self.assertEqual(app._finalize_team({"team_id": "alpha"}), {"finalized": True})

    def test_retired_principal_blocks_reprovision_until_finalized(self) -> None:
        token = "d" * 64
        database = "proj_team_alpha"
        principal_store.register("alpha", token, database)
        principal_store.retire(token, "alpha")

        with self.assertRaisesRegex(principal_store.PrincipalError, "finalized"):
            principal_store.owns_database("alpha", database)
        with self.assertRaisesRegex(principal_store.PrincipalError, "finalized"):
            principal_store.register("alpha", "e" * 64, database)

        principal_store.finalize("alpha")
        principal_store.register("alpha", "e" * 64, database)
        self.assertEqual(principal_store.database("e" * 64, "alpha"), database)

    def test_unknown_internal_operation_cannot_fall_through_to_drop(self) -> None:
        with (
            mock.patch.object(app, "_drop_team") as drop,
            self.assertRaisesRegex(app.ApiError, "unsupported operation"),
        ):
            app._run_operation("future.operation", {"team_id": "alpha"}, "a" * 64)
        drop.assert_not_called()

    def test_client_refuses_foreign_or_incomplete_existing_resources(self) -> None:
        with (
            mock.patch.object(postgresql_client, "_role_exists", return_value=True),
            mock.patch.object(postgresql_client, "_db_exists", return_value=True),
            mock.patch.object(postgresql_client, "_psql") as psql,
            self.assertRaisesRegex(postgresql_client.PostgreSQLError, "without registry ownership"),
        ):
            postgresql_client.create_db_and_role("team_foreign_app")
        psql.assert_not_called()

        with (
            mock.patch.object(postgresql_client, "_role_exists", return_value=True),
            mock.patch.object(postgresql_client, "_db_exists", return_value=False),
            self.assertRaisesRegex(postgresql_client.PostgreSQLError, "are incomplete"),
        ):
            postgresql_client.create_db_and_role("team_incomplete_app")

    def test_manifest_is_closed_and_public_metadata_contains_no_credentials(self) -> None:
        manifest = service_manifest.load()
        self.assertEqual(manifest.id, "postgresql")
        self.assertEqual(manifest.scope, "space")
        self.assertEqual(manifest.credential_policy, "managed")
        self.assertEqual(manifest.data_plane, "direct")
        self.assertEqual(
            set(manifest.operations),
            {"team.provision", "team.finalize", "team.drop"},
        )
        self.assertTrue({"credentials", "secrets"}.isdisjoint(manifest.public()))

        canonical = service_manifest.MANIFEST_PATH.read_text(encoding="utf-8")
        invalid = (
            canonical.replace("[capabilities]", "unsupported = true\n\n[capabilities]"),
            canonical.replace('scope = "space"', 'scope = "team"'),
            canonical.replace('  "team.drop",', '  "team.drop",\n  "team.drop",'),
            "schema_version = [\n",
        )
        for index, source in enumerate(invalid):
            path = Path(self.temporary.name) / f"invalid-{index}.toml"
            path.write_text(source, encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(service_manifest.ManifestError):
                service_manifest.load(path)

    def test_http_discovery_is_public_while_mutation_requires_a_bearer(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            for path, expected in (("/healthz", {"status": "ok"}), ("/v1/service", app.SERVICE.public())):
                with self.subTest(path=path):
                    status, payload = self.http(server, "GET", path)
                    self.assertEqual(status, 200)
                    self.assertEqual(payload, expected)

            status, payload = self.http(server, "GET", "/v1/driver")
            self.assertEqual(status, 404)
            self.assertEqual(payload, {"error": "no route for GET /v1/driver"})

            status, payload = self.http(server, "POST", "/v1/teams/provision", body={})
            self.assertEqual(status, 403)
            self.assertEqual(payload, {"error": "bearer required"})

            for retired_path in ("/v1/teams/apps/create", "/v1/teams/apps/drop"):
                with self.subTest(retired_path=retired_path):
                    status, payload = self.http(server, "POST", retired_path, body={})
                    self.assertEqual(status, 404)
                    self.assertEqual(payload, {"error": f"no route for POST {retired_path}"})

            with mock.patch.object(
                app,
                "_provision_team",
                side_effect=postgresql_client.PostgreSQLError("database-secret"),
            ):
                status, payload = self.http(
                    server,
                    "POST",
                    "/v1/teams/provision",
                    body={"team_id": "alpha", "principal_token": "a" * 64},
                    bearer=app._provisioner_token,
                )
            self.assertEqual(status, 502)
            self.assertEqual(payload, {"error": "database operation failed"})
            self.assertNotIn("database-secret", json.dumps(payload))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    @staticmethod
    def http(
        server: ThreadingHTTPServer,
        method: str,
        path: str,
        *,
        body: dict[str, object] | None = None,
        bearer: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        try:
            encoded = None if body is None else json.dumps(body)
            headers = {} if body is None else {"Content-Type": "application/json"}
            if bearer is not None:
                headers["Authorization"] = f"Bearer {bearer}"
            connection.request(method, path, encoded, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
