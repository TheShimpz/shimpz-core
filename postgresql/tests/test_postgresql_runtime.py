from __future__ import annotations

import contextlib
import grp
import http.client
import io
import json
import os
import runpy
import socket
import tempfile
import threading
import unittest
from email.message import Message
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

POSTGRESQL = Path(__file__).resolve().parents[1]
MODULE_STATE = tempfile.TemporaryDirectory(prefix="postgresql-runtime-module-test-")
PASSWORD_FILE = Path(MODULE_STATE.name) / "postgres-password"
PASSWORD_FILE.write_text("test-superuser-secret-long-enough\n", encoding="ascii")
os.environ.setdefault("SHIMPZ_POSTGRESQL_DSN", "postgresql://shimpz-postgresql-service@postgres:5432/postgres")
os.environ["SHIMPZ_POSTGRESQL_PASSWORD_FILE"] = str(PASSWORD_FILE)
os.environ["SHIMPZ_POSTGRESQL_SERVICE_TOKEN_FILE"] = str(Path(MODULE_STATE.name) / "token")
os.environ["SHIMPZ_POSTGRESQL_SERVICE_TOKEN_GROUP"] = grp.getgrgid(os.getgid()).gr_name
os.environ["SHIMPZ_POSTGRESQL_SERVICE_PRINCIPALS_FILE"] = str(Path(MODULE_STATE.name) / "principals.json")
os.environ["SHIMPZ_POSTGRESQL_SERVICE_AUDIT_LOG"] = str(Path(MODULE_STATE.name) / "audit.jsonl")

import app
import audit
import postgresql_client
import principal_store
import service_manifest
import stdlib_http
import token_store
import validate


class _Response:
    def __init__(self, status: int, payload: object) -> None:
        self.status = status
        self.payload = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self.payload


class _Connection:
    def __init__(self, status: int, payload: object, *, failure: bool = False) -> None:
        self.response = _Response(status, payload)
        self.failure = failure
        self.closed = False
        self.requests: list[tuple[str, str]] = []

    def request(self, method: str, path: str, **_kwargs: object) -> None:
        self.requests.append((method, path))
        if self.failure:
            raise OSError("unavailable")

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class _JsonHandler:
    def __init__(self) -> None:
        self.status: HTTPStatus | None = None
        self.headers: list[tuple[str, str]] = []
        self.wfile = io.BytesIO()

    def send_response(self, status: HTTPStatus) -> None:
        self.status = status

    def send_header(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def end_headers(self) -> None:
        return


class _Crash(BaseException):
    """Process death: none of the Service's exception compensation runs."""


class _FakePostgres:
    """In-memory Postgres catalog driven through the client's `_psql`/`_run` seams."""

    def __init__(self, *, roles: set[str] | None = None, databases: set[str] | None = None) -> None:
        self.roles = set(roles or ())
        self.databases = set(databases or ())
        self.crash_on_createdb = False
        self.fail_after: str | None = None
        self.commands: list[str] = []

    def _record(self, command: str) -> None:
        """Record an applied command; `fail_after` models a command that committed and then timed out."""
        self.commands.append(command)
        if command == self.fail_after:
            raise postgresql_client.PostgreSQLError("Postgres command timed out")

    def psql(self, _database: str, sql: str, variables: dict[str, str] | None = None) -> str:
        if "FROM pg_roles" in sql:
            return "1\n" if variables["role_name"] in self.roles else ""
        if "FROM pg_database" in sql:
            return "1\n" if variables["database_name"] in self.databases else ""
        name = sql.split('"')[1]
        if sql.startswith("CREATE ROLE"):
            if name in self.roles:
                raise postgresql_client.PostgreSQLError("role exists")
            self.roles.add(name)
        elif sql.startswith("DROP ROLE IF EXISTS"):
            self.roles.discard(name)
        self._record(sql.split(' "')[0])
        return ""

    def run(self, command: list[str], *, stdin: str | None = None) -> str:
        tool, name = command[0], command[-1]
        if tool == "createdb":
            if self.crash_on_createdb:
                raise _Crash
            if name in self.databases:
                raise postgresql_client.PostgreSQLError("database exists")
            self.databases.add(name)
        elif tool == "dropdb":
            self.databases.discard(name)
        self._record(tool)
        return ""

    @contextlib.contextmanager
    def serving(self):
        with (
            mock.patch.object(postgresql_client, "_psql", side_effect=self.psql),
            mock.patch.object(postgresql_client, "_run", side_effect=self.run),
        ):
            yield self


_ALPHA = {"team_id": "alpha", "principal_token": "a" * 64, "not_after": 2**53}
_ALPHA_ABSENT = {"team_id": "alpha", "not_after": 0}
_ALPHA_DATABASE = "proj_team_alpha"


class PostgreSQLRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="postgresql-runtime-test-")
        self.root = Path(self.temporary.name)
        self.original_audit_path = audit.AUDIT_PATH
        self.original_audit_max = audit.MAX_BYTES
        self.original_principal_path = principal_store.STATE_PATH
        self.original_token_path = token_store.TOKEN_PATH
        audit.AUDIT_PATH = self.root / "audit" / "audit.jsonl"
        principal_store.STATE_PATH = self.root / "principals.json"
        token_store.TOKEN_PATH = self.root / "token" / "bearer"
        clock = mock.patch.object(app, "_fence_clock", app._FenceClock())
        clock.start()
        self.addCleanup(clock.stop)

    def tearDown(self) -> None:
        audit.AUDIT_PATH = self.original_audit_path
        audit.MAX_BYTES = self.original_audit_max
        principal_store.STATE_PATH = self.original_principal_path
        token_store.TOKEN_PATH = self.original_token_path
        self.temporary.cleanup()

    @contextlib.contextmanager
    def _server(self):
        server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    @staticmethod
    def _request(
        server: app.BoundedThreadingHTTPServer,
        method: str,
        path: str,
        body: object | None = None,
        bearer: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        connection = http.client.HTTPConnection(*server.server_address, timeout=3)
        encoded = None if body is None else json.dumps(body)
        headers = {} if body is None else {"Content-Type": "application/json"}
        if bearer is not None:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            connection.request(method, path, encoded, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_stdlib_http_primitives_are_closed_and_redacted(self) -> None:
        headers = Message()
        self.assertEqual(stdlib_http.bearer_token(headers), "")
        headers.add_header("Authorization", "Basic value")
        self.assertEqual(stdlib_http.bearer_token(headers), "")
        headers.replace_header("Authorization", "Bearer exact")
        self.assertEqual(stdlib_http.bearer_token(headers), "exact")
        self.assertTrue(stdlib_http.bearer_authorized(headers, "exact"))
        headers.add_header("Authorization", "Bearer duplicate")
        self.assertFalse(stdlib_http.bearer_authorized(headers, "exact"))

        handler = _JsonHandler()
        stdlib_http.send_json(handler, HTTPStatus.CREATED, {"created": True})
        self.assertEqual(handler.status, HTTPStatus.CREATED)
        self.assertEqual(json.loads(handler.wfile.getvalue()), {"created": True})

        self.assertEqual(stdlib_http.read_json_body({}, io.BytesIO(), max_bytes=4), {})
        self.assertEqual(
            stdlib_http.read_json_body({"Content-Length": "2"}, io.BytesIO(b"{}"), max_bytes=4),
            {},
        )
        malformed = (
            ({"Content-Length": "invalid"}, b"", "invalid Content-Length"),
            ({"Content-Length": "-1"}, b"", "too large"),
            ({"Content-Length": "5"}, b"{}", "too large"),
            ({"Content-Length": "1"}, b"{", "invalid JSON"),
            ({"Content-Length": "2"}, b"[]", "must be an object"),
        )
        for malformed_headers, body, message in malformed:
            with self.subTest(message=message), self.assertRaisesRegex(stdlib_http.HttpError, message):
                stdlib_http.read_json_body(malformed_headers, io.BytesIO(body), max_bytes=4)

        route = stdlib_http.Route("GET", app.re.compile(r"^/items/(?P<item>[a-z]+)$"), "items.get")
        match = stdlib_http.resolve_route((route,), "GET", "/items/alpha?tag=a&tag=b")
        self.assertEqual(
            (match.operation, match.params, match.query),
            ("items.get", {"item": "alpha"}, {"tag": ["a", "b"]}),
        )
        with self.assertRaisesRegex(stdlib_http.HttpError, "no route"):
            stdlib_http.resolve_route((route,), "POST", "/items/alpha")

        emitted: list[stdlib_http.HttpFailure] = []
        stdlib_http.dispatch(lambda: None, classify=lambda _exc: None, emit=emitted.append, unexpected_message="closed")
        stdlib_http.dispatch(
            lambda: (_ for _ in ()).throw(KeyError("secret")),
            classify=lambda _exc: None,
            emit=emitted.append,
            unexpected_message="closed",
        )
        expected = stdlib_http.HttpFailure(HTTPStatus.CONFLICT, "public", "audit", "denied")
        stdlib_http.dispatch(
            lambda: (_ for _ in ()).throw(ValueError("invalid")),
            classify=lambda _exc: expected,
            emit=emitted.append,
            unexpected_message="closed",
        )
        self.assertEqual(emitted[0].public_message, "closed")
        self.assertEqual(emitted[0].audit_reason, "KeyError")
        self.assertIs(emitted[1], expected)

    def test_healthcheck_requires_liveness_and_a_protected_mutation_gate(self) -> None:
        healthcheck = POSTGRESQL / "healthcheck.py"
        cases = (
            ((_Connection(200, {"status": "ok"}), _Connection(403, {})), 0),
            ((_Connection(503, {"status": "down"}),), 1),
            ((_Connection(200, {"status": "ok"}), _Connection(200, {})), 1),
            ((_Connection(200, {"status": "ok"}), _Connection(403, {}, failure=True)), 1),
        )
        for connections, expected in cases:
            with (
                self.subTest(expected=expected),
                mock.patch("http.client.HTTPConnection", side_effect=connections),
                self.assertRaises(SystemExit) as raised,
            ):
                runpy.run_path(str(healthcheck), run_name="__main__")
            self.assertEqual(raised.exception.code, expected)
            self.assertTrue(connections[0].closed)

        failed = _Connection(200, {"status": "ok"}, failure=True)
        with (
            mock.patch("http.client.HTTPConnection", return_value=failed),
            self.assertRaises(SystemExit) as raised,
        ):
            runpy.run_path(str(healthcheck), run_name="__main__")
        self.assertEqual(raised.exception.code, 1)
        self.assertTrue(failed.closed)

    def test_concurrent_audit_writes_rotate_one_at_a_time_and_keep_every_line(self) -> None:
        # Each rotation waits up to a second for the other writer to rotate too; the audit lock must keep them apart.
        audit_module = audit
        active = peak = 0
        guard = threading.Lock()
        barrier = threading.Barrier(2, timeout=1)
        rotate = audit_module._rotate

        def overlapping_rotate() -> None:
            nonlocal active, peak
            with guard:
                active += 1
                peak = max(peak, active)
            with contextlib.suppress(threading.BrokenBarrierError):
                barrier.wait()
            rotate()
            with guard:
                active -= 1

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "audit.jsonl")
            with (
                mock.patch.object(audit_module, "AUDIT_PATH", path),
                mock.patch.object(audit_module, "_rotate", overlapping_rotate),
                mock.patch("sys.stdout", io.StringIO()),
            ):
                writers = [
                    threading.Thread(
                        target=audit_module.log, args=("connect", f"host{index}.example:443"), kwargs={"result": "ok"}
                    )
                    for index in range(2)
                ]
                for writer in writers:
                    writer.start()
                for writer in writers:
                    writer.join()
            lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(peak, 1)
        self.assertEqual(len(lines), 2)

    def test_audit_rotation_and_token_materialization_are_durable(self) -> None:
        with (
            mock.patch.object(audit.uuid, "uuid4", return_value=mock.Mock(hex="a" * 32)),
            mock.patch.object(audit.time, "strftime", return_value="2026-08-07T00:00:00Z"),
        ):
            self.assertEqual(audit.log("provision", "team", result="ok", level="debug"), "a" * 32)
            audit.MAX_BYTES = 0
            audit.log("drop", "team", result="denied")
            audit.AUDIT_PATH.with_name("audit.jsonl.1").write_text("first", encoding="utf-8")
            audit.AUDIT_PATH.with_name("audit.jsonl.2").write_text("second", encoding="utf-8")
            audit.log("drop", "team", result="error")
        self.assertEqual(audit.AUDIT_PATH.with_name("audit.jsonl.2").read_text(), "first")
        self.assertEqual(audit.AUDIT_PATH.with_name("audit.jsonl.3").read_text(), "second")

        with mock.patch.object(token_store, "_group_readable") as group_readable:
            token = token_store.ensure_token()
            self.assertEqual(token_store.ensure_token(), token)
            self.assertEqual(group_readable.call_count, 2)
            token_store.TOKEN_PATH.write_text("", encoding="utf-8")
            self.assertNotEqual(token_store.ensure_token(), token)

    def test_manifest_helpers_and_every_closed_field_fail_closed(self) -> None:
        with self.assertRaisesRegex(service_manifest.ManifestError, "must be a table"):
            service_manifest._closed_keys([], {"one"}, "value")
        with self.assertRaisesRegex(service_manifest.ManifestError, "is missing"):
            service_manifest._closed_keys({}, {"one"}, "value")
        with self.assertRaisesRegex(service_manifest.ManifestError, "unknown keys"):
            service_manifest._closed_keys({"one": 1, "two": 2}, {"one"}, "value")
        for value in (None, "", " padded", "line\nnext", "line\rnext", "x" * 81):
            with self.subTest(value=value), self.assertRaises(service_manifest.ManifestError):
                service_manifest._string(value, "field")
        with self.assertRaisesRegex(service_manifest.ManifestError, "must be one of"):
            service_manifest._choice("other", "field", {"allowed"})

        canonical = service_manifest.MANIFEST_PATH.read_text(encoding="utf-8")
        invalid_sources = (
            canonical.replace("schema_version = 1", "schema_version = true"),
            canonical.replace('id = "postgresql"', 'id = "PostgreSQL"'),
            canonical.replace('version = "3.0.0"', 'version = "03.0.0"'),
            canonical.replace('interface = "shimpz.postgresql/v1"', 'interface = "postgresql/v1"'),
            canonical.replace("port = 7072", "port = 0"),
            canonical.replace('health_path = "/healthz"', 'health_path = "healthz"'),
            canonical.replace('metadata_path = "/v1/service"', 'metadata_path = "/healthz"'),
            canonical.replace(
                'operations = [\n  "team.provision",\n  "team.finalize",\n  "team.drop",\n]',
                "operations = []",
            ),
            canonical.replace('  "team.provision",', "  7,"),
        )
        for index, source in enumerate(invalid_sources):
            path = self.root / f"manifest-{index}.toml"
            path.write_text(source, encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(service_manifest.ManifestError):
                service_manifest.load(path)
        with self.assertRaisesRegex(service_manifest.ManifestError, "cannot read"):
            service_manifest.load(self.root / "missing.toml")

    def test_principal_store_rejects_corruption_and_commit_failures(self) -> None:
        corrupt_records: tuple[object, ...] = (
            [],
            {"digest": []},
            {"digest": {"team_id": 1, "database": "proj_alpha", "state": "active"}},
            {"digest": {"team_id": "alpha", "database": "invalid", "state": "active"}},
            {"digest": {"team_id": "alpha", "database": "proj_alpha"}},
            {"digest": {"team_id": "alpha", "database": "proj_alpha", "state": ["active"]}},
            {"digest": {"team_id": "alpha", "database": "proj_alpha", "state": "unknown"}},
            {
                "one": {"team_id": "alpha", "database": "proj_alpha", "state": "active"},
                "two": {"team_id": "beta", "database": "proj_alpha", "state": "active"},
            },
        )
        for index, record in enumerate(corrupt_records):
            principal_store.STATE_PATH.write_text(json.dumps(record), encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(principal_store.PrincipalStoreError):
                principal_store._read()
        principal_store.STATE_PATH.write_text("{", encoding="utf-8")
        with self.assertRaisesRegex(principal_store.PrincipalStoreError, "could not be read"):
            principal_store._read()

        blocked_parent = self.root / "blocked"
        blocked_parent.write_text("file", encoding="utf-8")
        principal_store.STATE_PATH = blocked_parent / "principals.json"
        with self.assertRaisesRegex(principal_store.PrincipalStoreError, "could not be committed"):
            principal_store._write({})

    def test_principal_store_commit_is_fsynced_before_and_after_its_atomic_replace(self) -> None:
        events: list[tuple[str, object]] = []
        real_fsync, real_replace = os.fsync, Path.replace

        def fsync(descriptor: int) -> None:
            events.append(("fsync", Path(f"/proc/self/fd/{descriptor}").readlink()))
            real_fsync(descriptor)

        def replace(source: Path, destination: Path) -> Path:
            events.append(("replace", source))
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(source.name, principal_store.STATE_PATH.with_suffix(".tmp").name)
            return real_replace(source, destination)

        with (
            mock.patch.object(principal_store.os, "fsync", side_effect=fsync),
            mock.patch.object(Path, "replace", autospec=True, side_effect=replace),
        ):
            principal_store._write({})

        temporary = events[1][1]
        self.assertEqual(
            events,
            [("fsync", temporary), ("replace", temporary), ("fsync", principal_store.STATE_PATH.parent)],
        )
        self.assertEqual(json.loads(principal_store.STATE_PATH.read_text(encoding="utf-8")), {})
        self.assertEqual(principal_store.STATE_PATH.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["principals.json"])

        with (
            mock.patch.object(principal_store.os, "fsync", side_effect=OSError("disk")),
            self.assertRaisesRegex(principal_store.PrincipalStoreError, "could not be committed"),
        ):
            principal_store._write({"unsynced": {}})
        self.assertEqual(json.loads(principal_store.STATE_PATH.read_text(encoding="utf-8")), {})
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["principals.json"])

    def test_principal_store_rejects_duplicate_scopes_and_active_finalization(self) -> None:
        data = {
            "one": {"team_id": "alpha", "database": "proj_alpha", "state": "active"},
            "two": {"team_id": "alpha", "database": "proj_alpha_two", "state": "pending"},
        }
        principal_store.STATE_PATH.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(principal_store.PrincipalStoreError, "duplicate Team identities"):
            principal_store.register("alpha", "a" * 64, "proj_alpha")
        with self.assertRaisesRegex(principal_store.PrincipalStoreError, "duplicate Team identities"):
            principal_store.provision_state("alpha", "proj_alpha")

        principal_store.STATE_PATH.unlink()
        self.assertIsNone(principal_store.provision_state("missing", "proj_missing"))
        principal_store.record_pending("alpha", "a" * 64, "proj_alpha")
        with self.assertRaisesRegex(principal_store.PrincipalError, "dropped before finalization"):
            principal_store.finalize("alpha")
        principal_store.register("alpha", "a" * 64, "proj_alpha")
        with self.assertRaisesRegex(principal_store.PrincipalError, "dropped before finalization"):
            principal_store.finalize("alpha")
        with self.assertRaisesRegex(principal_store.PrincipalError, "scope mismatch"):
            principal_store.retire("b" * 64, "alpha")

        for invalid_team_id in (None, "UPPERCASE", "a" * 41):
            with self.subTest(invalid_team_id=invalid_team_id), self.assertRaises(validate.ValidationError):
                validate.validate_team_id(invalid_team_id)

    def test_postgresql_client_import_guards_password_sources(self) -> None:
        module = POSTGRESQL / "postgresql_client.py"
        with (
            mock.patch.dict(os.environ, {"SHIMPZ_POSTGRESQL_DSN": "postgresql://user:secret@postgres/db"}),
            self.assertRaisesRegex(RuntimeError, "must not contain a password"),
        ):
            runpy.run_path(str(module), run_name="postgresql_client_password_dsn")

        symlink = self.root / "password-link"
        symlink.symlink_to(PASSWORD_FILE)
        environment = {
            "SHIMPZ_POSTGRESQL_DSN": "postgresql://user@postgres/db",
            "SHIMPZ_POSTGRESQL_PASSWORD_FILE": str(symlink),
        }
        with mock.patch.dict(os.environ, environment), self.assertRaisesRegex(RuntimeError, "not a regular file"):
            runpy.run_path(str(module), run_name="postgresql_client_password_symlink")

    def test_postgresql_client_success_and_existence_checks(self) -> None:
        completed = mock.Mock(returncode=0, stdout="result", stderr="")
        with mock.patch.object(postgresql_client.subprocess, "run", return_value=completed):
            self.assertEqual(postgresql_client._run(["psql"]), "result")
        self.assertEqual(
            postgresql_client.ProvisionResult("url", created=True).public(),
            {"database_url": "url", "created": True},
        )
        with mock.patch.object(postgresql_client, "_psql", side_effect=("1\n", "0\n")):
            self.assertTrue(postgresql_client._role_exists("role"))
            self.assertFalse(postgresql_client._db_exists("database"))

    def test_postgresql_client_provisions_new_and_reuses_owned_resources(self) -> None:
        for existing in (False, True):
            with (
                self.subTest(existing=existing),
                mock.patch.object(postgresql_client, "_psql", return_value="") as psql,
                mock.patch.object(postgresql_client, "_run", return_value="") as run,
            ):
                result = postgresql_client.create_db_and_role("team_alpha", existing=existing)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(result.created, not existing)
            self.assertEqual(any(command[0] == "createdb" for command in commands), not existing)
            self.assertIn("ALTER ROLE" if existing else "CREATE ROLE", psql.call_args_list[0].args[1])

        with (
            mock.patch.object(postgresql_client, "_role_exists", return_value=False),
            mock.patch.object(postgresql_client, "_db_exists", return_value=False),
            self.assertRaisesRegex(postgresql_client.PostgreSQLError, "are missing"),
        ):
            postgresql_client.require_resources("team_alpha", registered=True)
        for exists in (False, True):
            with (
                self.subTest(registered_and_exists=exists),
                mock.patch.object(postgresql_client, "_role_exists", return_value=exists),
                mock.patch.object(postgresql_client, "_db_exists", return_value=exists),
            ):
                postgresql_client.require_resources("team_alpha", registered=exists)

    def test_postgresql_client_drop_removes_database_then_role(self) -> None:
        with _FakePostgres(roles={"proj_team"}, databases={"proj_team"}).serving() as postgres:
            self.assertEqual(postgresql_client.drop_db_and_role("team"), {"dropped": "proj_team"})
        self.assertEqual((postgres.roles, postgres.databases), (set(), set()))
        self.assertEqual(postgres.commands, ["dropdb", "DROP ROLE IF EXISTS"])

    def test_failed_creation_keeps_its_pending_resources_for_retry(self) -> None:
        # A failed or timed-out command may still have committed; the durable pending intent owns whatever it left.
        for failed, left_behind in (
            ("CREATE ROLE", ({_ALPHA_DATABASE}, set())),
            ("createdb", ({_ALPHA_DATABASE}, {_ALPHA_DATABASE})),
            ("GRANT ALL ON DATABASE", ({_ALPHA_DATABASE}, {_ALPHA_DATABASE})),
        ):
            principal_store.STATE_PATH.unlink(missing_ok=True)
            with self.subTest(failed=failed), _FakePostgres().serving() as postgres:
                with (
                    mock.patch.object(postgres, "fail_after", failed),
                    self.assertRaisesRegex(postgresql_client.PostgreSQLError, "timed out"),
                ):
                    app._provision_team(_ALPHA)
                self.assertEqual((postgres.roles, postgres.databases), left_behind)
                self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.PENDING)

                self.assertTrue(app._provision_team(_ALPHA)["created"])
                self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.ACTIVE)
                self.assertEqual((postgres.roles, postgres.databases), ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}))

    def test_failed_registration_keeps_owned_resources_for_retry(self) -> None:
        # os.fsync order for a new Team: intent contents, intent directory, registration contents, registration
        # directory. Failing the registration's contents fsync precedes its replace; failing its directory fsync
        # follows the replace, so `active` ownership has already landed when the failure surfaces.
        for boundary, fsyncs, committed, retry_creates in (
            ("before replace", [None, None, OSError("disk")], principal_store.PENDING, True),
            ("after replace", [None, None, None, OSError("disk")], principal_store.ACTIVE, False),
        ):
            principal_store.STATE_PATH.unlink(missing_ok=True)
            with self.subTest(boundary=boundary), _FakePostgres().serving() as postgres:
                with (
                    mock.patch.object(principal_store.os, "fsync", side_effect=fsyncs),
                    self.assertRaisesRegex(principal_store.PrincipalStoreError, "could not be committed"),
                ):
                    app._provision_team(_ALPHA)
                self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), committed)
                self.assertEqual((postgres.roles, postgres.databases), ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}))
                self.assertNotIn("dropdb", postgres.commands)

                postgres.commands.clear()
                self.assertEqual(app._provision_team(_ALPHA)["created"], retry_creates)
                self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.ACTIVE)
                self.assertEqual((postgres.roles, postgres.databases), ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}))
                self.assertEqual("dropdb" in postgres.commands, retry_creates)

    def test_provisioning_interrupted_by_process_death_is_reconciled_by_retry_or_drop(self) -> None:
        crashes = {
            "after the intent, before DDL": lambda _fake: mock.patch.object(
                postgresql_client, "create_db_and_role", side_effect=_Crash
            ),
            "between the role and the database": lambda fake: mock.patch.object(fake, "crash_on_createdb", True),
            "after DDL, before registration": lambda _fake: mock.patch.object(
                principal_store, "register", side_effect=_Crash
            ),
        }
        left_behind = {
            "after the intent, before DDL": (set(), set()),
            "between the role and the database": ({_ALPHA_DATABASE}, set()),
            "after DDL, before registration": ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}),
        }
        for crash, interrupt in crashes.items():
            for recovery in ("retry", "drop"):
                principal_store.STATE_PATH.unlink(missing_ok=True)
                with self.subTest(crash=crash, recovery=recovery), _FakePostgres().serving() as postgres:
                    with interrupt(postgres), self.assertRaises(_Crash):
                        app._provision_team(_ALPHA)
                    self.assertEqual((postgres.roles, postgres.databases), left_behind[crash])
                    self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.PENDING)

                    if recovery == "retry":
                        self.assertTrue(app._provision_team(_ALPHA)["created"])
                        self.assertEqual(
                            principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.ACTIVE
                        )
                        expected = ({_ALPHA_DATABASE}, {_ALPHA_DATABASE})
                    else:
                        self.assertEqual(app._drop_team({"team_id": "alpha"}, "a" * 64), {"dropped": [_ALPHA_DATABASE]})
                        self.assertEqual(app._finalize_team({"team_id": "alpha"}), {"finalized": True})
                        self.assertIsNone(principal_store.provision_state("alpha", _ALPHA_DATABASE))
                        expected = (set(), set())
                    self.assertEqual((postgres.roles, postgres.databases), expected)

    def test_unrecorded_existing_resources_stay_refused_and_record_no_intent(self) -> None:
        for roles, databases, refusal in (
            ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}, "without registry ownership"),
            ({_ALPHA_DATABASE}, set(), "are incomplete"),
        ):
            with (
                self.subTest(refusal=refusal),
                _FakePostgres(roles=roles, databases=databases).serving() as postgres,
                self.assertRaisesRegex(postgresql_client.PostgreSQLError, refusal),
            ):
                app._provision_team(_ALPHA)
            self.assertEqual((postgres.roles, postgres.databases, postgres.commands), (roles, databases, []))
            self.assertFalse(principal_store.STATE_PATH.exists())

    def test_provisioning_failed_before_its_intent_is_cleared_only_by_the_absence_proof(self) -> None:
        failures = {
            "registry commit": mock.patch.object(
                principal_store, "record_pending", side_effect=principal_store.PrincipalStoreError("commit")
            ),
            "catalog check": mock.patch.object(
                postgresql_client, "require_resources", side_effect=postgresql_client.PostgreSQLError("down")
            ),
        }
        for failure, interrupt in failures.items():
            principal_store.STATE_PATH.unlink(missing_ok=True)
            with self.subTest(failure=failure), _FakePostgres().serving() as postgres:
                with (
                    interrupt,
                    self.assertRaises((principal_store.PrincipalStoreError, postgresql_client.PostgreSQLError)),
                ):
                    app._provision_team(_ALPHA)
                self.assertIsNone(principal_store.provision_state("alpha", _ALPHA_DATABASE))
                with self.assertRaisesRegex(principal_store.PrincipalError, "unknown principal"):
                    app._drop_team({"team_id": "alpha"}, "a" * 64)

                self.assertEqual(app._confirm_team_absent(_ALPHA_ABSENT), {"dropped": []})
                self.assertEqual(app._confirm_team_absent(_ALPHA_ABSENT), {"dropped": []})
                self.assertEqual(app._finalize_team({"team_id": "alpha"}), {"finalized": True})
                self.assertEqual(postgres.commands, [])
                self.assertEqual((postgres.roles, postgres.databases), (set(), set()))

                self.assertTrue(app._provision_team(_ALPHA)["created"])
                self.assertEqual(principal_store.provision_state("alpha", _ALPHA_DATABASE), principal_store.ACTIVE)

    def test_a_delayed_provision_can_never_land_once_absence_is_proven(self) -> None:
        now = [1000.0]
        delayed = {**_ALPHA, "not_after": 1030}
        proof = {"team_id": "alpha", "not_after": 1030}
        with mock.patch.object(app.time, "time", side_effect=lambda: now[0]), _FakePostgres().serving() as postgres:
            now[0] = 1030.0
            with self.assertRaisesRegex(app.ApiError, "may still be in flight"):
                app._confirm_team_absent(proof)
            now[0] = 1031.0
            self.assertEqual(app._confirm_team_absent(proof), {"dropped": []})

            # Window 1: the delayed request arrives after the proof but before finalization.
            with self.assertRaisesRegex(app.ApiError, "expired") as expired:
                app._provision_team(delayed)
            self.assertEqual(expired.exception.status, HTTPStatus.CONFLICT)
            self.assertIsNone(principal_store.provision_state("alpha", _ALPHA_DATABASE))
            self.assertEqual(app._finalize_team({"team_id": "alpha"}), {"finalized": True})

            # Window 2: it arrives after finalization, even across a wall-clock step backward.
            for current in (1032.0, 1000.0):
                now[0] = current
                with self.subTest(now=current), self.assertRaisesRegex(app.ApiError, "expired"):
                    app._provision_team(delayed)
            self.assertIsNone(principal_store.provision_state("alpha", _ALPHA_DATABASE))
            self.assertEqual((postgres.roles, postgres.databases, postgres.commands), (set(), set(), []))
            self.assertFalse(principal_store.STATE_PATH.exists())

            # A request admitted before its fence is registered first, so the later proof refuses the Team.
            now[0] = 1100.0
            self.assertTrue(app._provision_team({**_ALPHA, "not_after": 1100})["created"])
            with self.assertRaisesRegex(principal_store.PrincipalError, "only that principal may drop"):
                app._confirm_team_absent({"team_id": "alpha", "not_after": 1100 - 1})

    def test_absence_proof_refuses_any_registered_or_existing_team_resource_without_ddl(self) -> None:
        for state in (principal_store.PENDING, principal_store.ACTIVE, principal_store.RETIRED):
            principal_store.STATE_PATH.unlink(missing_ok=True)
            principal_store.record_pending("alpha", "a" * 64, _ALPHA_DATABASE)
            if state != principal_store.PENDING:
                principal_store.register("alpha", "a" * 64, _ALPHA_DATABASE)
            if state == principal_store.RETIRED:
                principal_store.retire("a" * 64, "alpha")
            with (
                self.subTest(state=state),
                _FakePostgres().serving() as postgres,
                self.assertRaisesRegex(principal_store.PrincipalError, "only that principal may drop"),
            ):
                app._confirm_team_absent(_ALPHA_ABSENT)
            self.assertEqual(postgres.commands, [])

        principal_store.STATE_PATH.unlink()
        for roles, databases, refusal in (
            ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}, "without registry ownership"),
            ({_ALPHA_DATABASE}, set(), "are incomplete"),
            (set(), {_ALPHA_DATABASE}, "are incomplete"),
        ):
            with (
                self.subTest(roles=roles, databases=databases),
                _FakePostgres(roles=roles, databases=databases).serving() as postgres,
                self.assertRaisesRegex(postgresql_client.PostgreSQLError, refusal),
            ):
                app._confirm_team_absent(_ALPHA_ABSENT)
            self.assertEqual((postgres.roles, postgres.databases, postgres.commands), (roles, databases, []))

    def test_active_team_reprovision_rotates_without_reclaiming_its_database(self) -> None:
        with _FakePostgres().serving() as postgres:
            self.assertTrue(app._provision_team(_ALPHA)["created"])
            postgres.commands.clear()
            rotated = {**_ALPHA, "principal_token": "b" * 64}
            self.assertFalse(app._provision_team(rotated)["created"])
        self.assertEqual((postgres.roles, postgres.databases), ({_ALPHA_DATABASE}, {_ALPHA_DATABASE}))
        self.assertNotIn("dropdb", postgres.commands)
        self.assertNotIn("DROP ROLE IF EXISTS", postgres.commands)
        self.assertEqual(principal_store.database("b" * 64, "alpha"), _ALPHA_DATABASE)
        with self.assertRaises(principal_store.PrincipalError):
            principal_store.database("a" * 64, "alpha")

    def test_app_classifies_every_expected_failure_without_leaking(self) -> None:
        failures = (
            (app.ApiError(HTTPStatus.CONFLICT, "conflict"), HTTPStatus.CONFLICT, "conflict"),
            (validate.ValidationError("invalid"), HTTPStatus.BAD_REQUEST, "invalid"),
            (principal_store.PrincipalError("secret"), HTTPStatus.FORBIDDEN, "principal scope denied"),
            (
                principal_store.PrincipalStoreError("secret"),
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "principal registry unavailable",
            ),
            (postgresql_client.PostgreSQLError("secret"), HTTPStatus.BAD_GATEWAY, "database operation failed"),
            (RuntimeError("secret"), HTTPStatus.INTERNAL_SERVER_ERROR, "internal service error"),
        )
        for error, status, public in failures:
            with self.subTest(error=type(error).__name__):
                failure = app._http_failure(error)
                self.assertIsNotNone(failure)
                self.assertEqual((failure.status, failure.public_message), (status, public))
        self.assertIsNone(app._http_failure(KeyError("unclassified")))

    def test_app_routes_authorized_mutations_and_refuses_wrong_provisioner(self) -> None:
        with self._server() as server, mock.patch.object(audit, "log", return_value="a" * 32):
            status, payload = self._request(
                server,
                "POST",
                "/v1/teams/provision",
                {"team_id": "alpha", "principal_token": "a" * 64},
                bearer="wrong",
            )
            self.assertEqual((status, payload["error"]), (HTTPStatus.FORBIDDEN, "provisioner bearer required"))

            operations = (
                ("team.provision", "/v1/teams/provision", "_provision_team", {"created": True}),
                ("team.finalize", "/v1/teams/finalize", "_finalize_team", {"finalized": True}),
                ("team.drop", "/v1/teams/drop", "_drop_team", {"dropped": ["proj_alpha"]}),
            )
            for operation, path, target, result in operations:
                bearer = app._provisioner_token if operation != "team.drop" else "a" * 64
                with self.subTest(operation=operation), mock.patch.object(app, target, return_value=result):
                    status, payload = self._request(server, "POST", path, {"team_id": "alpha"}, bearer=bearer)
                self.assertEqual(status, HTTPStatus.OK)
                self.assertEqual(payload["trace_id"], "a" * 32)

            with (
                mock.patch.object(app, "_drop_team") as drop,
                mock.patch.object(app, "_confirm_team_absent", return_value={"dropped": []}) as absent,
            ):
                status, payload = self._request(
                    server, "POST", "/v1/teams/drop", {"team_id": "alpha"}, bearer=app._provisioner_token
                )
            self.assertEqual((status, payload["dropped"]), (HTTPStatus.OK, []))
            drop.assert_not_called()
            absent.assert_called_once_with({"team_id": "alpha"})

    def test_bounded_server_lifecycle_and_script_entrypoint(self) -> None:
        server = app.BoundedThreadingHTTPServer(("127.0.0.1", 0), app.Handler, max_concurrency=1)
        request, peer = socket.socketpair()
        try:
            request.settimeout(10)
            with mock.patch.object(ThreadingHTTPServer, "get_request", return_value=(request, ("127.0.0.1", 1))):
                accepted, _address = server.get_request()
            self.assertEqual(accepted.gettimeout(), app.HTTP_CONNECTION_TIMEOUT_SECONDS)

            with (
                mock.patch.object(ThreadingHTTPServer, "process_request", side_effect=RuntimeError("dispatch")),
                self.assertRaisesRegex(RuntimeError, "dispatch"),
            ):
                server.process_request(request, ("127.0.0.1", 1))
            self.assertTrue(server._request_slots.acquire(blocking=False))
            server._request_slots.release()

            self.assertTrue(server._request_slots.acquire(blocking=False))
            with mock.patch.object(ThreadingHTTPServer, "process_request_thread", return_value=None):
                server.process_request_thread(request, ("127.0.0.1", 1))
            self.assertTrue(server._request_slots.acquire(blocking=False))
            server._request_slots.release()
        finally:
            request.close()
            peer.close()
            server.server_close()

        with (
            mock.patch.object(ThreadingHTTPServer, "__init__", return_value=None),
            mock.patch.object(ThreadingHTTPServer, "serve_forever", return_value=None) as serve,
        ):
            runpy.run_path(str(POSTGRESQL / "app.py"), run_name="__main__")
        serve.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
