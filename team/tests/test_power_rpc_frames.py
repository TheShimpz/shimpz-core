"""Adversarial frame contracts for hosted and local Assistant Power RPC."""

from __future__ import annotations

import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import brain_runtime_client
import manifests
import power_execution
import power_journal

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import local_app
from hosted_app_fixture import hosted_assistants, runtime_state
from local_support import assistant_rpc as local_assistant_rpc


def _frame(stream_id: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxL", stream_id, len(payload)) + payload


@contextmanager
def _socket_bytes(payload: bytes, *, pieces: tuple[int, ...] = ()):
    reader, writer = socket.socketpair()

    def send() -> None:
        offset = 0
        for size in pieces:
            writer.sendall(payload[offset : offset + size])
            offset += size
            time.sleep(0.005)
        writer.sendall(payload[offset:])
        writer.shutdown(socket.SHUT_WR)

    sender = threading.Thread(target=send, daemon=True)
    sender.start()
    try:
        yield reader
    finally:
        sender.join(timeout=1)
        reader.close()
        writer.close()


class PowerRpcFrameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = object.__new__(local_app.LocalController)
        self.local._wire_collaborators()

    def test_split_stdout_and_stderr_frames_are_read_exactly(self) -> None:
        payload = _frame(1, b'{"ok":') + _frame(2, b"warning") + _frame(1, b"true}")
        with _socket_bytes(payload, pieces=(1, 2, 5, 3, 7)) as hosted_socket:
            stdout, stderr = hosted_assistants._read_rpc_frames(hosted_socket, time.monotonic() + 1)
        with _socket_bytes(payload, pieces=(4, 1, 6, 2)) as local_socket:
            local_stdout, local_stderr = self.local.assistant_lifecycle._read_rpc_frames(
                local_socket, time.monotonic() + 1
            )

        self.assertEqual(stdout, b'{"ok":true}')
        self.assertEqual(stderr, b"warning")
        self.assertEqual(local_stdout, stdout)
        self.assertEqual(local_stderr, stderr)

    def test_rpc_response_accepts_only_a_direct_spec_v1_object(self) -> None:
        self.assertEqual(
            power_execution.decode_rpc_response(b'{"ok":true}'),
            {"ok": True},
        )
        for invalid in (
            b'{"ok":true,"ok":false}',
            b'{"value":NaN}',
            b"[]",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(power_execution.RpcExchangeError):
                power_execution.decode_rpc_response(invalid)

    def test_rpc_failure_kinds_share_one_http_status_table(self) -> None:
        self.assertEqual(
            {
                kind: power_execution.rpc_failure_status(kind)
                for kind in ("timeout", "ambiguous", "invalid-result", "failed")
            },
            {
                "timeout": HTTPStatus.GATEWAY_TIMEOUT,
                "ambiguous": HTTPStatus.BAD_GATEWAY,
                "invalid-result": HTTPStatus.BAD_GATEWAY,
                "failed": HTTPStatus.BAD_GATEWAY,
            },
        )
        with self.assertRaisesRegex(AssertionError, "unknown RPC failure"):
            power_execution.rpc_failure_status("unknown")

    def test_local_readiness_requires_only_a_running_prebuilt_container(self) -> None:
        container = SimpleNamespace(status="running", reload=lambda: None)
        self.local.assistant_lifecycle._rpc = mock.Mock()

        self.local.assistant_lifecycle._wait_ready(container, object())

        self.local.assistant_lifecycle._rpc.assert_not_called()

    def test_private_generation_helpers_apply_one_power_contract(self) -> None:
        powers = {
            "lookup": SimpleNamespace(accounts=("cloud",)),
        }
        account_metadata = mock.Mock(
            return_value=(SimpleNamespace(id="cloud", status="connected", generation=5),),
        )

        self.assertEqual(
            power_execution.account_generations(
                powers,
                {"cloud": "declaration"},
                "lookup",
                account_metadata,
            ),
            (("cloud", 5),),
        )
        account_metadata.assert_called_once_with({"cloud": "declaration"})
        with self.assertRaisesRegex(power_journal.PowerJournalConflictError, "account contract"):
            power_execution.account_generations(powers, {}, "lookup", account_metadata)

    def test_rpc_result_projection_rejects_private_and_invalid_outputs(self) -> None:
        projected = power_execution.project_rpc_result(
            {"ok": True},
            {"cloud": {"access_token": "private"}},
            lambda value: value,
        )
        self.assertEqual(projected, {"ok": True})

        with self.assertRaises(power_execution.RpcSecretExposureError):
            power_execution.project_rpc_result(
                {"echo": "private"},
                {"cloud": {"access_token": "private"}},
                lambda value: value,
            )
        with self.assertRaises(power_execution.RpcInvalidResultError):
            power_execution.project_rpc_result(
                {"invalid": True},
                {},
                lambda _value: (_ for _ in ()).throw(ValueError("invalid")),
            )

    def test_malformed_frames_fail_closed_in_both_readers(self) -> None:
        oversized = struct.pack(
            ">BxxxL",
            1,
            max(hosted_assistants.MAX_ASSISTANT_RPC_OUTPUT_BYTES, local_assistant_rpc.MAX_RESPONSE_BYTES) + 2,
        )
        cases = (
            b"\x01\x00\x00",
            _frame(1, b"payload")[:-2],
            oversized,
            b"garbage!",
        )

        for payload in cases:
            with self.subTest(payload=payload):
                with _socket_bytes(payload) as hosted_socket, self.assertRaises(ValueError):
                    hosted_assistants._read_rpc_frames(hosted_socket, time.monotonic() + 1)
                with _socket_bytes(payload) as local_socket, self.assertRaises(ValueError):
                    self.local.assistant_lifecycle._read_rpc_frames(local_socket, time.monotonic() + 1)

    def test_clean_eof_is_the_only_empty_success(self) -> None:
        with _socket_bytes(b"") as hosted_socket:
            self.assertEqual(hosted_assistants._read_rpc_frames(hosted_socket, time.monotonic() + 1), (b"", b""))
        with _socket_bytes(b"") as local_socket:
            self.assertEqual(
                self.local.assistant_lifecycle._read_rpc_frames(local_socket, time.monotonic() + 1),
                (b"", b""),
            )

    def test_rpc_exchange_bounds_stdin_write_by_deadline(self) -> None:
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close)
        self.addCleanup(writer.close)
        for current in (reader, writer):
            current.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
            current.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        writer.settimeout(3.0)
        stream = SimpleNamespace(_sock=writer, close=lambda: None)
        api = SimpleNamespace(
            exec_create=lambda *_args, **_kwargs: {"Id": "e"},
            exec_start=lambda *_args, **_kwargs: stream,
            exec_inspect=lambda *_args, **_kwargs: {"ExitCode": 0},
        )
        strategy = power_execution.RpcExchangeStrategy(
            api=api,
            user="10001:10001",
            workdir=manifests.CONTAINER_TMP,
            timeout=0.5,
            maximum=power_execution.MAX_RPC_REQUEST_BYTES,
            transport_errors=(),
            fail_stop=lambda: None,
            cancelled=lambda _error: None,
            close_stream=lambda _stream: None,
        )

        start = time.monotonic()
        with self.assertRaises(power_execution.RpcExchangeError) as caught:
            power_execution.rpc_exchange(
                "cid",
                ["/bin/true"],
                b"x" * (512 * 1024),
                strategy,
            )
        elapsed = time.monotonic() - start

        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(elapsed, 1.5)

    def test_both_power_batch_adapters_reject_the_same_generation_drift(self) -> None:
        request = brain_runtime_client.PowerRequest("interrupt-1", "assistant", "lookup", {"query": "safe"})
        generation = [1]
        execute = mock.Mock(return_value={"ok": True})
        image = "example.invalid/assistant@sha256:" + "a" * 64
        bindings = (
            (
                SimpleNamespace(container=SimpleNamespace(id="container-1"), image=image),
                lambda item: (item.container.id, item.image),
            ),
            (
                SimpleNamespace(container_id="container-1", spec=SimpleNamespace(image=image)),
                lambda item: (item.container_id, item.spec.image),
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            for index, (binding, identity) in enumerate(bindings):
                with self.subTest(adapter=index):
                    journal = power_journal.PowerJournal(Path(directory) / f"journal-{index}.sqlite3")
                    self.addCleanup(journal.close)
                    batch = power_execution.PowerBatch(
                        journal,
                        "generation-1",
                        "thread-1",
                        {"assistant": binding},
                        power_execution.PowerBatchStrategy(
                            identity,
                            execute,
                            lambda _request: None,
                            lambda _request: (("secret", generation[0]),),
                        ),
                    )
                    generation[0] = 1
                    batch.prepare((request,))
                    generation[0] = 2
                    with self.assertRaisesRegex(
                        power_journal.PowerJournalConflictError,
                        "Power credential generation changed",
                    ):
                        batch.invoke(request)
        execute.assert_not_called()

    def test_power_resolution_failures_have_identical_statuses(self) -> None:
        local_spec = SimpleNamespace(assistant_id="assistant", name="Assistant", powers={}, accounts={})

        hosted_active = SimpleNamespace(
            assistant_id="assistant",
            contract=SimpleNamespace(powers={}, accounts={}),
        )
        self.local.assistant_accounts = object()
        with self.assertRaises(runtime_state.ApiError) as hosted_account:
            hosted_assistants._resolve_power_accounts("team_1", hosted_active, "missing")
        with self.assertRaises(local_app.ApiProblem) as local_account:
            self.local.chat_turn_service._resolve_power_accounts("team_1", local_spec, "missing")
        self.assertEqual(
            hosted_account.exception.status,
            local_account.exception.status,
            power_execution.ACCOUNT_PRECONDITION_STATUS,
        )

    def test_hosted_exchange_fail_stops_on_malformed_frame(self) -> None:
        with _socket_bytes(b"truncated") as raw_socket:
            stream = SimpleNamespace(_sock=raw_socket, close=lambda: None)
            create = mock.Mock(return_value={"Id": "exec-1"})
            api = SimpleNamespace(
                exec_create=create,
                exec_start=lambda *_args, **_kwargs: stream,
            )
            fail_stop = mock.Mock()
            container = SimpleNamespace(id="assistant-container")
            with (
                mock.patch.object(runtime_state, "_docker", SimpleNamespace(api=api)),
                mock.patch.object(hosted_assistants, "_fail_stop_power", fail_stop),
                mock.patch.object(power_execution, "encode_rpc_invocation", return_value=b"request"),
                self.assertRaises(runtime_state.ApiError) as caught,
            ):
                hosted_assistants._assistant_rpc_exchange(
                    hosted_assistants.AssistantRpcRequest(
                        team_id="team_1",
                        container=container,
                        power_id="test",
                        payload={"input": {}, "accounts": {}},
                        token=None,
                    )
                )

        self.assertEqual(caught.exception.status, HTTPStatus.BAD_GATEWAY)
        fail_stop.assert_called_once_with("team_1", container)
        self.assertEqual(create.call_args.args[1], [hosted_assistants.POWER_COMMAND, "test"])
        self.assertEqual(create.call_args.kwargs["workdir"], manifests.CONTAINER_TMP)
        self.assertEqual(create.call_args.kwargs["environment"], {})

    def test_local_exchange_fail_stops_on_malformed_frame(self) -> None:
        with _socket_bytes(b"truncated") as raw_socket:
            stream = SimpleNamespace(_sock=raw_socket, close=lambda: None)
            create = mock.Mock(return_value={"Id": "exec-1"})
            api = SimpleNamespace(
                exec_create=create,
                exec_start=lambda *_args, **_kwargs: stream,
            )
            controller = object.__new__(local_app.LocalController)
            controller.client = SimpleNamespace(api=api)
            controller._wire_collaborators()
            controller.assistant_lifecycle._fail_stop_power = mock.Mock()
            with (
                mock.patch.object(
                    local_assistant_rpc.power_execution,
                    "encode_rpc_invocation",
                    return_value=b"request",
                ),
                self.assertRaises(local_app.ApiProblem) as caught,
            ):
                controller.assistant_lifecycle._rpc(
                    SimpleNamespace(id="assistant-container"),
                    "test",
                    {"input": {}, "accounts": {}},
                )

        self.assertEqual(caught.exception.status, HTTPStatus.BAD_GATEWAY)
        controller.assistant_lifecycle._fail_stop_power.assert_called_once()
        self.assertEqual(create.call_args.args[1], [local_assistant_rpc.POWER_COMMAND, "test"])
        self.assertEqual(create.call_args.kwargs["workdir"], local_assistant_rpc.ASSISTANT_WORKDIR)
        self.assertEqual(create.call_args.kwargs["environment"], {})


if __name__ == "__main__":
    unittest.main()
