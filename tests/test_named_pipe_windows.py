from __future__ import annotations

import ctypes
import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any

import pytest

from ollydbg_mcp.protocol import BridgeError
from ollydbg_mcp.transport import NamedPipeTransport

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows named pipes only")

ResponseParts = list[tuple[float, bytes]]
Responder = Callable[[dict[str, Any]], ResponseParts]


class WindowsPipeServer:
    def __init__(self, responder: Responder) -> None:
        self.pipe_name = rf"\\.\pipe\OllyBridgeTest-{uuid.uuid4()}"
        self.responder = responder
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.request: dict[str, Any] | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self.ready.wait(timeout=5):
            raise AssertionError("named-pipe test server did not start")
        if self.error is not None:
            raise self.error

    def join(self) -> None:
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise AssertionError("named-pipe test server did not stop")
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_BYTE = 0x00000000
        PIPE_READMODE_BYTE = 0x00000000
        PIPE_WAIT = 0x00000000
        ERROR_PIPE_CONNECTED = 535
        ERROR_BROKEN_PIPE = 109
        ERROR_NO_DATA = 232
        ERROR_PIPE_NOT_CONNECTED = 233

        CreateNamedPipeW = kernel32.CreateNamedPipeW
        CreateNamedPipeW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        CreateNamedPipeW.restype = ctypes.c_void_p

        ConnectNamedPipe = kernel32.ConnectNamedPipe
        ConnectNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        ConnectNamedPipe.restype = ctypes.c_int

        ReadFile = kernel32.ReadFile
        ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        ReadFile.restype = ctypes.c_int

        WriteFile = kernel32.WriteFile
        WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        WriteFile.restype = ctypes.c_int

        DisconnectNamedPipe = kernel32.DisconnectNamedPipe
        DisconnectNamedPipe.argtypes = [ctypes.c_void_p]
        DisconnectNamedPipe.restype = ctypes.c_int

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [ctypes.c_void_p]
        CloseHandle.restype = ctypes.c_int

        pipe = CreateNamedPipeW(
            self.pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            65536,
            65536,
            1000,
            None,
        )
        if pipe == INVALID_HANDLE_VALUE:
            self.error = OSError(ctypes.get_last_error(), "CreateNamedPipeW failed")
            self.ready.set()
            return

        self.ready.set()
        try:
            if not ConnectNamedPipe(pipe, None):
                error = ctypes.get_last_error()
                if error != ERROR_PIPE_CONNECTED:
                    raise OSError(error, "ConnectNamedPipe failed")

            buffer = ctypes.create_string_buffer(65536)
            read = ctypes.c_uint32(0)
            if not ReadFile(pipe, buffer, len(buffer), ctypes.byref(read), None):
                raise OSError(ctypes.get_last_error(), "ReadFile failed")
            raw_request = buffer.raw[: read.value].split(b"\n", 1)[0]
            parsed = json.loads(raw_request.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise AssertionError("transport request was not a JSON object")
            self.request = parsed

            for delay_seconds, chunk in self.responder(parsed):
                if delay_seconds:
                    time.sleep(delay_seconds)
                written = ctypes.c_uint32(0)
                data = ctypes.create_string_buffer(chunk)
                if not WriteFile(pipe, data, len(chunk), ctypes.byref(written), None):
                    error = ctypes.get_last_error()
                    if error in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                        break
                    raise OSError(error, "WriteFile failed")
                if written.value != len(chunk):
                    raise AssertionError(
                        f"incomplete server write: {written.value}/{len(chunk)}"
                    )

            closed_probe = ctypes.create_string_buffer(1)
            closed_read = ctypes.c_uint32(0)
            if not ReadFile(
                pipe,
                closed_probe,
                len(closed_probe),
                ctypes.byref(closed_read),
                None,
            ):
                error = ctypes.get_last_error()
                if error not in (
                    ERROR_BROKEN_PIPE,
                    ERROR_NO_DATA,
                    ERROR_PIPE_NOT_CONNECTED,
                ):
                    raise OSError(error, "waiting for client close failed")
        except BaseException as exc:  # surfaced in the test thread
            self.error = exc
        finally:
            DisconnectNamedPipe(pipe)
            CloseHandle(pipe)


class WindowsPipeStallServer:
    def __init__(self, hold_seconds: float = 0.25) -> None:
        self.pipe_name = rf"\\.\pipe\OllyBridgeStall-{uuid.uuid4()}"
        self.hold_seconds = hold_seconds
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self.ready.wait(timeout=5):
            raise AssertionError("stalled named-pipe server did not start")
        if self.error is not None:
            raise self.error

    def join(self) -> None:
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise AssertionError("stalled named-pipe server did not stop")
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        invalid_handle = ctypes.c_void_p(-1).value
        error_pipe_connected = 535

        create_named_pipe = kernel32.CreateNamedPipeW
        create_named_pipe.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_named_pipe.restype = ctypes.c_void_p

        connect_named_pipe = kernel32.ConnectNamedPipe
        connect_named_pipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        connect_named_pipe.restype = ctypes.c_int

        disconnect_named_pipe = kernel32.DisconnectNamedPipe
        disconnect_named_pipe.argtypes = [ctypes.c_void_p]
        disconnect_named_pipe.restype = ctypes.c_int

        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int

        pipe = create_named_pipe(
            self.pipe_name,
            0x00000003,
            0x00000000,
            1,
            4096,
            4096,
            1000,
            None,
        )
        if pipe == invalid_handle:
            self.error = OSError(ctypes.get_last_error(), "CreateNamedPipeW failed")
            self.ready.set()
            return

        self.ready.set()
        try:
            if not connect_named_pipe(pipe, None):
                error = ctypes.get_last_error()
                if error != error_pipe_connected:
                    raise OSError(error, "ConnectNamedPipe failed")
            time.sleep(self.hold_seconds)
        except BaseException as exc:
            self.error = exc
        finally:
            disconnect_named_pipe(pipe)
            close_handle(pipe)


def make_transport(server: WindowsPipeServer, **overrides: Any) -> NamedPipeTransport:
    return NamedPipeTransport(
        pipe_name=server.pipe_name,
        timeout_seconds=overrides.pop("timeout_seconds", 1.0),
        retries=overrides.pop("retries", 1),
        retry_delay_seconds=overrides.pop("retry_delay_seconds", 0.01),
        **overrides,
    )


def test_real_named_pipe_round_trip_handles_fragmented_response() -> None:
    payload = {"ok": True, "value": 42}
    encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    server = WindowsPipeServer(
        lambda request: [(0.0, encoded[:7]), (0.02, encoded[7:])]
    )
    server.start()

    result = make_transport(server).request({"command": "status", "token": "abc"})
    server.join()

    assert result == payload
    assert server.request == {"command": "status", "token": "abc"}


def test_real_named_pipe_rejects_invalid_json_response() -> None:
    server = WindowsPipeServer(lambda request: [(0.0, b"{not-json}\n")])
    server.start()

    with pytest.raises(BridgeError, match="pipe returned invalid JSON"):
        make_transport(server).request({"command": "status"})
    server.join()


def test_real_named_pipe_rejects_invalid_utf8_response() -> None:
    server = WindowsPipeServer(lambda request: [(0.0, b'{"ok":true,"value":"\xff"}\n')])
    server.start()

    with pytest.raises(BridgeError, match="invalid UTF-8"):
        make_transport(server).request({"command": "status"})
    server.join()


def test_real_named_pipe_rejects_non_object_response() -> None:
    server = WindowsPipeServer(lambda request: [(0.0, b"[1,2,3]\n")])
    server.start()

    with pytest.raises(BridgeError, match="unexpected payload"):
        make_transport(server).request({"command": "status"})
    server.join()


def test_real_named_pipe_surfaces_bridge_error_metadata() -> None:
    response = (
        b'{"ok":false,"error":"Go failed","debug_status":2,'
        b'"cpu_thread_id":"0x00000001","last_pause_reasonex":16}\n'
    )
    server = WindowsPipeServer(lambda request: [(0.0, response)])
    server.start()

    with pytest.raises(BridgeError) as raised:
        make_transport(server).request({"command": "run"})
    server.join()

    message = str(raised.value)
    assert "Go failed" in message
    assert "debug_status=2" in message
    assert "cpu_thread_id=0x00000001" in message
    assert "last_pause_reasonex=16" in message


def test_real_named_pipe_enforces_response_size_limit() -> None:
    oversized = b'{"ok":true,"padding":"' + (b"x" * 256) + b'"}\n'
    server = WindowsPipeServer(lambda request: [(0.0, oversized)])
    server.start()

    with pytest.raises(BridgeError, match="pipe response exceeded 64 bytes"):
        make_transport(server, max_response_bytes=64).request({"command": "status"})
    server.join()


def test_real_named_pipe_enforces_response_timeout() -> None:
    server = WindowsPipeServer(lambda request: [(0.2, b'{"ok":true}\n')])
    server.start()

    with pytest.raises(BridgeError, match="timed out"):
        make_transport(server, timeout_seconds=0.05).request({"command": "status"})
    server.join()


def test_real_named_pipe_write_is_cancelled_at_deadline() -> None:
    server = WindowsPipeStallServer()
    server.start()
    transport = NamedPipeTransport(
        pipe_name=server.pipe_name,
        timeout_seconds=0.05,
        retries=1,
        retry_delay_seconds=0.01,
    )
    started = time.monotonic()

    with pytest.raises(BridgeError, match="timed out.*writing request"):
        transport.request({"command": "status", "padding": "x" * (4 * 1024 * 1024)})

    elapsed = time.monotonic() - started
    server.join()
    assert elapsed < 1.0


def test_unavailable_real_named_pipe_fails_cleanly() -> None:
    missing_pipe = rf"\\.\pipe\OllyBridgeMissing-{uuid.uuid4()}"
    transport = NamedPipeTransport(
        pipe_name=missing_pipe,
        timeout_seconds=0.05,
        retries=1,
        retry_delay_seconds=0.01,
    )

    with pytest.raises(BridgeError, match="pipe is busy or unavailable"):
        transport.request({"command": "status"})
