from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .protocol import (
    DEFAULT_PIPE_NAME,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_PIPE_RESPONSE,
    BridgeError,
)

# These commands do not mutate debugger/debuggee state, so an ambiguous empty
# response may be retried without executing a state-changing operation twice.
_EMPTY_RESPONSE_RETRY_SAFE = frozenset(
    {
        "status",
        "wait_for_pause",
        "goto",
        "read_memory",
        "read_disasm",
        "get_registers",
        "get_eip",
        "current_instruction",
        "goto_eip",
        "read_stack",
        "disasm_from_stack",
        "lookup_address",
        "list_breakpoints",
        "list_modules",
        "list_threads",
        "list_hardware_breakpoints",
    }
)


class BridgeTransport(Protocol):
    def request(self, payload: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(slots=True)
class NamedPipeTransport:
    pipe_name: str = DEFAULT_PIPE_NAME
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    retries: int = 5
    retry_delay_seconds: float = 0.15
    max_response_bytes: int = MAX_PIPE_RESPONSE
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = str(payload.get("command", "unknown"))
        with self._lock:
            last_error: BridgeError | None = None
            for attempt in range(self.retries):
                try:
                    return self._request_once(payload)
                except BridgeError as exc:
                    last_error = exc
                    message = str(exc)
                    # Opening failures happen before the request is delivered and
                    # are always safe to retry. An empty response is ambiguous: the
                    # server may already have executed the command, so only retry
                    # commands explicitly classified as read-only/idempotent.
                    retryable = (
                        "unable to open OllyDbg pipe" in message
                        or "pipe is busy" in message
                        or (
                            "pipe returned an empty response" in message
                            and command in _EMPTY_RESPONSE_RETRY_SAFE
                        )
                    )
                    if not retryable or attempt + 1 >= self.retries:
                        raise
                    time.sleep(self.retry_delay_seconds * (attempt + 1))
            raise last_error or BridgeError("pipe request failed for an unknown reason")

    def _request_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = str(payload.get("command", "unknown"))
        if os.name != "nt":
            raise BridgeError(f"{command}: named-pipe transport requires Windows")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        ERROR_BROKEN_PIPE = 109

        WaitNamedPipeW = kernel32.WaitNamedPipeW
        WaitNamedPipeW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        WaitNamedPipeW.restype = ctypes.c_int

        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        CreateFileW.restype = ctypes.c_void_p

        WriteFile = kernel32.WriteFile
        WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        WriteFile.restype = ctypes.c_int

        PeekNamedPipe = kernel32.PeekNamedPipe
        PeekNamedPipe.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        PeekNamedPipe.restype = ctypes.c_int

        ReadFile = kernel32.ReadFile
        ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        ReadFile.restype = ctypes.c_int

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [ctypes.c_void_p]
        CloseHandle.restype = ctypes.c_int

        timeout_ms = max(1, int(self.timeout_seconds * 1000))
        if not WaitNamedPipeW(self.pipe_name, timeout_ms):
            last_error = ctypes.get_last_error()
            raise BridgeError(
                f"{command}: pipe is busy or unavailable at {self.pipe_name} "
                f"(WinError {last_error})"
            )

        handle = CreateFileW(
            self.pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            last_error = ctypes.get_last_error()
            raise BridgeError(
                f"{command}: unable to open OllyDbg pipe {self.pipe_name} "
                f"(WinError {last_error}). Is the plugin loaded?"
            )

        message = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        deadline = time.monotonic() + self.timeout_seconds
        chunks: list[bytes] = []
        total = 0
        try:
            written = ctypes.c_uint32(0)
            if not WriteFile(
                handle,
                ctypes.c_char_p(message),
                len(message),
                ctypes.byref(written),
                None,
            ):
                last_error = ctypes.get_last_error()
                raise BridgeError(
                    f"{command}: failed to write request to OllyDbg pipe "
                    f"(WinError {last_error})"
                )
            if written.value != len(message):
                raise BridgeError(
                    f"{command}: incomplete pipe write ({written.value}/{len(message)} bytes)"
                )

            while time.monotonic() < deadline:
                available = ctypes.c_uint32(0)
                if not PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
                    last_error = ctypes.get_last_error()
                    if last_error == ERROR_BROKEN_PIPE:
                        break
                    raise BridgeError(
                        f"{command}: failed while waiting for pipe response "
                        f"(WinError {last_error})"
                    )
                if available.value == 0:
                    time.sleep(0.01)
                    continue

                read_size = min(available.value, 4096, self.max_response_bytes - total)
                if read_size <= 0:
                    raise BridgeError(
                        f"{command}: pipe response exceeded {self.max_response_bytes} bytes"
                    )
                buffer = ctypes.create_string_buffer(read_size)
                read = ctypes.c_uint32(0)
                if not ReadFile(handle, buffer, read_size, ctypes.byref(read), None):
                    last_error = ctypes.get_last_error()
                    raise BridgeError(
                        f"{command}: failed to read pipe response (WinError {last_error})"
                    )
                if read.value == 0:
                    break
                chunk = buffer.raw[: read.value]
                chunks.append(chunk)
                total += read.value
                if b"\n" in chunk:
                    break
            else:
                raise BridgeError(
                    f"{command}: timed out after {self.timeout_seconds:.2f}s waiting for response"
                )
        finally:
            CloseHandle(handle)

        raw_bytes = b"".join(chunks).split(b"\n", 1)[0]
        if not raw_bytes:
            raise BridgeError(f"{command}: pipe returned an empty response")
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BridgeError(f"{command}: pipe returned invalid UTF-8") from exc
        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BridgeError(f"{command}: pipe returned invalid JSON: {raw!r}") from exc
        if not isinstance(body, dict):
            raise BridgeError(f"{command}: pipe returned an unexpected payload: {body!r}")
        if not body.get("ok", False):
            message = str(body.get("error") or f"{command}: OllyDbg pipe request failed")
            extras = []
            for key in ("debug_status", "cpu_thread_id", "last_pause_reasonex"):
                if body.get(key) is not None:
                    extras.append(f"{key}={body[key]}")
            if extras:
                message = f"{message} ({', '.join(extras)})"
            raise BridgeError(message)
        return body
