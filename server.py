from __future__ import annotations

import argparse
import json
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib import error, request

import ctypes

from mcp.server.fastmcp import FastMCP


DEFAULT_BRIDGE_URL = os.environ.get("OLLYDBG_BRIDGE_URL", "http://127.0.0.1:31337")
DEFAULT_PIPE_NAME = os.environ.get("OLLYDBG_PIPE_NAME", r"\\.\pipe\OllyBridge110")

STATUS_NAMES = {
    0: "none",
    1: "stopped",
    2: "event",
    3: "running",
    4: "finished",
    5: "closing",
}

PP_MAIN_MASK = 0x0003
PAUSE_MAIN_REASONS = {
    0x0000: "event",
    0x0001: "pause",
    0x0002: "terminated",
}
PAUSE_REASON_FLAGS = {
    0x0004: "by_program",
    0x0010: "int3_breakpoint",
    0x0020: "memory_breakpoint",
    0x0040: "hardware_breakpoint",
    0x0080: "single_step",
    0x0100: "exception",
    0x0200: "access_violation",
    0x0400: "guard_page",
}


class BridgeError(RuntimeError):
    pass


@dataclass(slots=True)
class OllyBridgeClient:
    base_url: str = DEFAULT_BRIDGE_URL
    pipe_name: str = DEFAULT_PIPE_NAME
    timeout_seconds: float = 5.0
    pipe_retries: int = 5
    pipe_retry_delay_seconds: float = 0.15

    @staticmethod
    def decode_pause_reason(reasonex: int | None) -> dict[str, Any]:
        if reasonex is None:
            return {"main": "unknown", "flags": [], "summary": "unknown"}
        main = PAUSE_MAIN_REASONS.get(reasonex & PP_MAIN_MASK, "unknown")
        flags = [name for bit, name in PAUSE_REASON_FLAGS.items() if reasonex & bit]
        summary_parts = [main] + flags
        return {
            "main": main,
            "flags": flags,
            "summary": ", ".join(summary_parts) if summary_parts else "unknown",
        }

    @staticmethod
    def _augment_status(body: dict[str, Any]) -> dict[str, Any]:
        debug_status = body.get("debug_status")
        if isinstance(debug_status, int):
            body.setdefault("debug_status_name", STATUS_NAMES.get(debug_status, "unknown"))
        pause_info = OllyBridgeClient.decode_pause_reason(body.get("last_pause_reasonex"))
        body.setdefault("pause_info", pause_info)
        return body

    def _raise_pipe_error(self, command: str, message: str) -> None:
        raise BridgeError(f"{command}: {message}")

    def _pipe_request_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = str(payload.get("command", "unknown"))
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

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

        message = (json.dumps(payload) + "\n").encode("utf-8")
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
            self._raise_pipe_error(
                command,
                (
                    f"unable to open OllyDbg pipe {self.pipe_name} "
                    f"(WinError {last_error}). Is the plugin loaded?"
                ),
            )

        try:
            written = ctypes.c_uint32(0)
            ok = WriteFile(
                handle,
                ctypes.c_char_p(message),
                len(message),
                ctypes.byref(written),
                None,
            )
            if not ok:
                last_error = ctypes.get_last_error()
                self._raise_pipe_error(
                    command, f"failed to write request to OllyDbg pipe (WinError {last_error})"
                )

            chunks: list[bytes] = []
            while True:
                buf = ctypes.create_string_buffer(4096)
                read = ctypes.c_uint32(0)
                ok = ReadFile(handle, buf, len(buf), ctypes.byref(read), None)
                if not ok:
                    break
                if read.value == 0:
                    break
                chunks.append(buf.raw[: read.value])
                if b"\n" in chunks[-1]:
                    break
            raw = b"".join(chunks).split(b"\n", 1)[0].decode("utf-8", errors="replace")
        finally:
            CloseHandle(handle)

        if not raw:
            self._raise_pipe_error(command, "pipe returned an empty response")

        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise BridgeError(f"{command}: pipe returned invalid JSON: {raw!r}") from exc

        if not isinstance(body, dict):
            raise BridgeError(f"{command}: pipe returned an unexpected payload: {body!r}")

        if not body.get("ok", False):
            message = body.get("error") or f"{command}: OllyDbg pipe request failed"
            extras: list[str] = []
            debug_status = body.get("debug_status")
            cpu_thread_id = body.get("cpu_thread_id")
            if debug_status is not None:
                extras.append(f"debug_status={debug_status}")
            if cpu_thread_id:
                extras.append(f"cpu_thread_id={cpu_thread_id}")
            if extras:
                message = f"{message} ({', '.join(extras)})"
            raise BridgeError(message)

        return self._augment_status(body)

    def _pipe_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        last_error: BridgeError | None = None
        for attempt in range(self.pipe_retries):
            try:
                return self._pipe_request_once(payload)
            except BridgeError as exc:
                last_error = exc
                retryable = any(
                    marker in str(exc)
                    for marker in ("unable to open OllyDbg pipe", "pipe returned an empty response")
                )
                if not retryable or attempt + 1 >= self.pipe_retries:
                    raise
                time.sleep(self.pipe_retry_delay_seconds * (attempt + 1))
        if last_error is not None:
            raise last_error
        raise BridgeError("pipe request failed for an unknown reason")

    def _post(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}{path}"
        data = json.dumps(payload or {}).encode("utf-8")
        req = request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except error.URLError as exc:
            raise BridgeError(f"Bridge request to {url} failed: {exc}") from exc

        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise BridgeError(f"Bridge returned invalid JSON for {path}: {raw!r}") from exc

        if not isinstance(body, dict):
            raise BridgeError(f"Bridge returned an unexpected payload for {path}: {body!r}")

        if not body.get("ok", False):
            message = body.get("error") or f"Bridge call to {path} failed"
            raise BridgeError(message)

        return body

    def status(self) -> dict[str, Any]:
        return self._pipe_request({"command": "status"})

    def goto_address(self, address: str) -> dict[str, Any]:
        return self._pipe_request({"command": "goto", "address": address})

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        return self._pipe_request({"command": "read_memory", "address": address, "size": size})

    def read_disasm(self, address: str, count: int = 8) -> dict[str, Any]:
        return self._pipe_request({"command": "read_disasm", "address": address, "count": count})

    def get_registers(self) -> dict[str, Any]:
        return self._pipe_request({"command": "get_registers"})

    def get_eip(self) -> dict[str, Any]:
        return self._pipe_request({"command": "get_eip"})

    def current_instruction(self) -> dict[str, Any]:
        return self._pipe_request({"command": "current_instruction"})

    def goto_eip(self) -> dict[str, Any]:
        return self._pipe_request({"command": "goto_eip"})

    def read_stack(self, size: int = 64) -> dict[str, Any]:
        return self._pipe_request({"command": "read_stack", "size": size})

    def disasm_from_stack(self, offset: int = 0, count: int = 8) -> dict[str, Any]:
        return self._pipe_request({"command": "disasm_from_stack", "offset": offset, "count": count})

    def write_memory(self, address: str, hex: str, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            raise BridgeError("write_memory: pass confirm=True to allow debuggee memory writes")
        return self._pipe_request({"command": "write_memory", "address": address, "hex": hex})

    def lookup_address(self, address: str) -> dict[str, Any]:
        return self._pipe_request({"command": "lookup_address", "address": address})

    def list_breakpoints(self) -> dict[str, Any]:
        return self._pipe_request({"command": "list_breakpoints"})

    def list_modules(self) -> dict[str, Any]:
        return self._pipe_request({"command": "list_modules"})

    def list_threads(self) -> dict[str, Any]:
        return self._pipe_request({"command": "list_threads"})

    def set_breakpoint(self, address: str) -> dict[str, Any]:
        return self._pipe_request({"command": "set_breakpoint", "address": address})

    def clear_breakpoint(self, address: str) -> dict[str, Any]:
        return self._pipe_request({"command": "clear_breakpoint", "address": address})

    def set_hardware_breakpoint(self, address: str, type: str = "execute", size: int = 1) -> dict[str, Any]:
        return self._pipe_request(
            {
                "command": "set_hardware_breakpoint",
                "address": address,
                "type": type,
                "size": size,
            }
        )

    def clear_hardware_breakpoint(self, index: int) -> dict[str, Any]:
        return self._pipe_request({"command": "clear_hardware_breakpoint", "index": index})

    def list_hardware_breakpoints(self) -> dict[str, Any]:
        return self._pipe_request({"command": "list_hardware_breakpoints"})

    def set_label(self, address: str, text: str) -> dict[str, Any]:
        return self._pipe_request({"command": "set_label", "address": address, "text": text})

    def set_comment(self, address: str, text: str) -> dict[str, Any]:
        return self._pipe_request({"command": "set_comment", "address": address, "text": text})

    def run(self, address: str | None = None, give_chance: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"command": "run", "give_chance": give_chance}
        if address is not None:
            payload["address"] = address
        return self._pipe_request(payload)

    def wait_for_ready(
        self,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
        module_name: str | None = None,
    ) -> dict[str, Any]:
        started = time.time()
        last_status = self.status()
        last_modules: dict[str, Any] = {"ok": True, "count": 0, "modules": []}
        target_module_name = module_name.lower() if module_name else None
        while time.time() - started < timeout_seconds:
            last_status = self.status()
            last_modules = self.list_modules()
            modules = last_modules.get("modules", [])
            matching_module = None
            if target_module_name is None:
                for module in modules:
                    if module.get("entry") and module.get("entry") != "0x00000000":
                        matching_module = module
                        break
            else:
                for module in modules:
                    name = (module.get("name") or "").lower()
                    path = (module.get("path") or "").lower()
                    if target_module_name in {name, path} and module.get("entry") != "0x00000000":
                        matching_module = module
                        break
            if matching_module is not None:
                return {
                    "ok": True,
                    "status": last_status,
                    "module": matching_module,
                    "modules_count": last_modules.get("count", 0),
                }
            time.sleep(poll_interval_seconds)
        return {
            "ok": False,
            "error": "Timed out waiting for module readiness",
            "status": last_status,
            "modules": last_modules,
        }

    def clear_all_breakpoints(self) -> dict[str, Any]:
        before = self.list_breakpoints()
        cleared: list[str] = []
        errors: list[dict[str, str]] = []
        for breakpoint in before.get("breakpoints", []):
            address = breakpoint.get("address")
            if not address:
                continue
            try:
                self.clear_breakpoint(address)
                cleared.append(address)
            except BridgeError as exc:
                errors.append({"address": address, "error": str(exc)})
        after = self.list_breakpoints()
        return {
            "ok": len(errors) == 0,
            "cleared": cleared,
            "errors": errors,
            "before": before,
            "after": after,
        }

    def prepare_session(
        self,
        module_name: str | None = None,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
        clear_breakpoints: bool = True,
    ) -> dict[str, Any]:
        ready = self.wait_for_ready(timeout_seconds, poll_interval_seconds, module_name)
        result: dict[str, Any] = {"ok": bool(ready.get("ok")), "ready": ready}
        if clear_breakpoints:
            cleared = self.clear_all_breakpoints()
            result["cleared_breakpoints"] = cleared
            result["ok"] = result["ok"] and cleared.get("ok", False)
        result["status"] = self.status()
        result["eip"] = self.get_eip()
        result["instruction"] = self.current_instruction()
        return result

    def _step_with_analysis(self, command: str, address: str | None = None) -> dict[str, Any]:
        before_status = self.status()
        before_eip = self.get_eip()
        before_instruction = self.current_instruction()
        payload: dict[str, Any] = {"command": command}
        if address is not None:
            payload["address"] = address
        step_result = self._pipe_request(payload)
        time.sleep(0.2)
        after_status = self.status()
        after_eip = self.get_eip()
        after_instruction = self.current_instruction()
        moved = before_eip.get("eip") != after_eip.get("eip")
        trap_flags = after_status.get("pause_info", {}).get("flags", [])
        return {
            "ok": True,
            "step_result": step_result,
            "before": {
                "status": before_status,
                "eip": before_eip,
                "instruction": before_instruction,
            },
            "after": {
                "status": after_status,
                "eip": after_eip,
                "instruction": after_instruction,
            },
            "moved": moved,
            "re_trapped": (not moved) and bool(trap_flags),
            "trap_flags": trap_flags,
        }

    def step_into(self, address: str | None = None) -> dict[str, Any]:
        return self._step_with_analysis("step_into", address)

    def step_over(self, address: str | None = None) -> dict[str, Any]:
        return self._step_with_analysis("step_over", address)

    def pause(self) -> dict[str, Any]:
        return self._pipe_request({"command": "pause"})

    def continue_execution(self) -> dict[str, Any]:
        return self.run()

    def run_to_address(
        self,
        address: str,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
    ) -> dict[str, Any]:
        started = time.time()
        continue_result = self.run(address)
        while time.time() - started < timeout_seconds:
            status = self.status()
            eip = self.get_eip()
            if eip.get("eip", "").lower() == address.lower():
                instruction = self.current_instruction()
                return {
                    "ok": True,
                    "address": address,
                    "continue_result": continue_result,
                    "status": status,
                    "eip": eip,
                    "instruction": instruction,
                }
            time.sleep(poll_interval_seconds)
        return {
            "ok": False,
            "address": address,
            "continue_result": continue_result,
            "status": self.status(),
            "eip": self.get_eip(),
            "instruction": self.current_instruction(),
            "error": "Timed out waiting to reach address",
        }


def build_server() -> FastMCP:
    bridge = OllyBridgeClient()
    mcp = FastMCP(
        name="ollydbg-bridge",
        instructions=(
            "Connects to a small localhost bridge that exposes a narrow set of "
            "OllyDbg automation actions."
        ),
    )

    @mcp.tool(description="Check whether the local OllyDbg bridge is reachable.")
    def olly_status() -> dict[str, Any]:
        return bridge.status()

    @mcp.tool(description="Move the OllyDbg CPU/disassembly view to a specific address.")
    def olly_goto_address(address: str) -> dict[str, Any]:
        return bridge.goto_address(address)

    @mcp.tool(description="Read a block of memory from the debuggee as a hex string.")
    def olly_read_memory(address: str, size: int) -> dict[str, Any]:
        if size <= 0:
            raise ValueError("size must be positive")
        return bridge.read_memory(address, size)

    @mcp.tool(description="Read disassembly lines starting at an address.")
    def olly_read_disasm(address: str, count: int = 8) -> dict[str, Any]:
        if count <= 0:
            raise ValueError("count must be positive")
        return bridge.read_disasm(address, count)

    @mcp.tool(description="Read the current general-purpose register snapshot.")
    def olly_get_registers() -> dict[str, Any]:
        return bridge.get_registers()

    @mcp.tool(description="Read the current EIP from the active CPU thread.")
    def olly_get_eip() -> dict[str, Any]:
        return bridge.get_eip()

    @mcp.tool(description="Read the current disassembly line at EIP.")
    def olly_current_instruction() -> dict[str, Any]:
        return bridge.current_instruction()

    @mcp.tool(description="Move the CPU/disassembly view to the current EIP.")
    def olly_goto_eip() -> dict[str, Any]:
        return bridge.goto_eip()

    @mcp.tool(description="Read bytes from the current stack pointer (ESP).")
    def olly_read_stack(size: int = 64) -> dict[str, Any]:
        if size <= 0:
            raise ValueError("size must be positive")
        return bridge.read_stack(size)

    @mcp.tool(description="Treat a DWORD on the stack as a code pointer and disassemble from it.")
    def olly_disasm_from_stack(offset: int = 0, count: int = 8) -> dict[str, Any]:
        if count <= 0:
            raise ValueError("count must be positive")
        return bridge.disasm_from_stack(offset, count)

    @mcp.tool(description="Write bytes to debuggee memory using a hex string like '90 90'.")
    def olly_write_memory(address: str, hex: str, confirm: bool = False) -> dict[str, Any]:
        return bridge.write_memory(address, hex, confirm)

    @mcp.tool(description="Look up module and memory-block information for an address.")
    def olly_lookup_address(address: str) -> dict[str, Any]:
        return bridge.lookup_address(address)

    @mcp.tool(description="List software breakpoints known to OllyDbg.")
    def olly_list_breakpoints() -> dict[str, Any]:
        return bridge.list_breakpoints()

    @mcp.tool(description="Clear every software breakpoint currently known to OllyDbg.")
    def olly_clear_all_breakpoints() -> dict[str, Any]:
        return bridge.clear_all_breakpoints()

    @mcp.tool(description="List modules known to OllyDbg.")
    def olly_list_modules() -> dict[str, Any]:
        return bridge.list_modules()

    @mcp.tool(description="List active threads known to OllyDbg.")
    def olly_list_threads() -> dict[str, Any]:
        return bridge.list_threads()

    @mcp.tool(description="Set a software breakpoint at an address.")
    def olly_set_breakpoint(address: str) -> dict[str, Any]:
        return bridge.set_breakpoint(address)

    @mcp.tool(description="Clear software breakpoints at an address.")
    def olly_clear_breakpoint(address: str) -> dict[str, Any]:
        return bridge.clear_breakpoint(address)

    @mcp.tool(description="Set a hardware breakpoint at an address.")
    def olly_set_hardware_breakpoint(address: str, type: str = "execute", size: int = 1) -> dict[str, Any]:
        return bridge.set_hardware_breakpoint(address, type, size)

    @mcp.tool(description="Clear a hardware breakpoint by index.")
    def olly_clear_hardware_breakpoint(index: int) -> dict[str, Any]:
        return bridge.clear_hardware_breakpoint(index)

    @mcp.tool(description="List hardware breakpoints set through this bridge.")
    def olly_list_hardware_breakpoints() -> dict[str, Any]:
        return bridge.list_hardware_breakpoints()

    @mcp.tool(description="Set a user label at an address.")
    def olly_set_label(address: str, text: str) -> dict[str, Any]:
        return bridge.set_label(address, text)

    @mcp.tool(description="Set a user comment at an address.")
    def olly_set_comment(address: str, text: str) -> dict[str, Any]:
        return bridge.set_comment(address, text)

    @mcp.tool(description="Run the debuggee, optionally until an address.")
    def olly_run(address: str | None = None, give_chance: bool = False) -> dict[str, Any]:
        return bridge.run(address, give_chance)

    @mcp.tool(description="Step into one instruction, optionally with a target address.")
    def olly_step_into(address: str | None = None) -> dict[str, Any]:
        return bridge.step_into(address)

    @mcp.tool(description="Step over one instruction, optionally with a target address.")
    def olly_step_over(address: str | None = None) -> dict[str, Any]:
        return bridge.step_over(address)

    @mcp.tool(description="Pause the debuggee.")
    def olly_pause() -> dict[str, Any]:
        return bridge.pause()

    @mcp.tool(description="Continue execution using OllyDbg's main run shortcut.")
    def olly_continue() -> dict[str, Any]:
        return bridge.continue_execution()

    @mcp.tool(description="Run natively toward an address and wait until Olly stops there.")
    def olly_run_to_address(
        address: str, timeout_seconds: float = 5.0, poll_interval_seconds: float = 0.1
    ) -> dict[str, Any]:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        return bridge.run_to_address(address, timeout_seconds, poll_interval_seconds)

    @mcp.tool(description="Wait for module state to stabilize and optionally clear persisted breakpoints.")
    def olly_prepare_session(
        module_name: str | None = None,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
        clear_breakpoints: bool = True,
    ) -> dict[str, Any]:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        return bridge.prepare_session(
            module_name=module_name,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            clear_breakpoints=clear_breakpoints,
        )

    return mcp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the OllyDbg MCP bridge server.")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default="stdio",
        help="MCP transport to serve.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = build_server()
    server.run(args.transport)


if __name__ == "__main__":
    main()
