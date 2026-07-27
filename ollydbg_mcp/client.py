from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from .protocol import (
    DEFAULT_PIPE_NAME,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_DISASM_COUNT,
    MAX_MEMORY_READ,
    PAUSE_MAIN_REASONS,
    PAUSE_REASON_FLAGS,
    PP_MAIN_MASK,
    STATUS_NAMES,
    BridgeError,
    normalize_address,
    positive,
)
from .transport import BridgeTransport, NamedPipeTransport

TABLE_PAGE_SIZES = {
    "list_breakpoints": 32,
    "list_modules": 8,
    "list_threads": 32,
}
MAX_TABLE_PAGES = 4096
MAX_TABLE_ITEMS = 100_000


@dataclass(slots=True)
class OllyBridgeClient:
    transport: BridgeTransport | None = None
    pipe_name: str = DEFAULT_PIPE_NAME
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if self.transport is None:
            self.transport = NamedPipeTransport(
                pipe_name=self.pipe_name,
                timeout_seconds=self.timeout_seconds,
            )

    @staticmethod
    def decode_pause_reason(reasonex: int | None) -> dict[str, Any]:
        if reasonex is None:
            return {"main": "unknown", "flags": [], "summary": "unknown"}
        main = PAUSE_MAIN_REASONS.get(reasonex & PP_MAIN_MASK, "unknown")
        flags = [name for bit, name in PAUSE_REASON_FLAGS.items() if reasonex & bit]
        return {
            "main": main,
            "flags": flags,
            "summary": ", ".join([main, *flags]),
        }

    @classmethod
    def _augment_status(cls, body: dict[str, Any]) -> dict[str, Any]:
        debug_status = body.get("debug_status")
        if isinstance(debug_status, int):
            body.setdefault("debug_status_name", STATUS_NAMES.get(debug_status, "unknown"))
        body.setdefault("pause_info", cls.decode_pause_reason(body.get("last_pause_reasonex")))
        return body

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        payload = {"protocol_version": 1, **payload}
        assert self.transport is not None
        return self._augment_status(self.transport.request(payload))

    def _collect_table_pages(self, command: str, item_key: str) -> dict[str, Any]:
        page_size = TABLE_PAGE_SIZES[command]
        offset = 0
        pages = 0
        collected: list[Any] = []
        reported_count: int | None = None

        while pages < MAX_TABLE_PAGES:
            page = self._request(
                {
                    "command": command,
                    "offset": offset,
                    "limit": page_size,
                }
            )
            items = page.get(item_key)
            if not isinstance(items, list):
                raise BridgeError(f"{command}: response field {item_key!r} is not a list")
            collected.extend(items)
            pages += 1
            if len(collected) > MAX_TABLE_ITEMS:
                raise BridgeError(f"{command}: table exceeds the supported item limit")

            page_count = page.get("count")
            if isinstance(page_count, int) and page_count >= 0:
                reported_count = page_count

            if page.get("has_more") is not True:
                result = dict(page)
                result[item_key] = collected
                result["count"] = (
                    reported_count if reported_count is not None else len(collected)
                )
                result["offset"] = 0
                result["limit"] = page_size
                result["returned"] = len(collected)
                result["has_more"] = False
                result["next_offset"] = len(collected)
                result["pages"] = pages
                return result

            next_offset = page.get("next_offset")
            if not isinstance(next_offset, int) or next_offset <= offset:
                raise BridgeError(f"{command}: paginated response made no forward progress")
            if not items:
                raise BridgeError(f"{command}: paginated response returned an empty page")
            offset = next_offset

        raise BridgeError(f"{command}: pagination exceeded {MAX_TABLE_PAGES} pages")

    def status(self) -> dict[str, Any]:
        return self._request({"command": "status"})

    def get_capabilities(self) -> dict[str, Any]:
        status = self.status()
        return {
            "ok": True,
            "client_protocol_version": 1,
            "pipe_name": self.pipe_name,
            "timeout_seconds": self.timeout_seconds,
            "native": status,
            "features": {
                "canonical_32bit_addresses": True,
                "guarded_memory_writes": True,
                "bounded_reads": True,
                "pause_polling": True,
                "native_wait_for_pause": bool(
                    status.get("capabilities", {}).get("native_wait_for_pause")
                ),
                "paged_tables": bool(
                    status.get("capabilities", {}).get("paged_tables")
                ),
                "mutation_gate": bool(
                    status.get("capabilities", {}).get("mutation_gate")
                ),
                "mutations_enabled": status.get("mutations_enabled") is True,
                "atomic_snapshot": False,
            },
        }

    def goto_address(self, address: str | int) -> dict[str, Any]:
        return self._request({"command": "goto", "address": normalize_address(address)})

    def read_memory(self, address: str | int, size: int) -> dict[str, Any]:
        positive(size, "size", MAX_MEMORY_READ)
        return self._request(
            {"command": "read_memory", "address": normalize_address(address), "size": size}
        )

    def read_disasm(self, address: str | int, count: int = 8) -> dict[str, Any]:
        positive(count, "count", MAX_DISASM_COUNT)
        return self._request(
            {"command": "read_disasm", "address": normalize_address(address), "count": count}
        )

    def get_registers(self) -> dict[str, Any]:
        return self._request({"command": "get_registers"})

    def get_eip(self) -> dict[str, Any]:
        return self._request({"command": "get_eip"})

    def current_instruction(self) -> dict[str, Any]:
        return self._request({"command": "current_instruction"})

    def goto_eip(self) -> dict[str, Any]:
        return self._request({"command": "goto_eip"})

    def read_stack(self, size: int = 64) -> dict[str, Any]:
        positive(size, "size", MAX_MEMORY_READ)
        return self._request({"command": "read_stack", "size": size})

    def disasm_from_stack(self, offset: int = 0, count: int = 8) -> dict[str, Any]:
        if not -0x100000 <= offset <= 0x100000:
            raise ValueError("offset is outside the supported range")
        positive(count, "count", MAX_DISASM_COUNT)
        return self._request(
            {"command": "disasm_from_stack", "offset": offset, "count": count}
        )

    def write_memory(
        self, address: str | int, hex_bytes: str, confirm: bool = False
    ) -> dict[str, Any]:
        if not confirm:
            raise BridgeError("write_memory: pass confirm=True to allow debuggee memory writes")
        compact = "".join(character for character in hex_bytes if character not in " \t\r\n,_-")
        if not compact or len(compact) % 2:
            raise ValueError("hex_bytes must contain a whole number of bytes")
        try:
            bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("hex_bytes contains non-hexadecimal characters") from exc
        if len(compact) // 2 > MAX_MEMORY_READ:
            raise ValueError(f"hex_bytes must contain at most {MAX_MEMORY_READ} bytes")
        return self._request(
            {
                "command": "write_memory",
                "address": normalize_address(address),
                "hex": compact.upper(),
            }
        )

    def lookup_address(self, address: str | int) -> dict[str, Any]:
        return self._request(
            {"command": "lookup_address", "address": normalize_address(address)}
        )

    def list_breakpoints(self) -> dict[str, Any]:
        return self._collect_table_pages("list_breakpoints", "breakpoints")

    def list_modules(self) -> dict[str, Any]:
        return self._collect_table_pages("list_modules", "modules")

    def list_threads(self) -> dict[str, Any]:
        return self._collect_table_pages("list_threads", "threads")

    def set_breakpoint(self, address: str | int) -> dict[str, Any]:
        return self._request(
            {"command": "set_breakpoint", "address": normalize_address(address)}
        )

    def clear_breakpoint(self, address: str | int) -> dict[str, Any]:
        return self._request(
            {"command": "clear_breakpoint", "address": normalize_address(address)}
        )

    def set_hardware_breakpoint(
        self,
        address: str | int,
        type: Literal["execute", "access", "write"] = "execute",
        size: Literal[1, 2, 4] = 1,
    ) -> dict[str, Any]:
        canonical = normalize_address(address)
        numeric = int(canonical, 16)
        if type == "execute" and size != 1:
            raise ValueError("execute hardware breakpoints must have size 1")
        if type != "execute" and numeric % size:
            raise ValueError(f"{size}-byte data breakpoints must be {size}-byte aligned")
        return self._request(
            {
                "command": "set_hardware_breakpoint",
                "address": canonical,
                "type": type,
                "size": size,
            }
        )

    def clear_hardware_breakpoint(self, index: int) -> dict[str, Any]:
        if index not in range(4):
            raise ValueError("hardware breakpoint index must be between 0 and 3")
        return self._request({"command": "clear_hardware_breakpoint", "index": index})

    def list_hardware_breakpoints(self) -> dict[str, Any]:
        return self._request({"command": "list_hardware_breakpoints"})

    def set_label(self, address: str | int, text: str) -> dict[str, Any]:
        if not text or len(text) >= 256:
            raise ValueError("text must contain between 1 and 255 characters")
        if '"' in text or any(ord(character) < 0x20 for character in text):
            raise ValueError("text cannot contain quotes or control characters")
        return self._request(
            {"command": "set_label", "address": normalize_address(address), "text": text}
        )

    def set_comment(self, address: str | int, text: str) -> dict[str, Any]:
        if not text or len(text) >= 256:
            raise ValueError("text must contain between 1 and 255 characters")
        if '"' in text or any(ord(character) < 0x20 for character in text):
            raise ValueError("text cannot contain quotes or control characters")
        return self._request(
            {"command": "set_comment", "address": normalize_address(address), "text": text}
        )

    def run(self, address: str | int | None = None, give_chance: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {"command": "run", "give_chance": give_chance}
        if address is not None:
            payload["address"] = normalize_address(address)
        return self._request(payload)

    def pause(self) -> dict[str, Any]:
        return self._request({"command": "pause"})

    def continue_execution(self) -> dict[str, Any]:
        return self._request({"command": "continue"})

    @staticmethod
    def _pause_marker(status: dict[str, Any]) -> tuple[Any, ...]:
        if status.get("pause_sequence") is not None:
            return ("sequence", status.get("pause_sequence"))
        return (
            "legacy",
            status.get("debug_status"),
            status.get("last_pause_reasonex"),
            status.get("last_pause_eip"),
        )

    def wait_for_pause(
        self,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        after_sequence: int | None = None,
        baseline_status: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        positive(timeout_seconds, "timeout_seconds", 300)
        positive(poll_interval_seconds, "poll_interval_seconds", timeout_seconds)
        baseline = baseline_status or self.status()
        baseline_marker = self._pause_marker(baseline)
        deadline = time.monotonic() + timeout_seconds
        last_status = baseline
        saw_running = baseline.get("debug_status_name") == "running"
        capabilities = baseline.get("capabilities")
        baseline_sequence = baseline.get("pause_sequence")
        native_after = after_sequence if after_sequence is not None else baseline_sequence

        if (
            isinstance(capabilities, dict)
            and capabilities.get("native_wait_for_pause") is True
            and isinstance(native_after, int)
        ):
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                transport_window = max(0.05, self.timeout_seconds * 0.8)
                native_timeout = min(remaining, transport_window)
                try:
                    native_status = self._request(
                        {
                            "command": "wait_for_pause",
                            "after_sequence": native_after,
                            "timeout_ms": max(1, int(native_timeout * 1000)),
                        }
                    )
                except BridgeError as exc:
                    if "Timed out waiting for OllyDbg to pause" not in str(exc):
                        raise
                    last_status = self.status()
                    continue
                return {
                    "ok": True,
                    "timed_out": False,
                    "status": native_status,
                    "pause_marker": self._pause_marker(native_status),
                    "native": True,
                }
            return {
                "ok": False,
                "timed_out": True,
                "error": "Timed out waiting for OllyDbg to pause",
                "status": last_status,
                "pause_marker": self._pause_marker(last_status),
                "native": True,
            }

        while time.monotonic() < deadline:
            last_status = self.status()
            status_name = last_status.get("debug_status_name")
            if status_name == "running":
                saw_running = True
            sequence = last_status.get("pause_sequence")
            if after_sequence is not None and isinstance(sequence, int):
                changed = sequence > after_sequence
            else:
                changed = self._pause_marker(last_status) != baseline_marker
            if status_name in {"stopped", "event", "finished"} and (changed or saw_running):
                return {
                    "ok": True,
                    "timed_out": False,
                    "status": last_status,
                    "pause_marker": self._pause_marker(last_status),
                }
            time.sleep(poll_interval_seconds)

        return {
            "ok": False,
            "timed_out": True,
            "error": "Timed out waiting for OllyDbg to pause",
            "status": last_status,
            "pause_marker": self._pause_marker(last_status),
        }

    def _step_with_analysis(self, command: str) -> dict[str, Any]:
        before_status = self.status()
        before_eip = self.get_eip()
        before_instruction = self.current_instruction()
        step_result = self._request({"command": command})
        wait_result = self.wait_for_pause(baseline_status=before_status)
        after_status = wait_result.get("status", self.status())
        after_eip = self.get_eip()
        after_instruction = self.current_instruction()
        moved = before_eip.get("eip") != after_eip.get("eip")
        trap_flags = after_status.get("pause_info", {}).get("flags", [])
        return {
            "ok": bool(wait_result.get("ok")),
            "step_result": step_result,
            "wait": wait_result,
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

    def step_into(self) -> dict[str, Any]:
        return self._step_with_analysis("step_into")

    def step_over(self) -> dict[str, Any]:
        return self._step_with_analysis("step_over")

    def wait_for_ready(
        self,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
        module_name: str | None = None,
    ) -> dict[str, Any]:
        positive(timeout_seconds, "timeout_seconds", 300)
        positive(poll_interval_seconds, "poll_interval_seconds", timeout_seconds)
        target = module_name.casefold() if module_name else None
        deadline = time.monotonic() + timeout_seconds
        last_status = self.status()
        last_modules: dict[str, Any] = {"ok": True, "count": 0, "modules": []}
        while time.monotonic() < deadline:
            last_status = self.status()
            last_modules = self.list_modules()
            for module in last_modules.get("modules", []):
                entry = module.get("entry")
                if not entry or entry == "0x00000000":
                    continue
                if target is None:
                    matching = module
                else:
                    name = str(module.get("name") or "").casefold()
                    path = str(module.get("path") or "").casefold()
                    matching = module if target in {name, path} or target in path else None
                if matching is not None:
                    return {
                        "ok": True,
                        "status": last_status,
                        "module": matching,
                        "modules_count": last_modules.get("count", 0),
                    }
            time.sleep(poll_interval_seconds)
        return {
            "ok": False,
            "error": "Timed out waiting for module readiness",
            "status": last_status,
            "modules": last_modules,
        }

    def clear_all_breakpoints(self, confirm: bool = False) -> dict[str, Any]:
        if not confirm:
            raise BridgeError("clear_all_breakpoints: pass confirm=True to clear every breakpoint")
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
            "ok": not errors,
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
        clear_breakpoints: bool = False,
        confirm_clear: bool = False,
    ) -> dict[str, Any]:
        ready = self.wait_for_ready(timeout_seconds, poll_interval_seconds, module_name)
        result: dict[str, Any] = {"ok": bool(ready.get("ok")), "ready": ready}
        if clear_breakpoints:
            cleared = self.clear_all_breakpoints(confirm=confirm_clear)
            result["cleared_breakpoints"] = cleared
            result["ok"] = result["ok"] and bool(cleared.get("ok"))
        result["status"] = self.status()
        result["eip"] = self.get_eip()
        result["instruction"] = self.current_instruction()
        return result

    def run_to_address(
        self,
        address: str | int,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> dict[str, Any]:
        positive(timeout_seconds, "timeout_seconds", 300)
        positive(poll_interval_seconds, "poll_interval_seconds", timeout_seconds)
        target = normalize_address(address)
        continue_result = self.run(target)
        deadline = time.monotonic() + timeout_seconds
        status: dict[str, Any] = {}
        eip: dict[str, Any] = {}
        while time.monotonic() < deadline:
            status = self.status()
            eip = self.get_eip()
            current = eip.get("eip")
            try:
                current = normalize_address(current) if current is not None else None
            except ValueError:
                current = None
            if current == target:
                return {
                    "ok": True,
                    "address": target,
                    "continue_result": continue_result,
                    "status": status,
                    "eip": eip,
                    "instruction": self.current_instruction(),
                }
            time.sleep(poll_interval_seconds)
        return {
            "ok": False,
            "address": target,
            "continue_result": continue_result,
            "status": status or self.status(),
            "eip": eip or self.get_eip(),
            "instruction": self.current_instruction(),
            "error": "Timed out waiting to reach address",
        }

    def snapshot(self, stack_size: int = 64, disasm_count: int = 8) -> dict[str, Any]:
        positive(stack_size, "stack_size", MAX_MEMORY_READ)
        positive(disasm_count, "disasm_count", MAX_DISASM_COUNT)
        status = self.status()
        registers = self.get_registers()
        eip = self.get_eip()
        address = eip.get("eip")
        disassembly = self.read_disasm(address, disasm_count) if address else None
        return {
            "ok": True,
            "status": status,
            "registers": registers,
            "eip": eip,
            "instruction": self.current_instruction(),
            "stack": self.read_stack(stack_size),
            "disassembly": disassembly,
        }
