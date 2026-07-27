from __future__ import annotations

import os
from typing import Any

DEFAULT_PIPE_NAME = os.environ.get("OLLYDBG_PIPE_NAME", r"\\.\pipe\OllyBridge110")
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("OLLYDBG_TIMEOUT_SECONDS", "5"))
MAX_ADDRESS = 0xFFFFFFFF
MAX_MEMORY_READ = 1024
MAX_DISASM_COUNT = 32
MAX_PIPE_RESPONSE = 8192

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
    """Raised when the native OllyDbg bridge cannot satisfy a request."""


def normalize_address(value: str | int) -> str:
    """Return a canonical 32-bit OllyDbg address such as ``0x00401000``."""
    if isinstance(value, bool):
        raise ValueError("address must be an integer or hexadecimal string")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        text = value.strip().replace("_", "")
        if not text:
            raise ValueError("address must not be empty")
        try:
            # OllyDbg addresses are conventionally hexadecimal, including when
            # users omit the 0x prefix.
            parsed = int(text[2:] if text.lower().startswith("0x") else text, 16)
        except ValueError as exc:
            raise ValueError(f"invalid hexadecimal address: {value!r}") from exc
    else:
        raise ValueError("address must be an integer or hexadecimal string")

    if not 0 <= parsed <= MAX_ADDRESS:
        raise ValueError("address must fit in an unsigned 32-bit value")
    return f"0x{parsed:08X}"


def positive(value: int | float, name: str, maximum: int | float | None = None) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
