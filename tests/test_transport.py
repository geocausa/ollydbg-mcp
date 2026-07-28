from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from ollydbg_mcp.protocol import BridgeError
from ollydbg_mcp.transport import NamedPipeTransport


class ScriptedTransport(NamedPipeTransport):
    def __init__(self, outcomes: Iterable[dict[str, Any] | BridgeError]) -> None:
        super().__init__(retries=5, retry_delay_seconds=0)
        self.outcomes = iter(outcomes)
        self.calls = 0

    def _request_once(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, BridgeError):
            raise outcome
        return outcome


def test_empty_response_is_retried_for_read_only_command() -> None:
    transport = ScriptedTransport(
        [BridgeError("status: pipe returned an empty response"), {"ok": True}]
    )

    assert transport.request({"command": "status"}) == {"ok": True}
    assert transport.calls == 2


@pytest.mark.parametrize(
    "command",
    [
        "write_memory",
        "set_breakpoint",
        "clear_breakpoint",
        "set_hardware_breakpoint",
        "clear_hardware_breakpoint",
        "set_label",
        "set_comment",
        "run",
        "step_into",
        "step_over",
        "pause",
        "continue",
    ],
)
def test_empty_response_is_not_retried_for_stateful_command(command: str) -> None:
    transport = ScriptedTransport(
        [BridgeError(f"{command}: pipe returned an empty response"), {"ok": True}]
    )

    with pytest.raises(BridgeError, match="empty response"):
        transport.request({"command": command})
    assert transport.calls == 1


def test_pre_delivery_open_failure_remains_retryable_for_stateful_command() -> None:
    transport = ScriptedTransport(
        [BridgeError("run: unable to open OllyDbg pipe"), {"ok": True}]
    )

    assert transport.request({"command": "run"}) == {"ok": True}
    assert transport.calls == 2
