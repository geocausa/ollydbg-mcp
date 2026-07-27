from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from ollydbg_mcp import BridgeError, OllyBridgeClient, normalize_address


class FakeTransport:
    def __init__(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payload)
        return self.handler(payload)


def test_normalize_address() -> None:
    assert normalize_address("401000") == "0x00401000"
    assert normalize_address("0x1") == "0x00000001"
    assert normalize_address(0xFFFFFFFF) == "0xFFFFFFFF"


@pytest.mark.parametrize("value", ["", "xyz", -1, 0x1_0000_0000, True])
def test_normalize_address_rejects_invalid_values(value: object) -> None:
    with pytest.raises(ValueError):
        normalize_address(value)  # type: ignore[arg-type]


def test_requests_include_protocol_version_and_canonical_address() -> None:
    transport = FakeTransport(lambda payload: {"ok": True, "address": payload["address"]})
    client = OllyBridgeClient(transport=transport)

    result = client.goto_address("401000")

    assert result["address"] == "0x00401000"
    assert transport.calls == [
        {"protocol_version": 1, "command": "goto", "address": "0x00401000"}
    ]


def test_write_memory_requires_confirmation() -> None:
    client = OllyBridgeClient(transport=FakeTransport(lambda _: {"ok": True}))
    with pytest.raises(BridgeError, match="confirm=True"):
        client.write_memory("401000", "90")


def test_write_memory_normalizes_hex() -> None:
    transport = FakeTransport(lambda payload: {"ok": True, "hex": payload["hex"]})
    client = OllyBridgeClient(transport=transport)

    result = client.write_memory("401000", "90 90_cc", confirm=True)

    assert result["hex"] == "9090CC"


def test_clear_all_breakpoints_requires_confirmation() -> None:
    client = OllyBridgeClient(transport=FakeTransport(lambda _: {"ok": True}))
    with pytest.raises(BridgeError, match="confirm=True"):
        client.clear_all_breakpoints()


def test_hardware_breakpoint_validation() -> None:
    client = OllyBridgeClient(transport=FakeTransport(lambda _: {"ok": True}))
    with pytest.raises(ValueError, match="size 1"):
        client.set_hardware_breakpoint("401000", "execute", 4)
    with pytest.raises(ValueError, match="aligned"):
        client.set_hardware_breakpoint("401001", "write", 4)
    with pytest.raises(ValueError, match="0 and 3"):
        client.clear_hardware_breakpoint(4)


def test_status_is_augmented() -> None:
    transport = FakeTransport(
        lambda _: {
            "ok": True,
            "debug_status": 1,
            "last_pause_reasonex": 0x0091,
        }
    )
    status = OllyBridgeClient(transport=transport).status()
    assert status["debug_status_name"] == "stopped"
    assert status["pause_info"]["main"] == "pause"
    assert "single_step" in status["pause_info"]["flags"]
    assert "int3_breakpoint" in status["pause_info"]["flags"]


def test_run_to_address_compares_canonical_values(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "run": {"ok": True},
        "status": {"ok": True, "debug_status": 1},
        "get_eip": {"ok": True, "eip": "0x00401000"},
        "current_instruction": {"ok": True, "eip": "0x00401000", "lines": []},
    }
    transport = FakeTransport(lambda payload: responses[payload["command"]])
    client = OllyBridgeClient(transport=transport)
    monkeypatch.setattr("ollydbg_mcp.client.time.sleep", lambda _: None)

    result = client.run_to_address("401000", timeout_seconds=0.1, poll_interval_seconds=0.01)

    assert result["ok"] is True
    assert result["address"] == "0x00401000"


def test_prepare_session_does_not_clear_breakpoints_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = OllyBridgeClient(transport=FakeTransport(lambda _: {"ok": True}))
    monkeypatch.setattr(
        OllyBridgeClient, "wait_for_ready", lambda self, *args, **kwargs: {"ok": True}
    )
    monkeypatch.setattr(OllyBridgeClient, "status", lambda self: {"ok": True})
    monkeypatch.setattr(
        OllyBridgeClient,
        "get_eip",
        lambda self: {"ok": True, "eip": "0x00401000"},
    )
    monkeypatch.setattr(OllyBridgeClient, "current_instruction", lambda self: {"ok": True})
    monkeypatch.setattr(
        OllyBridgeClient,
        "clear_all_breakpoints",
        lambda self, confirm=False: pytest.fail("breakpoints should not be cleared"),
    )

    result = client.prepare_session()

    assert result["ok"] is True
    assert "cleared_breakpoints" not in result
