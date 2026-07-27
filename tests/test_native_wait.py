from collections.abc import Callable
from typing import Any

import pytest

from ollydbg_mcp import OllyBridgeClient


class FakeTransport:
    def __init__(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payload)
        return self.handler(payload)


def test_wait_for_pause_uses_native_sequence_when_available() -> None:
    def handler(payload: dict[str, Any]) -> dict[str, Any]:
        assert payload["command"] == "wait_for_pause"
        return {
            "ok": True,
            "debug_status": 1,
            "pause_sequence": 8,
            "last_pause_eip": "0x00401001",
            "capabilities": {"native_wait_for_pause": True},
        }

    transport = FakeTransport(handler)
    client = OllyBridgeClient(transport=transport)
    baseline = {
        "ok": True,
        "debug_status": 1,
        "debug_status_name": "stopped",
        "pause_sequence": 7,
        "capabilities": {"native_wait_for_pause": True},
    }

    result = client.wait_for_pause(timeout_seconds=0.25, baseline_status=baseline)

    assert result["ok"] is True
    assert result["native"] is True
    assert result["status"]["pause_sequence"] == 8
    assert len(transport.calls) == 1
    request = transport.calls[0]
    assert request["protocol_version"] == 1
    assert request["command"] == "wait_for_pause"
    assert request["after_sequence"] == 7
    assert 1 <= request["timeout_ms"] <= 250


def test_wait_for_pause_keeps_legacy_polling_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeTransport(
        lambda payload: {
            "ok": True,
            "debug_status": 1,
            "last_pause_reasonex": 0x10,
            "last_pause_eip": "0x00401001",
        }
    )
    client = OllyBridgeClient(transport=transport)
    monkeypatch.setattr("ollydbg_mcp.client.time.sleep", lambda _: None)
    baseline = {
        "ok": True,
        "debug_status": 3,
        "debug_status_name": "running",
        "last_pause_reasonex": 0,
        "last_pause_eip": "0x00401000",
    }

    result = client.wait_for_pause(
        timeout_seconds=0.25,
        poll_interval_seconds=0.01,
        baseline_status=baseline,
    )

    assert result["ok"] is True
    assert "native" not in result
    assert [call["command"] for call in transport.calls] == ["status"]
