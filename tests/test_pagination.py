from collections.abc import Callable
from typing import Any

import pytest

from ollydbg_mcp import OllyBridgeClient
from ollydbg_mcp.protocol import BridgeError


class FakeTransport:
    def __init__(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.handler = handler
        self.calls: list[dict[str, Any]] = []

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payload)
        return self.handler(payload)


def test_modules_are_collected_across_native_pages() -> None:
    def handler(payload: dict[str, Any]) -> dict[str, Any]:
        assert payload["command"] == "list_modules"
        assert payload["protocol_version"] == 1
        if payload["offset"] == 0:
            return {
                "ok": True,
                "count": 3,
                "offset": 0,
                "limit": 8,
                "returned": 2,
                "has_more": True,
                "next_offset": 2,
                "modules": [{"index": 0}, {"index": 1}],
            }
        assert payload["offset"] == 2
        return {
            "ok": True,
            "count": 3,
            "offset": 2,
            "limit": 8,
            "returned": 1,
            "has_more": False,
            "next_offset": 3,
            "modules": [{"index": 2}],
        }

    transport = FakeTransport(handler)
    result = OllyBridgeClient(transport=transport).list_modules()

    assert [module["index"] for module in result["modules"]] == [0, 1, 2]
    assert result["count"] == 3
    assert result["returned"] == 3
    assert result["pages"] == 2
    assert result["offset"] == 0
    assert result["limit"] == 8
    assert result["has_more"] is False
    assert result["next_offset"] == 3
    assert [call["offset"] for call in transport.calls] == [0, 2]
    assert [call["limit"] for call in transport.calls] == [8, 8]


def test_legacy_unpaged_plugin_response_remains_supported() -> None:
    transport = FakeTransport(
        lambda payload: {
            "ok": True,
            "count": 2,
            "modules": [{"index": 0}, {"index": 1}],
        }
    )

    result = OllyBridgeClient(transport=transport).list_modules()

    assert result["count"] == 2
    assert result["returned"] == 2
    assert result["pages"] == 1
    assert result["modules"] == [{"index": 0}, {"index": 1}]
    assert len(transport.calls) == 1


def test_each_table_uses_its_native_safe_page_size() -> None:
    def handler(payload: dict[str, Any]) -> dict[str, Any]:
        key = {
            "list_breakpoints": "breakpoints",
            "list_threads": "threads",
        }[payload["command"]]
        return {
            "ok": True,
            "count": 0,
            "has_more": False,
            "next_offset": 0,
            key: [],
        }

    transport = FakeTransport(handler)
    client = OllyBridgeClient(transport=transport)
    client.list_breakpoints()
    client.list_threads()

    assert transport.calls[0]["command"] == "list_breakpoints"
    assert transport.calls[0]["limit"] == 32
    assert transport.calls[1]["command"] == "list_threads"
    assert transport.calls[1]["limit"] == 32


def test_paginated_response_must_make_forward_progress() -> None:
    transport = FakeTransport(
        lambda payload: {
            "ok": True,
            "count": 2,
            "has_more": True,
            "next_offset": payload["offset"],
            "modules": [{"index": 0}],
        }
    )

    with pytest.raises(BridgeError, match="no forward progress"):
        OllyBridgeClient(transport=transport).list_modules()


def test_paginated_response_cannot_return_an_empty_intermediate_page() -> None:
    transport = FakeTransport(
        lambda payload: {
            "ok": True,
            "count": 2,
            "has_more": True,
            "next_offset": payload["offset"] + 1,
            "modules": [],
        }
    )

    with pytest.raises(BridgeError, match="empty page"):
        OllyBridgeClient(transport=transport).list_modules()


def test_paginated_table_field_must_be_a_list() -> None:
    transport = FakeTransport(
        lambda payload: {
            "ok": True,
            "count": 1,
            "has_more": False,
            "modules": {"index": 0},
        }
    )

    with pytest.raises(BridgeError, match="is not a list"):
        OllyBridgeClient(transport=transport).list_modules()
