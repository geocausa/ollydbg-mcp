from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ollydbg_mcp.protocol import BridgeError
from ollydbg_mcp.smoke import SmokeManifest, run_smoke, wait_for_connection


class FakeSmokeClient:
    def __init__(self) -> None:
        self.breakpoints: set[str] = set()
        self.set_calls: list[str] = []
        self.clear_calls: list[str] = []
        self.run_calls: list[str] = []
        self.step_calls = 0

    @staticmethod
    def status() -> dict[str, Any]:
        return {
            "ok": True,
            "protocol_version": 2,
            "plugin_version": "2.3",
            "debug_status": 2,
            "debug_status_name": "event",
            "capabilities": {
                "native_wait_for_pause": True,
                "owner_only_pipe": True,
                "overlapped_pipe": True,
                "ui_thread_dispatch": True,
                "bounded_json_parser": True,
                "paged_tables": True,
                "client_drain_wait": True,
                "remote_clients": False,
            },
        }

    def get_capabilities(self) -> dict[str, Any]:
        return {"ok": True, "native": self.status()}

    @staticmethod
    def wait_for_ready(
        timeout_seconds: float,
        poll_interval_seconds: float,
        module_name: str | None = None,
    ) -> dict[str, Any]:
        assert timeout_seconds > 0
        assert poll_interval_seconds > 0
        return {
            "ok": True,
            "module": {
                "name": module_name,
                "path": rf"C:\smoke\{module_name}",
                "base": "0x00400000",
                "size": "0x00010000",
                "entry": "0x00401000",
            },
        }

    @staticmethod
    def list_modules() -> dict[str, Any]:
        return {"ok": True, "count": 1, "modules": [{"name": "olly_smoke_target.exe"}]}

    @staticmethod
    def list_threads() -> dict[str, Any]:
        return {"ok": True, "count": 1, "threads": [{"thread_id": "0x00000001"}]}

    def list_breakpoints(self) -> dict[str, Any]:
        return {
            "ok": True,
            "count": len(self.breakpoints),
            "breakpoints": [
                {"address": address} for address in sorted(self.breakpoints)
            ],
        }

    @staticmethod
    def snapshot(stack_size: int = 64, disasm_count: int = 8) -> dict[str, Any]:
        return {"ok": True, "stack_size": stack_size, "disasm_count": disasm_count}

    @staticmethod
    def read_memory(address: str | int, size: int) -> dict[str, Any]:
        return {"ok": True, "address": str(address), "size": size, "hex": "44332211"}

    @staticmethod
    def read_disasm(address: str | int, count: int = 8) -> dict[str, Any]:
        return {
            "ok": True,
            "address": str(address),
            "lines": [{"address": str(address), "instruction": "push ebp", "size": 1}]
            * count,
        }

    @staticmethod
    def lookup_address(address: str | int) -> dict[str, Any]:
        return {"ok": True, "address": str(address), "module": {"present": True}}

    def set_breakpoint(self, address: str | int) -> dict[str, Any]:
        canonical = str(address)
        self.breakpoints.add(canonical)
        self.set_calls.append(canonical)
        return {"ok": True, "address": canonical}

    def clear_breakpoint(self, address: str | int) -> dict[str, Any]:
        canonical = str(address)
        self.breakpoints.discard(canonical)
        self.clear_calls.append(canonical)
        return {"ok": True, "address": canonical}

    def run_to_address(
        self,
        address: str | int,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> dict[str, Any]:
        canonical = str(address)
        self.run_calls.append(canonical)
        return {"ok": True, "eip": {"eip": canonical}}

    def step_into(self) -> dict[str, Any]:
        self.step_calls += 1
        return {"ok": True, "moved": True}


def manifest() -> SmokeManifest:
    return SmokeManifest(
        schema_version=1,
        module_name="olly_smoke_target.exe",
        image_base="0x00400000",
        probe_address="0x00401100",
        counter_address="0x00403000",
        target_path=r"C:\smoke\olly_smoke_target.exe",
        counter_initial_value="0x11223344",
    )


def check_by_name(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(check for check in report["checks"] if check["name"] == name)


def test_manifest_loads_and_normalizes_addresses(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "module_name": "olly_smoke_target.exe",
                "image_base": "400000",
                "probe_address": 0x401100,
                "counter_address": "0x403000",
                "counter_initial_value": "11223344",
            }
        ),
        encoding="utf-8",
    )

    loaded = SmokeManifest.load(path)

    assert loaded.image_base == "0x00400000"
    assert loaded.probe_address == "0x00401100"
    assert loaded.counter_address == "0x00403000"
    assert loaded.counter_initial_value == "0x11223344"


@pytest.mark.parametrize(
    "body, message",
    [
        ([], "JSON object"),
        ({"schema_version": 2}, "schema_version"),
        ({"schema_version": 1, "module_name": ""}, "module_name"),
    ],
)
def test_manifest_rejects_invalid_shapes(
    tmp_path: Path, body: Any, message: str
) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(body), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        SmokeManifest.load(path)


def test_read_only_smoke_report_passes() -> None:
    client = FakeSmokeClient()

    report = run_smoke(client, manifest())

    assert report["ok"] is True
    assert all(check["ok"] for check in report["checks"])
    assert client.set_calls == []
    assert client.run_calls == []


def test_mutation_smoke_creates_and_cleans_probe_breakpoint() -> None:
    client = FakeSmokeClient()

    report = run_smoke(client, manifest(), allow_mutations=True)

    assert report["ok"] is True
    assert client.set_calls == ["0x00401100"]
    assert client.clear_calls == ["0x00401100"]
    assert client.breakpoints == set()
    assert check_by_name(report, "verify_probe_breakpoint_cleared")["ok"] is True


def test_mutation_smoke_preserves_existing_probe_breakpoint() -> None:
    client = FakeSmokeClient()
    client.breakpoints.add("0x00401100")

    report = run_smoke(client, manifest(), allow_mutations=True)

    assert report["ok"] is True
    assert client.set_calls == []
    assert client.clear_calls == []
    assert client.breakpoints == {"0x00401100"}
    assert check_by_name(report, "breakpoint_mutation")["details"]["skipped"] is True


def test_execution_smoke_is_explicit_and_reaches_probe() -> None:
    client = FakeSmokeClient()

    report = run_smoke(client, manifest(), allow_execution=True)

    assert report["ok"] is True
    assert client.run_calls == ["0x00401100"]
    assert client.step_calls == 1


def test_manifest_address_outside_module_fails_without_stopping_other_checks() -> None:
    client = FakeSmokeClient()
    invalid = SmokeManifest(
        schema_version=1,
        module_name="olly_smoke_target.exe",
        image_base="0x00400000",
        probe_address="0x00600000",
        counter_address="0x00403000",
    )

    report = run_smoke(client, invalid)

    assert report["ok"] is False
    assert check_by_name(report, "manifest_addresses")["ok"] is False
    assert check_by_name(report, "counter_memory")["ok"] is True


def test_wait_for_connection_retries_bridge_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    class ConnectingClient:
        def status(self) -> dict[str, Any]:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise BridgeError("not ready")
            return {"ok": True}

    monkeypatch.setattr("ollydbg_mcp.smoke.time.sleep", lambda _: None)

    result = wait_for_connection(ConnectingClient(), 1.0)

    assert result == {"ok": True}
    assert attempts == 3
