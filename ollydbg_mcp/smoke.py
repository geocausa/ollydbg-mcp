from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from .client import OllyBridgeClient
from .protocol import DEFAULT_PIPE_NAME, BridgeError, normalize_address, positive
from .transport import NamedPipeTransport

REQUIRED_NATIVE_CAPABILITIES = (
    "native_wait_for_pause",
    "owner_only_pipe",
    "overlapped_pipe",
    "ui_thread_dispatch",
    "bounded_json_parser",
    "paged_tables",
    "client_drain_wait",
)


class SmokeClient(Protocol):
    def status(self) -> dict[str, Any]: ...

    def get_capabilities(self) -> dict[str, Any]: ...

    def wait_for_ready(
        self,
        timeout_seconds: float,
        poll_interval_seconds: float,
        module_name: str | None = None,
    ) -> dict[str, Any]: ...

    def list_modules(self) -> dict[str, Any]: ...

    def list_threads(self) -> dict[str, Any]: ...

    def list_breakpoints(self) -> dict[str, Any]: ...

    def snapshot(self, stack_size: int = 64, disasm_count: int = 8) -> dict[str, Any]: ...

    def read_memory(self, address: str | int, size: int) -> dict[str, Any]: ...

    def read_disasm(self, address: str | int, count: int = 8) -> dict[str, Any]: ...

    def lookup_address(self, address: str | int) -> dict[str, Any]: ...

    def set_breakpoint(self, address: str | int) -> dict[str, Any]: ...

    def clear_breakpoint(self, address: str | int) -> dict[str, Any]: ...

    def run_to_address(
        self,
        address: str | int,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> dict[str, Any]: ...

    def step_into(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class SmokeManifest:
    schema_version: int
    module_name: str
    image_base: str
    probe_address: str
    counter_address: str
    target_path: str | None = None
    counter_initial_value: str | None = None

    @classmethod
    def load(cls, path: str | Path) -> SmokeManifest:
        manifest_path = Path(path)
        try:
            body = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"unable to read smoke manifest {manifest_path}: {exc}") from exc
        if not isinstance(body, dict):
            raise ValueError("smoke manifest must contain a JSON object")
        if body.get("schema_version") != 1:
            raise ValueError("smoke manifest schema_version must be 1")
        module_name = body.get("module_name")
        if not isinstance(module_name, str) or not module_name.strip():
            raise ValueError("smoke manifest module_name must be a non-empty string")
        return cls(
            schema_version=1,
            module_name=module_name,
            image_base=normalize_address(body.get("image_base")),
            probe_address=normalize_address(body.get("probe_address")),
            counter_address=normalize_address(body.get("counter_address")),
            target_path=(str(body["target_path"]) if body.get("target_path") else None),
            counter_initial_value=(
                normalize_address(body["counter_initial_value"])
                if body.get("counter_initial_value") is not None
                else None
            ),
        )


@dataclass(slots=True)
class SmokeCheck:
    name: str
    ok: bool
    details: Any = None
    error: str | None = None


Validator = Callable[[Any], bool]


def _address_in_module(address: str, module: dict[str, Any]) -> bool:
    try:
        numeric = int(normalize_address(address), 16)
        base = int(normalize_address(module.get("base")), 16)
        size = int(normalize_address(module.get("size")), 16)
    except (TypeError, ValueError):
        return False
    return size > 0 and base <= numeric < base + size


def _breakpoint_addresses(body: dict[str, Any]) -> set[str]:
    addresses: set[str] = set()
    for item in body.get("breakpoints", []):
        if not isinstance(item, dict) or item.get("address") is None:
            continue
        try:
            addresses.add(normalize_address(item["address"]))
        except ValueError:
            continue
    return addresses


def run_smoke(
    client: SmokeClient,
    manifest: SmokeManifest | None = None,
    *,
    timeout_seconds: float = 15.0,
    allow_mutations: bool = False,
    allow_execution: bool = False,
) -> dict[str, Any]:
    positive(timeout_seconds, "timeout_seconds", 300)
    checks: list[SmokeCheck] = []

    def capture(name: str, operation: Callable[[], Any], validator: Validator) -> Any:
        try:
            details = operation()
            ok = bool(validator(details))
            checks.append(
                SmokeCheck(
                    name=name,
                    ok=ok,
                    details=details,
                    error=None if ok else f"validation failed for {name}",
                )
            )
            return details
        except Exception as exc:  # smoke reports should retain all independent failures
            checks.append(SmokeCheck(name=name, ok=False, error=f"{type(exc).__name__}: {exc}"))
            return None

    status = capture("status", client.status, lambda body: body.get("ok") is True)
    capabilities = capture(
        "capabilities",
        client.get_capabilities,
        lambda body: body.get("ok") is True
        and isinstance(body.get("native"), dict)
        and all(
            body["native"].get("capabilities", {}).get(name) is True
            for name in REQUIRED_NATIVE_CAPABILITIES
        )
        and body["native"].get("capabilities", {}).get("remote_clients") is False,
    )

    module: dict[str, Any] | None = None
    if manifest is not None:
        ready = capture(
            "target_ready",
            lambda: client.wait_for_ready(timeout_seconds, 0.1, manifest.module_name),
            lambda body: body.get("ok") is True and isinstance(body.get("module"), dict),
        )
        module = ready.get("module") if isinstance(ready, dict) else None

    capture("modules", client.list_modules, lambda body: isinstance(body.get("modules"), list))
    capture("threads", client.list_threads, lambda body: isinstance(body.get("threads"), list))
    capture(
        "breakpoints",
        client.list_breakpoints,
        lambda body: isinstance(body.get("breakpoints"), list),
    )
    capture("snapshot", client.snapshot, lambda body: body.get("ok") is True)

    if manifest is not None:
        capture(
            "manifest_addresses",
            lambda: {
                "module": module,
                "probe_address": manifest.probe_address,
                "counter_address": manifest.counter_address,
            },
            lambda body: isinstance(body.get("module"), dict)
            and _address_in_module(body["probe_address"], body["module"])
            and _address_in_module(body["counter_address"], body["module"]),
        )
        capture(
            "counter_memory",
            lambda: client.read_memory(manifest.counter_address, 4),
            lambda body: body.get("ok") is True
            and isinstance(body.get("hex"), str)
            and len(body["hex"]) == 8,
        )
        capture(
            "probe_disassembly",
            lambda: client.read_disasm(manifest.probe_address, 4),
            lambda body: body.get("ok") is True
            and isinstance(body.get("lines"), list)
            and bool(body["lines"]),
        )
        capture(
            "probe_lookup",
            lambda: client.lookup_address(manifest.probe_address),
            lambda body: body.get("ok") is True
            and body.get("module", {}).get("present") is True,
        )

        if allow_mutations:
            before = capture(
                "breakpoint_before_mutation",
                client.list_breakpoints,
                lambda body: isinstance(body.get("breakpoints"), list),
            )
            existing = (
                manifest.probe_address in _breakpoint_addresses(before)
                if isinstance(before, dict)
                else False
            )
            if existing:
                checks.append(
                    SmokeCheck(
                        name="breakpoint_mutation",
                        ok=True,
                        details={"skipped": True, "reason": "probe breakpoint already existed"},
                    )
                )
            else:
                created = False
                try:
                    set_result = capture(
                        "set_probe_breakpoint",
                        lambda: client.set_breakpoint(manifest.probe_address),
                        lambda body: body.get("ok") is True,
                    )
                    created = isinstance(set_result, dict) and set_result.get("ok") is True
                    capture(
                        "verify_probe_breakpoint",
                        client.list_breakpoints,
                        lambda body: manifest.probe_address in _breakpoint_addresses(body),
                    )
                finally:
                    if created:
                        capture(
                            "clear_probe_breakpoint",
                            lambda: client.clear_breakpoint(manifest.probe_address),
                            lambda body: body.get("ok") is True,
                        )
                        capture(
                            "verify_probe_breakpoint_cleared",
                            client.list_breakpoints,
                            lambda body: manifest.probe_address not in _breakpoint_addresses(body),
                        )

        if allow_execution:
            capture(
                "run_to_probe",
                lambda: client.run_to_address(
                    manifest.probe_address,
                    timeout_seconds=timeout_seconds,
                    poll_interval_seconds=0.05,
                ),
                lambda body: body.get("ok") is True
                and normalize_address(body.get("eip", {}).get("eip"))
                == manifest.probe_address,
            )
            capture(
                "step_from_probe",
                client.step_into,
                lambda body: body.get("ok") is True and body.get("moved") is True,
            )

    return {
        "ok": all(check.ok for check in checks),
        "mode": {
            "manifest": manifest is not None,
            "mutations": allow_mutations,
            "execution": allow_execution,
        },
        "manifest": asdict(manifest) if manifest is not None else None,
        "initial_status": status,
        "native_capabilities": capabilities,
        "checks": [asdict(check) for check in checks],
    }


def wait_for_connection(client: SmokeClient, timeout_seconds: float) -> dict[str, Any]:
    positive(timeout_seconds, "timeout_seconds", 300)
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return client.status()
        except BridgeError as exc:
            last_error = exc
            time.sleep(0.2)
    raise BridgeError(f"timed out waiting for OllyDbg bridge: {last_error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an OllyDbg bridge runtime smoke test")
    parser.add_argument("--manifest", type=Path, help="JSON manifest from build_smoke_target.ps1")
    parser.add_argument("--pipe-name", default=DEFAULT_PIPE_NAME)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--allow-mutations", action="store_true")
    parser.add_argument("--allow-execution", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = SmokeManifest.load(args.manifest) if args.manifest else None
        transport = NamedPipeTransport(
            pipe_name=args.pipe_name,
            timeout_seconds=min(max(args.timeout, 0.05), 5.0),
            retries=1,
        )
        client = OllyBridgeClient(transport=transport, pipe_name=args.pipe_name)
        wait_for_connection(client, args.timeout)
        report = run_smoke(
            client,
            manifest,
            timeout_seconds=args.timeout,
            allow_mutations=args.allow_mutations,
            allow_execution=args.allow_execution,
        )
    except (BridgeError, OSError, ValueError) as exc:
        report = {"ok": False, "fatal_error": f"{type(exc).__name__}: {exc}"}

    rendered = json.dumps(report, indent=None if args.compact else 2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    sys.exit(main())
