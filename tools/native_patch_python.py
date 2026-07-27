from pathlib import Path


PATH = Path("ollydbg_mcp/client.py")
source = PATH.read_text(encoding="utf-8")


def replace_once(old: str, new: str, name: str) -> None:
    global source
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"{name}: expected 1 match, found {matches}")
    source = source.replace(old, new, 1)


replace_once(
    '''                "pause_polling": True,
                "atomic_snapshot": False,
''',
    '''                "pause_polling": True,
                "native_wait_for_pause": bool(
                    status.get("capabilities", {}).get("native_wait_for_pause")
                ),
                "atomic_snapshot": False,
''',
    "capabilities",
)

replace_once(
    '''        baseline = baseline_status or self.status()
        baseline_marker = self._pause_marker(baseline)
        deadline = time.monotonic() + timeout_seconds
        last_status = baseline
        saw_running = baseline.get("debug_status_name") == "running"

        while time.monotonic() < deadline:
''',
    '''        baseline = baseline_status or self.status()
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
''',
    "native pause wait",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
