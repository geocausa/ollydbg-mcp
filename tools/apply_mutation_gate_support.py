from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


smoke = ROOT / "ollydbg_mcp" / "smoke.py"
replace_once(
    smoke,
    '    "client_drain_wait",\n)',
    '    "client_drain_wait",\n    "mutation_gate",\n)',
    "smoke capability",
)
replace_once(
    smoke,
    '''    module: dict[str, Any] | None = None
    if manifest is not None:
''',
    '''    mutation_gate_enabled = True
    if allow_mutations:
        mutation_gate_enabled = (
            isinstance(status, dict) and status.get("mutations_enabled") is True
        )
        checks.append(
            SmokeCheck(
                name="mutation_gate_enabled",
                ok=mutation_gate_enabled,
                details={
                    "mutations_enabled": (
                        status.get("mutations_enabled")
                        if isinstance(status, dict)
                        else None
                    )
                },
                error=(
                    None
                    if mutation_gate_enabled
                    else "native mutation gate is disabled for this OllyDbg process"
                ),
            )
        )

    module: dict[str, Any] | None = None
    if manifest is not None:
''',
    "smoke gate state",
)
replace_once(
    smoke,
    '''        if allow_mutations:
            before = capture(
''',
    '''        if allow_mutations and mutation_gate_enabled:
            before = capture(
''',
    "smoke mutation condition",
)

client = ROOT / "ollydbg_mcp" / "client.py"
replace_once(
    client,
    '''                "paged_tables": bool(
                    status.get("capabilities", {}).get("paged_tables")
                ),
                "atomic_snapshot": False,
''',
    '''                "paged_tables": bool(
                    status.get("capabilities", {}).get("paged_tables")
                ),
                "mutation_gate": bool(
                    status.get("capabilities", {}).get("mutation_gate")
                ),
                "mutations_enabled": status.get("mutations_enabled") is True,
                "atomic_snapshot": False,
''',
    "client mutation features",
)

smoke_tests = ROOT / "tests" / "test_smoke.py"
replace_once(
    smoke_tests,
    '''class FakeSmokeClient:
    def __init__(self) -> None:
        self.breakpoints: set[str] = set()
''',
    '''class FakeSmokeClient:
    def __init__(self, *, mutations_enabled: bool = True) -> None:
        self.mutations_enabled = mutations_enabled
        self.breakpoints: set[str] = set()
''',
    "fake client constructor",
)
replace_once(
    smoke_tests,
    '''    @staticmethod
    def status() -> dict[str, Any]:
        return {
            "ok": True,
            "protocol_version": 2,
            "plugin_version": "2.3",
''',
    '''    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "protocol_version": 2,
            "plugin_version": "2.4",
            "mutations_enabled": self.mutations_enabled,
''',
    "fake status",
)
replace_once(
    smoke_tests,
    '''                "client_drain_wait": True,
                "remote_clients": False,
''',
    '''                "client_drain_wait": True,
                "mutation_gate": True,
                "remote_clients": False,
''',
    "fake mutation capability",
)
replace_once(
    smoke_tests,
    '''def test_mutation_smoke_preserves_existing_probe_breakpoint() -> None:
''',
    '''def test_mutation_smoke_stops_before_breakpoint_calls_when_gate_is_disabled() -> None:
    client = FakeSmokeClient(mutations_enabled=False)

    report = run_smoke(client, manifest(), allow_mutations=True)

    assert report["ok"] is False
    assert check_by_name(report, "mutation_gate_enabled")["ok"] is False
    assert client.set_calls == []
    assert client.clear_calls == []


def test_mutation_smoke_preserves_existing_probe_breakpoint() -> None:
''',
    "disabled mutation test",
)

native_tests = ROOT / "tests" / "test_native_source.py"
replace_once(
    native_tests,
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.3\\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.4\\\"" in SOURCE',
    "native version assertion",
)
replace_once(
    native_tests,
    '        "client_drain_wait",\n        "remote_clients",',
    '        "client_drain_wait",\n        "mutation_gate",\n        "remote_clients",',
    "native mutation capability",
)
replace_once(
    native_tests,
    '''\n\ndef test_pause_sequence_is_native_and_exported() -> None:
''',
    '''\n\ndef test_native_mutation_gate_is_read_only_by_default() -> None:
    assert SOURCE.count("static int command_requires_mutation(") == 1
    assert 'environment_truthy("OLLYBRIDGE_ALLOW_MUTATIONS")' in SOURCE
    assert '\\"mutations_enabled\\":%s' in SOURCE
    assert '\\"mutation_gate\\":true' in SOURCE
    assert "Native mutation gate is disabled" in SOURCE
    assert "InterlockedExchange(&g_mutations_enabled, 0);" in SOURCE
    for command in (
        "write_memory",
        "set_breakpoint",
        "clear_breakpoint",
        "set_hardware_breakpoint",
        "clear_hardware_breakpoint",
        "set_label",
        "set_comment",
    ):
        assert f'strcmp(command, "{command}") == 0' in SOURCE


def test_pause_sequence_is_native_and_exported() -> None:
''',
    "native mutation assertions",
)

runtime_tests = ROOT / "tests" / "test_runtime_harness.py"
replace_once(
    runtime_tests,
    '''    assert "SkipServer = $true" in RUNTIME_RUNNER
    assert '"--manifest"' in RUNTIME_RUNNER
''',
    '''    assert "SkipServer = $true" in RUNTIME_RUNNER
    assert "$launcherArgs.EnableNativeMutations = $true" in RUNTIME_RUNNER
    assert '"--manifest"' in RUNTIME_RUNNER
''',
    "runtime mutation forwarding",
)
replace_once(
    runtime_tests,
    '''    assert "[switch]$SkipServer" in LAUNCHER
    assert "Join-Path $workspacePath 'OllyBridge110.dll'" in LAUNCHER
''',
    '''    assert "[switch]$SkipServer" in LAUNCHER
    assert "[switch]$EnableNativeMutations" in LAUNCHER
    assert "OLLYBRIDGE_ALLOW_MUTATIONS" in LAUNCHER
    assert "Join-Path $workspacePath 'OllyBridge110.dll'" in LAUNCHER
''',
    "launcher mutation assertions",
)

readme = ROOT / "README.md"
replace_once(
    readme,
    "- bounded response-drain handshake before the server disconnects\n- reproducible 32-bit MSVC build and export validation",
    "- bounded response-drain handshake before the server disconnects\n- native read-only-by-default gate for debugger mutations\n- reproducible 32-bit MSVC build and export validation",
    "README feature",
)
replace_once(
    readme,
    '''Session preparation no longer clears breakpoints by default.

The native pipe rejects remote clients and applies an owner-only Windows access
''',
    '''Session preparation no longer clears breakpoints by default.

The native plugin independently blocks memory writes, software and hardware
breakpoint changes, labels and comments unless OllyDbg was started with
`OLLYBRIDGE_ALLOW_MUTATIONS=1`. The supplied launcher forces this setting to
`0` by default and enables it only with `-EnableNativeMutations`. This protects
direct same-user pipe access as well as MCP calls; MCP confirmation remains a
second, separate safety layer.

The native pipe rejects remote clients and applies an owner-only Windows access
''',
    "README safety gate",
)
replace_once(
    readme,
    '''  -PluginDir 'C:\\Tools\\OllyDbg\\Plugins' `
  -RestartOlly
''',
    '''  -PluginDir 'C:\\Tools\\OllyDbg\\Plugins' `
  -RestartOlly

# Explicitly enable native writes, breakpoint changes, labels and comments.
.\\start_olly_bridge.ps1 `
  -OllyDir 'C:\\Tools\\OllyDbg' `
  -PluginDir 'C:\\Tools\\OllyDbg\\Plugins' `
  -EnableNativeMutations `
  -RestartOlly
''',
    "README launcher example",
)
replace_once(
    readme,
    '''The mutation check preserves a breakpoint that already existed at the probe.
The execution check changes debuggee state and therefore remains separate. The
''',
    '''The mutation check automatically launches OllyDbg with the native mutation
gate enabled and preserves a breakpoint that already existed at the probe. The
execution-only check does not enable native mutations. The execution check
changes debuggee state and therefore remains separate. The
''',
    "README smoke mutation mode",
)
