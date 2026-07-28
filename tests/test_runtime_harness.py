from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = (ROOT / "integration" / "olly_smoke_target.c").read_text(encoding="utf-8")
TARGET_BUILD = (ROOT / "integration" / "build_smoke_target.ps1").read_text(
    encoding="utf-8"
)
RUNTIME_RUNNER = (ROOT / "integration" / "run_runtime_smoke.ps1").read_text(
    encoding="utf-8"
)
SMOKE = (ROOT / "ollydbg_mcp" / "smoke.py").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "start_olly_bridge.ps1").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "python.yml").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_controlled_target_exports_stable_probe_symbols() -> None:
    assert "__declspec(dllexport) volatile LONG olly_smoke_counter" in TARGET
    assert "__declspec(dllexport) __declspec(noinline)" in TARGET
    assert "void __cdecl olly_smoke_probe(void)" in TARGET
    assert "InterlockedIncrement(&olly_smoke_counter)" in TARGET
    assert "Sleep(100)" in TARGET


def test_target_build_is_fixed_x86_and_emits_address_manifest() -> None:
    for flag in (
        '"/MACHINE:X86"',
        '"/DYNAMICBASE:NO"',
        '"/FIXED"',
        '"/BASE:0x00400000"',
        '"/W4"',
        '"/WX"',
        '"/Od"',
        '"/Ob0"',
    ):
        assert flag in TARGET_BUILD
    assert "dumpbin.exe /headers" in TARGET_BUILD
    assert "dumpbin.exe /exports" in TARGET_BUILD
    assert 'Get-ExportRva -Name "olly_smoke_probe"' in TARGET_BUILD
    assert 'Get-ExportRva -Name "olly_smoke_counter"' in TARGET_BUILD
    assert '"olly_smoke_manifest.json"' in TARGET_BUILD
    assert "System.Text.UTF8Encoding($false)" in TARGET_BUILD


def test_runtime_runner_requires_genuine_sdk_and_uses_safe_launcher() -> None:
    assert "[Parameter(Mandatory = $true)]\n    [string]$SdkDir" in RUNTIME_RUNNER
    assert "plugin_stub\\build_plugin.ps1" in RUNTIME_RUNNER
    assert "-AllowTestSdk" not in RUNTIME_RUNNER
    assert "integration\\build_smoke_target.ps1" in RUNTIME_RUNNER
    assert "PluginDllPath = $pluginDll" in RUNTIME_RUNNER
    assert "SkipServer = $true" in RUNTIME_RUNNER
    assert "$launcherArgs.EnableNativeMutations = $true" in RUNTIME_RUNNER
    assert '"--manifest"' in RUNTIME_RUNNER
    assert '"--allow-mutations"' in RUNTIME_RUNNER
    assert '"--allow-execution"' in RUNTIME_RUNNER


def test_manifest_target_is_ready_before_snapshot_inspection() -> None:
    assert SMOKE.index('"target_ready"') < SMOKE.index('capture("snapshot"')


def test_launcher_keeps_existing_behaviour_with_optional_smoke_inputs() -> None:
    assert "[string]$PluginDllPath" in LAUNCHER
    assert "[switch]$SkipServer" in LAUNCHER
    assert "[switch]$EnableNativeMutations" in LAUNCHER
    assert "OLLYBRIDGE_ALLOW_MUTATIONS" in LAUNCHER
    assert "Join-Path $workspacePath 'OllyBridge110.dll'" in LAUNCHER
    assert "if (!$SkipServer)" in LAUNCHER
    process_check = LAUNCHER.index("Get-Process -Name OLLYDBG")
    assert process_check < LAUNCHER.index("Copy-Item -LiteralPath $iniPath")
    assert process_check < LAUNCHER.index("Copy-Item -LiteralPath $resolvedPluginDll")
    assert "OllyDbg did not stop within 10 seconds" in LAUNCHER
    assert "MCP server launch skipped." in LAUNCHER


def test_execution_smoke_only_steps_after_reaching_probe() -> None:
    assert SMOKE.index("if reached_probe:") < SMOKE.index('"step_from_probe"')
    assert "skipped because run_to_probe did not reach the probe" in SMOKE
    assert "_little_endian_u32_hex" in SMOKE
    assert "timeout_seconds=transport.timeout_seconds" in SMOKE


def test_smoke_command_and_ci_target_build_are_registered() -> None:
    assert 'ollydbg-smoke = "ollydbg_mcp.smoke:main"' in PYPROJECT
    assert "runtime-target:" in WORKFLOW
    assert "build_smoke_target.ps1" in WORKFLOW
    assert "Remove the test-only smoke target" in WORKFLOW
    assert "upload-artifact" not in WORKFLOW
