from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


source = ROOT / "plugin_stub" / "ollydbg110_bridge.c"
replace_once(
    source,
    '#define BRIDGE_PLUGIN_VERSION "2.6"',
    '#define BRIDGE_PLUGIN_VERSION "2.7"',
    "plugin version",
)
replace_once(
    source,
    "typedef int (cdecl *fn_deletehardwarebreakpoint_t)(int index);",
    "typedef int (cdecl *fn_deletehardwarebreakbyaddr_t)(ulong address);",
    "hardware delete typedef",
)
replace_once(
    source,
    "static fn_deletehardwarebreakpoint_t g_deletehardwarebreakpoint = NULL;",
    "static fn_deletehardwarebreakbyaddr_t g_deletehardwarebreakbyaddr = NULL;",
    "hardware delete global",
)
replace_once(
    source,
    '''  g_deletehardwarebreakpoint = (fn_deletehardwarebreakpoint_t)resolve_export("_Deletehardwarebreakpoint");''',
    '''  g_deletehardwarebreakbyaddr = (fn_deletehardwarebreakbyaddr_t)resolve_export("_Deletehardwarebreakbyaddr");''',
    "hardware delete binding",
)
replace_once(
    source,
    '''          g_sethardwarebreakpoint != NULL && g_deletehardwarebreakpoint != NULL &&''',
    '''          g_sethardwarebreakpoint != NULL && g_deletehardwarebreakbyaddr != NULL &&''',
    "hardware delete requirement",
)
replace_once(
    source,
    '''static void respond_error(char *out, size_t out_size, const char *message) {''',
    '''static void reset_debuggee_state(void) {
  memset(g_hardware_breakpoints, 0, sizeof(g_hardware_breakpoints));
  memset(g_hardware_breakpoints_valid, 0, sizeof(g_hardware_breakpoints_valid));
  InterlockedExchange(&g_last_pause_reason, 0);
  InterlockedExchange(&g_last_pause_reasonex, 0);
  g_last_pause_eip = 0;
  if (g_pause_event != NULL) ResetEvent(g_pause_event);
}

static void respond_error(char *out, size_t out_size, const char *message) {''',
    "debuggee reset helper",
)
replace_once(
    source,
    '''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"remote_clients\":false''',
    '''\"hardware_breakpoint_validation\":true,\"execution_result_validation\":true,\"hardware_breakpoint_address_delete\":true,\"debuggee_reset\":true,\"remote_clients\":false''',
    "native audit capabilities",
)
replace_once(
    source,
    '''  if (g_deletehardwarebreakpoint(index) != 0) {
    respond_error(out, out_size, "Deletehardwarebreakpoint failed");
    return;
  }
  g_hardware_breakpoints_valid[index] = 0;
  memset(&g_hardware_breakpoints[index], 0, sizeof(g_hardware_breakpoints[index]));''',
    '''  if (g_deletehardwarebreakbyaddr(g_hardware_breakpoints[index].addr) != 0) {
    respond_error(out, out_size, "Deletehardwarebreakbyaddr failed");
    return;
  }
  g_hardware_breakpoints_valid[index] = 0;
  memset(&g_hardware_breakpoints[index], 0, sizeof(g_hardware_breakpoints[index]));''',
    "hardware delete by address",
)
replace_once(
    source,
    '''  g_pause_event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (g_pause_event == NULL) {''',
    '''  g_pause_event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (g_pause_event == NULL) {''',
    "pause event anchor",
)
replace_once(
    source,
    '''  log_line("OllyBridge110 plugin loaded");''',
    '''  reset_debuggee_state();
  log_line("OllyBridge110 plugin loaded");''',
    "initial debuggee reset",
)
replace_once(
    source,
    '''extc __declspec(dllexport) int cdecl _ODBG_Pluginclose(void) {
  return 0;
}''',
    '''extc __declspec(dllexport) void cdecl _ODBG_Pluginreset(void) {
  reset_debuggee_state();
}

extc __declspec(dllexport) int cdecl _ODBG_Pluginclose(void) {
  return 0;
}''',
    "plugin reset callback",
)

exports = ROOT / "plugin_stub" / "OllyBridge110.def"
replace_once(
    exports,
    '''  _ODBG_Pluginaction=_ODBG_Pluginaction
  _ODBG_Pluginclose=_ODBG_Pluginclose''',
    '''  _ODBG_Pluginaction=_ODBG_Pluginaction
  _ODBG_Pluginreset=_ODBG_Pluginreset
  _ODBG_Pluginclose=_ODBG_Pluginclose''',
    "reset export",
)

build = ROOT / "plugin_stub" / "build_plugin.ps1"
replace_once(
    build,
    '''    "_ODBG_Pluginaction",
    "_ODBG_Pluginclose",''',
    '''    "_ODBG_Pluginaction",
    "_ODBG_Pluginreset",
    "_ODBG_Pluginclose",''',
    "build reset export check",
)

client = ROOT / "ollydbg_mcp" / "client.py"
replace_once(
    client,
    '''                "execution_result_validation": bool(
                    status.get("capabilities", {}).get(
                        "execution_result_validation"
                    )
                ),
                "atomic_snapshot": False,''',
    '''                "execution_result_validation": bool(
                    status.get("capabilities", {}).get(
                        "execution_result_validation"
                    )
                ),
                "hardware_breakpoint_address_delete": bool(
                    status.get("capabilities", {}).get(
                        "hardware_breakpoint_address_delete"
                    )
                ),
                "debuggee_reset": bool(
                    status.get("capabilities", {}).get("debuggee_reset")
                ),
                "command_aware_retries": True,
                "strict_response_utf8": True,
                "atomic_snapshot": False,''',
    "client audit capabilities",
)

smoke = ROOT / "ollydbg_mcp" / "smoke.py"
replace_once(
    smoke,
    '''    "execution_result_validation",
)''',
    '''    "execution_result_validation",
    "hardware_breakpoint_address_delete",
    "debuggee_reset",
)''',
    "smoke required capabilities",
)
replace_once(
    smoke,
    '''def run_smoke(
    client: SmokeClient,''',
    '''def _little_endian_u32_hex(value: str) -> str:
    numeric = int(normalize_address(value), 16)
    return numeric.to_bytes(4, "little").hex().upper()


def run_smoke(
    client: SmokeClient,''',
    "smoke counter helper",
)
replace_once(
    smoke,
    '''        capture(
            "counter_memory",
            lambda: client.read_memory(manifest.counter_address, 4),
            lambda body: body.get("ok") is True
            and isinstance(body.get("hex"), str)
            and len(body["hex"]) == 8,
        )''',
    '''        expected_counter_hex = (
            _little_endian_u32_hex(manifest.counter_initial_value)
            if manifest.counter_initial_value is not None
            else None
        )
        capture(
            "counter_memory",
            lambda: client.read_memory(manifest.counter_address, 4),
            lambda body: body.get("ok") is True
            and isinstance(body.get("hex"), str)
            and len(body["hex"]) == 8
            and (
                expected_counter_hex is None
                or body["hex"].upper() == expected_counter_hex
            ),
        )''',
    "smoke counter validation",
)
replace_once(
    smoke,
    '''        if allow_execution:
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
            )''',
    '''        if allow_execution:
            run_to_probe = capture(
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
            reached_probe = (
                isinstance(run_to_probe, dict)
                and run_to_probe.get("ok") is True
                and normalize_address(run_to_probe.get("eip", {}).get("eip"))
                == manifest.probe_address
            )
            if reached_probe:
                capture(
                    "step_from_probe",
                    client.step_into,
                    lambda body: body.get("ok") is True and body.get("moved") is True,
                )
            else:
                checks.append(
                    SmokeCheck(
                        name="step_from_probe",
                        ok=False,
                        details={"skipped": True},
                        error="skipped because run_to_probe did not reach the probe",
                    )
                )''',
    "conditional smoke step",
)
replace_once(
    smoke,
    '''        client = OllyBridgeClient(transport=transport, pipe_name=args.pipe_name)''',
    '''        client = OllyBridgeClient(
            transport=transport,
            pipe_name=args.pipe_name,
            timeout_seconds=transport.timeout_seconds,
        )''',
    "smoke client timeout",
)

native_tests = ROOT / "tests" / "test_native_source.py"
replace_once(
    native_tests,
    '''    assert "Hardware breakpoint slot is not tracked by this plugin" in SOURCE
    assert SOURCE.index("if (slot >= 4)") < SOURCE.index(''',
    '''    assert "Hardware breakpoint slot is not tracked by this plugin" in SOURCE
    assert "_Deletehardwarebreakbyaddr" in SOURCE
    assert "g_deletehardwarebreakpoint" not in SOURCE
    assert "g_deletehardwarebreakbyaddr(g_hardware_breakpoints[index].addr)" in SOURCE
    assert SOURCE.index("if (slot >= 4)") < SOURCE.index(''',
    "hardware deletion assertions",
)
replace_once(
    native_tests,
    '''    assert "#define BRIDGE_PLUGIN_VERSION \"2.6\"" in SOURCE''',
    '''    assert "#define BRIDGE_PLUGIN_VERSION \"2.7\"" in SOURCE''',
    "native test plugin version",
)
replace_once(
    native_tests,
    '''        "execution_result_validation",
        "remote_clients",''',
    '''        "execution_result_validation",
        "hardware_breakpoint_address_delete",
        "debuggee_reset",
        "remote_clients",''',
    "native capability assertions",
)
replace_once(
    native_tests,
    '''def test_debugger_requests_are_marshaled_to_the_ui_thread() -> None:''',
    '''def test_debuggee_reset_clears_bridge_owned_session_state() -> None:
    assert "static void reset_debuggee_state(void)" in SOURCE
    assert "memset(g_hardware_breakpoints_valid, 0" in SOURCE
    assert "InterlockedExchange(&g_last_pause_reasonex, 0)" in SOURCE
    assert "_ODBG_Pluginreset" in SOURCE
    assert "_ODBG_Pluginreset" in EXPORTS


def test_debugger_requests_are_marshaled_to_the_ui_thread() -> None:''',
    "debuggee reset assertions",
)

smoke_tests = ROOT / "tests" / "test_smoke.py"
replace_once(
    smoke_tests,
    '''    def __init__(self, *, mutations_enabled: bool = True) -> None:
        self.mutations_enabled = mutations_enabled''',
    '''    def __init__(
        self,
        *,
        mutations_enabled: bool = True,
        run_succeeds: bool = True,
        counter_hex: str = "44332211",
    ) -> None:
        self.mutations_enabled = mutations_enabled
        self.run_succeeds = run_succeeds
        self.counter_hex = counter_hex''',
    "fake smoke options",
)
replace_once(
    smoke_tests,
    '''            "plugin_version": "2.6",''',
    '''            "plugin_version": "2.7",''',
    "fake plugin version",
)
replace_once(
    smoke_tests,
    '''                "execution_result_validation": True,
                "remote_clients": False,''',
    '''                "execution_result_validation": True,
                "hardware_breakpoint_address_delete": True,
                "debuggee_reset": True,
                "remote_clients": False,''',
    "fake audit capabilities",
)
replace_once(
    smoke_tests,
    '''    @staticmethod
    def read_memory(address: str | int, size: int) -> dict[str, Any]:
        return {"ok": True, "address": str(address), "size": size, "hex": "44332211"}''',
    '''    def read_memory(self, address: str | int, size: int) -> dict[str, Any]:
        return {
            "ok": True,
            "address": str(address),
            "size": size,
            "hex": self.counter_hex,
        }''',
    "fake counter memory",
)
replace_once(
    smoke_tests,
    '''        self.run_calls.append(canonical)
        return {"ok": True, "eip": {"eip": canonical}}''',
    '''        self.run_calls.append(canonical)
        if not self.run_succeeds:
            return {"ok": False, "eip": {"eip": "0x00401000"}}
        return {"ok": True, "eip": {"eip": canonical}}''',
    "fake run failure",
)
replace_once(
    smoke_tests,
    '''def test_manifest_address_outside_module_fails_without_stopping_other_checks() -> None:''',
    '''def test_execution_smoke_does_not_step_when_probe_was_not_reached() -> None:
    client = FakeSmokeClient(run_succeeds=False)

    report = run_smoke(client, manifest(), allow_execution=True)

    assert report["ok"] is False
    assert client.step_calls == 0
    assert check_by_name(report, "step_from_probe")["details"]["skipped"] is True


def test_counter_initial_value_is_verified() -> None:
    client = FakeSmokeClient(counter_hex="00000000")

    report = run_smoke(client, manifest())

    assert report["ok"] is False
    assert check_by_name(report, "counter_memory")["ok"] is False


def test_manifest_address_outside_module_fails_without_stopping_other_checks() -> None:''',
    "smoke audit tests",
)

runtime_tests = ROOT / "tests" / "test_runtime_harness.py"
replace_once(
    runtime_tests,
    '''    assert "if (!$SkipServer)" in LAUNCHER
    assert "MCP server launch skipped." in LAUNCHER''',
    '''    assert "if (!$SkipServer)" in LAUNCHER
    assert LAUNCHER.index("Get-Process -Name OLLYDBG") < LAUNCHER.index("Copy-Item -LiteralPath $iniPath")
    assert LAUNCHER.index("Get-Process -Name OLLYDBG") < LAUNCHER.index("Copy-Item -LiteralPath $resolvedPluginDll")
    assert "OllyDbg did not stop within 10 seconds" in LAUNCHER
    assert "MCP server launch skipped." in LAUNCHER''',
    "launcher ordering assertions",
)
replace_once(
    runtime_tests,
    '''def test_smoke_command_and_ci_target_build_are_registered() -> None:''',
    '''def test_execution_smoke_only_steps_after_reaching_probe() -> None:
    assert SMOKE.index("if reached_probe:") < SMOKE.index('"step_from_probe"')
    assert "skipped because run_to_probe did not reach the probe" in SMOKE
    assert "_little_endian_u32_hex" in SMOKE
    assert "timeout_seconds=transport.timeout_seconds" in SMOKE


def test_smoke_command_and_ci_target_build_are_registered() -> None:''',
    "smoke ordering assertions",
)

pipe_tests = ROOT / "tests" / "test_named_pipe_windows.py"
replace_once(
    pipe_tests,
    '''def test_real_named_pipe_rejects_non_object_response() -> None:''',
    '''def test_real_named_pipe_rejects_invalid_utf8_response() -> None:
    server = WindowsPipeServer(lambda request: [(0.0, b'{"ok":true,"value":"\\xff"}\\n')])
    server.start()

    with pytest.raises(BridgeError, match="invalid UTF-8"):
        make_transport(server).request({"command": "status"})
    server.join()


def test_real_named_pipe_rejects_non_object_response() -> None:''',
    "invalid UTF-8 pipe test",
)

readme = ROOT / "README.md"
replace_once(
    readme,
    '''- hardware-breakpoint slot, size, index and alignment validation
- address lookup, labels and comments''',
    '''- hardware-breakpoint logical-slot, size, index and alignment validation
- address-based deletion of bridge-owned hardware breakpoints
- per-debuggee reset of bridge-owned native state
- command-aware retries that never replay ambiguous state-changing requests
- strict UTF-8 validation for native responses
- address lookup, labels and comments''',
    "README audit features",
)
replace_once(
    readme,
    '''The mutation check automatically launches OllyDbg with the native mutation
 gate enabled and preserves a breakpoint that already existed at the probe.'''.replace("\n ", "\n"),
    '''The mutation check automatically launches OllyDbg with the native mutation
gate enabled and preserves a breakpoint that already existed at the probe.''',
    "README no-op anchor",
)
