from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "plugin_stub" / "ollydbg110_bridge.c"


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


text = SOURCE.read_text(encoding="utf-8")
for old, new, label in (
    ('#define BRIDGE_PLUGIN_VERSION "2.5"', '#define BRIDGE_PLUGIN_VERSION "2.6"', "version"),
    ('typedef void (cdecl *fn_sendshortcut_t)(int where, ulong addr, int msg, int ctrl, int shift, int vkcode);\n', '', "shortcut typedef"),
    ('static fn_sendshortcut_t g_sendshortcut = NULL;\n', '', "shortcut global"),
    ('  g_sendshortcut = (fn_sendshortcut_t)resolve_export("_Sendshortcut");\n', '', "shortcut binding"),
    ('         g_suspendprocess != NULL && g_sendshortcut != NULL;\n', '         g_suspendprocess != NULL;\n', "shortcut requirement"),
):
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)

shortcut = r'''static void dispatch_main_key(int vkcode) {
  HWND main_window = (HWND)(ULONG_PTR)g_plugingetvalue(VAL_HWMAIN);
  if (main_window != NULL) {
    PostMessageA(main_window, WM_KEYDOWN, (WPARAM)vkcode, 0);
    PostMessageA(main_window, WM_KEYUP, (WPARAM)vkcode, 0);
  }
  g_sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 0, vkcode);
}

'''
if text.count(shortcut) != 1:
    raise RuntimeError("dead shortcut helper did not match")
text = text.replace(shortcut, "", 1)
text = text.replace(
    '\\"hardware_breakpoint_validation\\":true,\\"remote_clients\\":false',
    '\\"hardware_breakpoint_validation\\":true,\\"execution_result_validation\\":true,\\"remote_clients\\":false',
    1,
)
old_step = r'''static void handle_step_shortcut(char *out, size_t out_size, int vkcode, int stepmode) {
  int command = (vkcode == VK_F7) ? EXEC_STEP_IN : EXEC_STEP_OVER;
  if (execute_on_ui_thread(command, 0, 0) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread step dispatch failed");
    return;
  }
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"stepmode\":%d,\"debug_status\":%d}\n",
      g_exec_request.thread_id,
      stepmode,
      g_exec_request.debug_status);
}
'''
new_step = r'''static void handle_step(char *out, size_t out_size, int command, int stepmode) {
  if (execute_on_ui_thread(command, 0, 0) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread step dispatch failed");
    return;
  }
  if (g_exec_request.result != 0) {
    respond_stateful_error(out, out_size, "Step failed");
    return;
  }
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"stepmode\":%d,\"debug_status\":%d}\n",
      g_exec_request.thread_id,
      stepmode,
      g_exec_request.debug_status);
}
'''
if text.count(old_step) != 1:
    raise RuntimeError("step handler did not match")
text = text.replace(old_step, new_step, 1)
old_continue = r'''static void handle_continue(char *out, size_t out_size) {
  if (execute_on_ui_thread(EXEC_CONTINUE, 0, 0) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread continue dispatch failed");
    return;
  }
  snprintf(
'''
new_continue = r'''static void handle_continue(char *out, size_t out_size) {
  if (execute_on_ui_thread(EXEC_CONTINUE, 0, 0) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread continue dispatch failed");
    return;
  }
  if (g_exec_request.result != 0) {
    respond_stateful_error(out, out_size, "Continue failed");
    return;
  }
  snprintf(
'''
if text.count(old_continue) != 1:
    raise RuntimeError("continue handler did not match")
text = text.replace(old_continue, new_continue, 1)
text = text.replace(
    '    handle_step_shortcut(out, out_size, VK_F7, STEP_IN);',
    '    handle_step(out, out_size, EXEC_STEP_IN, STEP_IN);',
    1,
)
text = text.replace(
    '    handle_step_shortcut(out, out_size, VK_F8, STEP_OVER);',
    '    handle_step(out, out_size, EXEC_STEP_OVER, STEP_OVER);',
    1,
)
if "g_sendshortcut" in text or "dispatch_main_key" in text or "handle_step_shortcut" in text:
    raise RuntimeError("dead shortcut path remains")
SOURCE.write_text(text, encoding="utf-8")

smoke = ROOT / "ollydbg_mcp" / "smoke.py"
replace_once(
    smoke,
    '    "hardware_breakpoint_validation",\n)',
    '    "hardware_breakpoint_validation",\n    "execution_result_validation",\n)',
    "smoke capability",
)

client = ROOT / "ollydbg_mcp" / "client.py"
replace_once(
    client,
    '''                "hardware_breakpoint_validation": bool(
                    status.get("capabilities", {}).get(
                        "hardware_breakpoint_validation"
                    )
                ),
                "atomic_snapshot": False,
''',
    '''                "hardware_breakpoint_validation": bool(
                    status.get("capabilities", {}).get(
                        "hardware_breakpoint_validation"
                    )
                ),
                "execution_result_validation": bool(
                    status.get("capabilities", {}).get(
                        "execution_result_validation"
                    )
                ),
                "atomic_snapshot": False,
''',
    "client capability",
)

smoke_tests = ROOT / "tests" / "test_smoke.py"
replace_once(smoke_tests, '            "plugin_version": "2.5",', '            "plugin_version": "2.6",', "fake version")
replace_once(
    smoke_tests,
    '''                "hardware_breakpoint_validation": True,
                "remote_clients": False,
''',
    '''                "hardware_breakpoint_validation": True,
                "execution_result_validation": True,
                "remote_clients": False,
''',
    "fake capability",
)

native_tests = ROOT / "tests" / "test_native_source.py"
replace_once(
    native_tests,
    '''\n\ndef test_native_tables_are_paginated_with_bounded_page_sizes() -> None:
''',
    '''\n\ndef test_execution_results_are_validated_without_shortcut_fallbacks() -> None:
    assert "fn_sendshortcut_t" not in SOURCE
    assert "g_sendshortcut" not in SOURCE
    assert "dispatch_main_key" not in SOURCE
    assert "handle_step_shortcut" not in SOURCE
    assert "static void handle_step(" in SOURCE
    step_start = SOURCE.index("static void handle_step(")
    step_end = SOURCE.index("static void handle_continue(")
    step_source = SOURCE[step_start:step_end]
    assert "g_exec_request.result != 0" in step_source
    assert 'respond_stateful_error(out, out_size, "Step failed")' in step_source
    continue_start = SOURCE.index("static void handle_continue(")
    continue_end = SOURCE.index("static void handle_pause(")
    continue_source = SOURCE[continue_start:continue_end]
    assert "g_exec_request.result != 0" in continue_source
    assert 'respond_stateful_error(out, out_size, "Continue failed")' in continue_source


def test_native_tables_are_paginated_with_bounded_page_sizes() -> None:
''',
    "execution assertions",
)
replace_once(
    native_tests,
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.5\\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.6\\\"" in SOURCE',
    "version assertion",
)
replace_once(
    native_tests,
    '        "hardware_breakpoint_validation",\n        "remote_clients",',
    '        "hardware_breakpoint_validation",\n        "execution_result_validation",\n        "remote_clients",',
    "capability assertion",
)

readme = ROOT / "README.md"
replace_once(
    readme,
    '''- pause, continue, run, step and run-to-address helpers
- debugger operations marshalled through OllyDbg's UI thread
''',
    '''- pause, continue, run, step and run-to-address helpers
- native run, step and continue result validation
- debugger operations marshalled through OllyDbg's UI thread
''',
    "README feature",
)
replace_once(
    readme,
    '''strict native values, hardware-breakpoint validation, bounded response, bounded
pagination, native-build and runtime-harness protections.
''',
    '''strict native values, hardware-breakpoint validation, execution-result
validation, bounded response, bounded pagination, native-build and runtime-harness
protections.
''',
    "README assertions",
)
