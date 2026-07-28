from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "plugin_stub" / "ollydbg110_bridge.c").read_text(encoding="utf-8")
PARSER = (ROOT / "plugin_stub" / "bridge_json.h").read_text(encoding="utf-8")
VALUES = (ROOT / "plugin_stub" / "bridge_values.h").read_text(encoding="utf-8")
EXPORTS = (ROOT / "plugin_stub" / "OllyBridge110.def").read_text(encoding="utf-8")


def test_pipe_is_local_owner_only_and_interruptible() -> None:
    assert '"D:P(A;;GA;;;OW)"' in SOURCE
    assert "PIPE_REJECT_REMOTE_CLIENTS" in SOURCE
    assert "FILE_FLAG_OVERLAPPED" in SOURCE
    assert "WaitForMultipleObjects" in SOURCE
    assert "CancelIo(pipe)" in SOURCE
    assert "FlushFileBuffers" not in SOURCE


def test_pipe_response_waits_for_client_drain() -> None:
    assert "#define PIPE_CLIENT_DRAIN_TIMEOUT_MS 5000" in SOURCE
    assert "static int wait_for_pipe_io_timeout(" in SOURCE
    assert SOURCE.count("static void wait_for_client_close(") == 1
    assert "error == ERROR_PIPE_NOT_CONNECTED" in SOURCE
    assert "wait_for_client_close(pipe, &ov);" in SOURCE
    assert "FlushFileBuffers" not in SOURCE


def test_native_mutation_gate_is_read_only_by_default() -> None:
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
    assert "g_pause_sequence" in SOURCE
    assert 'strcmp(command, "wait_for_pause") == 0' in SOURCE
    assert '\\"pause_sequence\\"' in SOURCE
    assert "WaitForSingleObject(g_pipe_thread, INFINITE)" in SOURCE
    assert "_ODBG_Paused" in EXPORTS
    assert "_ODBG_Pausedex" in EXPORTS


def test_json_and_response_construction_are_bounded() -> None:
    assert "static int append_format(" in SOURCE
    assert "used += (size_t)snprintf" not in SOURCE
    assert "*used + required >= output_size" in PARSER
    assert '#pragma comment(lib, "Advapi32.lib")' in SOURCE


def test_bounded_json_parser_is_integrated() -> None:
    assert '#include "bridge_json.h"' in SOURCE
    assert "return bridge_json_extract_string(json, field, out, out_size);" in SOURCE
    assert "return bridge_json_extract_int(json, field, value);" in SOURCE
    assert "return bridge_json_extract_bool(json, field, value);" in SOURCE
    assert 'snprintf(needle, sizeof(needle), "\\\"%s\\\"", field)' not in SOURCE
    assert "BRIDGE_JSON_MAX_DEPTH 16" in PARSER
    assert "bridge_json_find_field(" in PARSER
    assert "bridge_json_parse_raw_utf8(" in PARSER
    assert "bridge_json_parse_hex4(" in PARSER
    assert "bridge_json_extract_string(" in PARSER
    assert "bridge_json_extract_int(" in PARSER
    assert "bridge_json_extract_bool(" in PARSER


def test_native_values_are_strict_and_portable() -> None:
    assert '#include "bridge_values.h"' in SOURCE
    assert "return bridge_parse_u32_hex(text, value);" in SOURCE
    assert "return bridge_parse_hex_bytes(text, out, max_bytes);" in SOURCE
    assert "strtoul(" not in SOURCE
    assert "bridge_parse_u32_hex(" in VALUES
    assert "bridge_parse_hex_bytes(" in VALUES
    assert "digits >= 8" in VALUES
    assert "*text != '\\0'" in VALUES
    assert "length > (size_t)max_bytes * 2" in VALUES


def test_hardware_breakpoints_are_validated_before_api_calls() -> None:
    assert "Execute hardware breakpoints must have size 1" in SOURCE
    assert "Data hardware breakpoint address is not aligned to its size" in SOURCE
    assert "No free tracked hardware breakpoint slot" in SOURCE
    assert "Hardware breakpoint index must be between 0 and 3" in SOURCE
    assert "Hardware breakpoint slot is not tracked by this plugin" in SOURCE
    assert "_Deletehardwarebreakbyaddr" in SOURCE
    assert "g_deletehardwarebreakpoint" not in SOURCE
    delete_by_address = "g_deletehardwarebreakbyaddr(g_hardware_breakpoints[index].addr)"
    assert delete_by_address in SOURCE
    assert SOURCE.index("if (slot >= 4)") < SOURCE.index(
        "result = g_sethardwarebreakpoint(address, size, type);"
    )
    clear_start = SOURCE.index("static void handle_clear_hardware_breakpoint(")
    clear_end = SOURCE.index("static void handle_list_hardware_breakpoints(")
    clear_source = SOURCE[clear_start:clear_end]
    assert clear_source.index("index < 0 || index >= 4") < clear_source.index(
        delete_by_address
    )
    assert "index >= 0 && index < 4" not in clear_source


def test_execution_results_are_validated_without_shortcut_fallbacks() -> None:
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
    assert "#define BREAKPOINT_PAGE_LIMIT 32" in SOURCE
    assert "#define MODULE_PAGE_LIMIT 8" in SOURCE
    assert "#define THREAD_PAGE_LIMIT 32" in SOURCE
    assert "static int extract_optional_int_field(" in SOURCE
    assert "static int parse_page_request(" in SOURCE
    assert '\\"has_more\\"' in SOURCE
    assert '\\"next_offset\\"' in SOURCE
    assert "handle_list_breakpoints(json, out, out_size);" in SOURCE
    assert "handle_list_modules(json, out, out_size);" in SOURCE
    assert "handle_list_threads(json, out, out_size);" in SOURCE
    assert "handle_list_breakpoints(out, out_size);" not in SOURCE
    assert "handle_list_modules(out, out_size);" not in SOURCE
    assert "handle_list_threads(out, out_size);" not in SOURCE


def test_native_protocol_identifies_capabilities() -> None:
    assert "#define BRIDGE_PROTOCOL_VERSION 2" in SOURCE
    assert '#define BRIDGE_PLUGIN_VERSION "2.7"' in SOURCE
    for capability in (
        "native_wait_for_pause",
        "owner_only_pipe",
        "overlapped_pipe",
        "ui_thread_dispatch",
        "bounded_json_parser",
        "paged_tables",
        "client_drain_wait",
        "mutation_gate",
        "strict_native_values",
        "hardware_breakpoint_validation",
        "execution_result_validation",
        "hardware_breakpoint_address_delete",
        "debuggee_reset",
        "remote_clients",
    ):
        assert capability in SOURCE


def test_debuggee_reset_clears_bridge_owned_session_state() -> None:
    assert "static void reset_debuggee_state(void)" in SOURCE
    assert "memset(g_hardware_breakpoints_valid, 0" in SOURCE
    assert "InterlockedExchange(&g_last_pause_reasonex, 0)" in SOURCE
    assert "_ODBG_Pluginreset" in SOURCE
    assert "_ODBG_Pluginreset" in EXPORTS


def test_debugger_requests_are_marshaled_to_the_ui_thread() -> None:
    assert "#define OLLYBRIDGE_WM_REQUEST" in SOURCE
    assert "g_ui_thread_id = GetCurrentThreadId()" in SOURCE
    assert "static int execute_request_on_ui_thread(" in SOURCE
    assert "PostMessageA(g_command_window, OLLYBRIDGE_WM_REQUEST" in SOURCE
    assert "execute_request_on_ui_thread(request, response, sizeof(response))" in SOURCE
    assert 'respond_error(out, out_size, "wait_for_pause must run on the pipe worker")' in SOURCE
    assert "static void handle_wait_for_pause_worker(" in SOURCE
    assert "request[read] = '\\0'; dispatch_request(" not in SOURCE


def test_ui_request_buffers_keep_single_owner_until_completion() -> None:
    assert "InterlockedCompareExchange(&g_exec_request.pending, 1, 0)" in SOURCE
    assert "InterlockedCompareExchange(&g_bridge_request.pending, 1, 0)" in SOURCE
    assert "InterlockedExchange(&g_exec_request.pending, 0)" in SOURCE
    assert "InterlockedExchange(&g_bridge_request.pending, 0)" in SOURCE
    assert "waits[0] = done_event" in SOURCE
    assert "waits[1] = g_stop_event" in SOURCE
