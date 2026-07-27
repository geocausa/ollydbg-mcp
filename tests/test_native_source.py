from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "plugin_stub" / "ollydbg110_bridge.c").read_text(encoding="utf-8")
PARSER = (ROOT / "plugin_stub" / "bridge_json.h").read_text(encoding="utf-8")
EXPORTS = (ROOT / "plugin_stub" / "OllyBridge110.def").read_text(encoding="utf-8")


def test_pipe_is_local_owner_only_and_interruptible() -> None:
    assert '"D:P(A;;GA;;;OW)"' in SOURCE
    assert "PIPE_REJECT_REMOTE_CLIENTS" in SOURCE
    assert "FILE_FLAG_OVERLAPPED" in SOURCE
    assert "WaitForMultipleObjects" in SOURCE
    assert "CancelIo(pipe)" in SOURCE
    assert "FlushFileBuffers" not in SOURCE


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
    assert "used + 1 >= out_size" in SOURCE
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


def test_native_protocol_identifies_capabilities() -> None:
    assert "#define BRIDGE_PROTOCOL_VERSION 2" in SOURCE
    assert "#define BRIDGE_PLUGIN_VERSION \"2.1\"" in SOURCE
    for capability in (
        "native_wait_for_pause",
        "owner_only_pipe",
        "overlapped_pipe",
        "ui_thread_dispatch",
        "bounded_json_parser",
        "remote_clients",
    ):
        assert capability in SOURCE


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
