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
    '#include "bridge_json.h"\n#include "bridge_values.h"',
    '#include "bridge_framing.h"\n#include "bridge_json.h"\n#include "bridge_values.h"',
    "framing header include",
)
replace_once(
    source,
    '#define BRIDGE_PLUGIN_VERSION "2.7"',
    '#define BRIDGE_PLUGIN_VERSION "2.8"',
    "plugin version",
)
replace_once(
    source,
    '\\"hardware_breakpoint_address_delete\\":true,\\"debuggee_reset\\":true,\\"remote_clients\\":false',
    '\\"hardware_breakpoint_address_delete\\":true,\\"debuggee_reset\\":true,\\"fragmented_requests\\":true,\\"remote_clients\\":false',
    "fragmented request capability",
)
replace_once(
    source,
    '''static int read_pipe_overlapped(HANDLE pipe, void *buf, DWORD size, DWORD *read, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *read = 0;
  if (ReadFile(pipe, buf, size, read, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, read);
}

static int write_pipe_overlapped''',
    '''static int read_pipe_overlapped(HANDLE pipe, void *buf, DWORD size, DWORD *read, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *read = 0;
  if (ReadFile(pipe, buf, size, read, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, read);
}

static int read_framed_request(
    HANDLE pipe,
    char *request,
    DWORD request_size,
    OVERLAPPED *ov,
    int *overflowed) {
  bridge_frame_state frame;
  char chunk[1024];
  DWORD read;
  int frame_result;
  if (request == NULL || request_size == 0 || overflowed == NULL) return 0;
  bridge_frame_init(&frame);
  request[0] = '\\0';
  *overflowed = 0;
  for (;;) {
    read = 0;
    if (!read_pipe_overlapped(pipe, chunk, sizeof(chunk), &read, ov) || read == 0)
      return 0;
    frame_result = bridge_frame_append(
        &frame, request, (size_t)request_size, chunk, (size_t)read);
    if (frame_result == BRIDGE_FRAME_COMPLETE) return 1;
    if (frame_result == BRIDGE_FRAME_OVERFLOW) {
      *overflowed = 1;
      return 0;
    }
  }
}

static int write_pipe_overlapped''',
    "framed request reader",
)
replace_once(
    source,
    '''    HANDLE pipe; OVERLAPPED ov; char request[PIPE_BUFFER_SIZE];
    char response[PIPE_BUFFER_SIZE]; DWORD read = 0, written = 0;''',
    '''    HANDLE pipe; OVERLAPPED ov; char request[PIPE_BUFFER_SIZE];
    char response[PIPE_BUFFER_SIZE]; DWORD written = 0;
    int request_overflowed = 0;''',
    "pipe worker declarations",
)
replace_once(
    source,
    '''      ZeroMemory(request, sizeof(request)); ZeroMemory(response, sizeof(response));
      if (read_pipe_overlapped(pipe, request, sizeof(request) - 1, &read, &ov) && read > 0) {
        char command[64];
        request[read] = '\\0';
        if (extract_string_field(request, "command", command, sizeof(command)) &&
            strcmp(command, "wait_for_pause") == 0) {
          handle_wait_for_pause_worker(request, response, sizeof(response));
        }
        else if (!execute_request_on_ui_thread(request, response, sizeof(response))) {
          respond_error(response, sizeof(response), "UI-thread request dispatch failed");
        }
      }
      else if (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        respond_error(response, sizeof(response), "Failed to read from pipe");
      }''',
    '''      ZeroMemory(request, sizeof(request)); ZeroMemory(response, sizeof(response));
      if (read_framed_request(
              pipe, request, sizeof(request), &ov, &request_overflowed)) {
        char command[64];
        if (extract_string_field(request, "command", command, sizeof(command)) &&
            strcmp(command, "wait_for_pause") == 0) {
          handle_wait_for_pause_worker(request, response, sizeof(response));
        }
        else if (!execute_request_on_ui_thread(request, response, sizeof(response))) {
          respond_error(response, sizeof(response), "UI-thread request dispatch failed");
        }
      }
      else if (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        if (request_overflowed)
          respond_error(response, sizeof(response), "Request exceeds pipe buffer before newline");
        else
          respond_error(response, sizeof(response), "Failed to read newline-terminated request");
      }''',
    "fragmented request accumulation",
)

client = ROOT / "ollydbg_mcp" / "client.py"
replace_once(
    client,
    '''                "command_aware_retries": True,
                "strict_response_utf8": True,
                "atomic_snapshot": False,''',
    '''                "command_aware_retries": True,
                "strict_response_utf8": True,
                "overlapped_client_io": True,
                "fragmented_native_requests": bool(
                    status.get("capabilities", {}).get("fragmented_requests")
                ),
                "atomic_snapshot": False,''',
    "client feature reporting",
)

smoke = ROOT / "ollydbg_mcp" / "smoke.py"
replace_once(
    smoke,
    '''    "debuggee_reset",
)''',
    '''    "debuggee_reset",
    "fragmented_requests",
)''',
    "smoke required capability",
)

smoke_tests = ROOT / "tests" / "test_smoke.py"
replace_once(
    smoke_tests,
    '            "plugin_version": "2.7",',
    '            "plugin_version": "2.8",',
    "fake smoke plugin version",
)
replace_once(
    smoke_tests,
    '''                "debuggee_reset": True,
                "remote_clients": False,''',
    '''                "debuggee_reset": True,
                "fragmented_requests": True,
                "remote_clients": False,''',
    "fake smoke capability",
)

native_tests = ROOT / "tests" / "test_native_source.py"
replace_once(
    native_tests,
    '''VALUES = (ROOT / "plugin_stub" / "bridge_values.h").read_text(encoding="utf-8")
EXPORTS =''',
    '''VALUES = (ROOT / "plugin_stub" / "bridge_values.h").read_text(encoding="utf-8")
FRAMING = (ROOT / "plugin_stub" / "bridge_framing.h").read_text(encoding="utf-8")
EXPORTS =''',
    "native framing fixture",
)
replace_once(
    native_tests,
    '    assert "#define BRIDGE_PLUGIN_VERSION \\"2.7\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\"2.8\\"" in SOURCE',
    "native plugin version assertion",
)
replace_once(
    native_tests,
    '''        "debuggee_reset",
        "remote_clients",''',
    '''        "debuggee_reset",
        "fragmented_requests",
        "remote_clients",''',
    "native capability assertion",
)
replace_once(
    native_tests,
    '''def test_debugger_requests_are_marshaled_to_the_ui_thread() -> None:''',
    '''def test_fragmented_requests_are_accumulated_until_newline() -> None:
    assert '#include "bridge_framing.h"' in SOURCE
    assert "static int read_framed_request(" in SOURCE
    assert "bridge_frame_append(" in SOURCE
    assert "Request exceeds pipe buffer before newline" in SOURCE
    assert "Failed to read newline-terminated request" in SOURCE
    assert "BRIDGE_FRAME_COMPLETE" in FRAMING
    assert "BRIDGE_FRAME_OVERFLOW" in FRAMING


def test_debugger_requests_are_marshaled_to_the_ui_thread() -> None:''',
    "native framing test",
)

workflow = ROOT / ".github" / "workflows" / "python.yml"
replace_once(
    workflow,
    '''      - name: Run strict native value parser harness
        run: ./native_values_harness

  native-dll:''',
    '''      - name: Run strict native value parser harness
        run: ./native_values_harness
      - name: Compile fragmented request framing harness
        run: cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_framing_harness.c -o native_framing_harness
      - name: Run fragmented request framing harness
        run: ./native_framing_harness

  native-dll:''',
    "native framing workflow",
)
