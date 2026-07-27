from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin_stub" / "ollydbg110_bridge.c"
WINDOWS_TESTS = ROOT / "tests" / "test_named_pipe_windows.py"
NATIVE_TESTS = ROOT / "tests" / "test_native_source.py"
README = ROOT / "README.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count == 1:
        return text.replace(old, new, 1)
    if count == 0 and new in text:
        return text
    raise RuntimeError(f"{label}: expected one old block, found {count}")


plugin = PLUGIN.read_text(encoding="utf-8")
plugin = replace_once(
    plugin,
    '#define BRIDGE_PLUGIN_VERSION "2.2"',
    '#define BRIDGE_PLUGIN_VERSION "2.3"',
    "plugin version",
)
plugin = replace_once(
    plugin,
    "#define THREAD_PAGE_LIMIT 32\n#define OLLYBRIDGE_WINDOW_CLASS",
    "#define THREAD_PAGE_LIMIT 32\n#define PIPE_CLIENT_DRAIN_TIMEOUT_MS 5000\n#define OLLYBRIDGE_WINDOW_CLASS",
    "drain timeout definition",
)
plugin = replace_once(
    plugin,
    '\\"bounded_json_parser\\":true,\\"paged_tables\\":true,\\"remote_clients\\":false',
    '\\"bounded_json_parser\\":true,\\"paged_tables\\":true,\\"client_drain_wait\\":true,\\"remote_clients\\":false',
    "capability",
)
plugin = replace_once(
    plugin,
    r'''static int wait_for_pipe_io(HANDLE pipe, OVERLAPPED *ov, DWORD *done) {
  HANDLE waits[2]; DWORD wr;
  waits[0] = g_stop_event; waits[1] = ov->hEvent;
  wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
  if (wr == WAIT_OBJECT_0) {
    CancelIo(pipe); WaitForSingleObject(ov->hEvent, 1000); return 0;
  }
  if (wr != WAIT_OBJECT_0 + 1) return 0;
  return GetOverlappedResult(pipe, ov, done, FALSE) != 0;
}
''',
    r'''static int wait_for_pipe_io_timeout(
    HANDLE pipe,
    OVERLAPPED *ov,
    DWORD *done,
    DWORD timeout_ms) {
  HANDLE waits[2];
  DWORD wr;
  waits[0] = g_stop_event;
  waits[1] = ov->hEvent;
  wr = WaitForMultipleObjects(2, waits, FALSE, timeout_ms);
  if (wr == WAIT_OBJECT_0 || wr == WAIT_TIMEOUT) {
    CancelIo(pipe);
    WaitForSingleObject(ov->hEvent, 1000);
    return 0;
  }
  if (wr != WAIT_OBJECT_0 + 1) return 0;
  return GetOverlappedResult(pipe, ov, done, FALSE) != 0;
}

static int wait_for_pipe_io(HANDLE pipe, OVERLAPPED *ov, DWORD *done) {
  return wait_for_pipe_io_timeout(pipe, ov, done, INFINITE);
}
''',
    "bounded pipe wait",
)
plugin = replace_once(
    plugin,
    r'''static int write_pipe_overlapped(HANDLE pipe, const void *buf, DWORD size, DWORD *written, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *written = 0;
  if (WriteFile(pipe, buf, size, written, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, written);
}
''',
    r'''static int write_pipe_overlapped(HANDLE pipe, const void *buf, DWORD size, DWORD *written, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *written = 0;
  if (WriteFile(pipe, buf, size, written, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, written);
}

static void wait_for_client_close(HANDLE pipe, OVERLAPPED *ov) {
  char ignored;
  DWORD read = 0;
  DWORD error;
  ResetEvent(ov->hEvent);
  if (ReadFile(pipe, &ignored, 1, &read, ov)) return;
  error = GetLastError();
  if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA ||
      error == ERROR_PIPE_NOT_CONNECTED) return;
  if (error != ERROR_IO_PENDING) return;
  wait_for_pipe_io_timeout(
      pipe, ov, &read, PIPE_CLIENT_DRAIN_TIMEOUT_MS);
}
''',
    "client-close wait",
)
plugin = replace_once(
    plugin,
    r'''      if (response[0] != '\0' && WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0)
        write_pipe_overlapped(pipe, response, (DWORD)strlen(response), &written, &ov);
''',
    r'''      if (response[0] != '\0' && WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        if (write_pipe_overlapped(
                pipe, response, (DWORD)strlen(response), &written, &ov))
          wait_for_client_close(pipe, &ov);
      }
''',
    "response drain call",
)
PLUGIN.write_text(plugin, encoding="utf-8")

windows_tests = WINDOWS_TESTS.read_text(encoding="utf-8")
windows_tests = replace_once(
    windows_tests,
    "        ERROR_NO_DATA = 232\n",
    "        ERROR_NO_DATA = 232\n        ERROR_PIPE_NOT_CONNECTED = 233\n",
    "test server error constants",
)
windows_tests = replace_once(
    windows_tests,
    r'''                if written.value != len(chunk):
                    raise AssertionError(
                        f"incomplete server write: {written.value}/{len(chunk)}"
                    )
''',
    r'''                if written.value != len(chunk):
                    raise AssertionError(
                        f"incomplete server write: {written.value}/{len(chunk)}"
                    )

            closed_probe = ctypes.create_string_buffer(1)
            closed_read = ctypes.c_uint32(0)
            if not ReadFile(
                pipe,
                closed_probe,
                len(closed_probe),
                ctypes.byref(closed_read),
                None,
            ):
                error = ctypes.get_last_error()
                if error not in (
                    ERROR_BROKEN_PIPE,
                    ERROR_NO_DATA,
                    ERROR_PIPE_NOT_CONNECTED,
                ):
                    raise OSError(error, "waiting for client close failed")
''',
    "test server client-close wait",
)
WINDOWS_TESTS.write_text(windows_tests, encoding="utf-8")

native_tests = NATIVE_TESTS.read_text(encoding="utf-8")
native_tests = replace_once(
    native_tests,
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.2\\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.3\\\"" in SOURCE',
    "native version assertion",
)
native_tests = replace_once(
    native_tests,
    '        "paged_tables",\n        "remote_clients",',
    '        "paged_tables",\n        "client_drain_wait",\n        "remote_clients",',
    "native capability assertion",
)
native_tests = replace_once(
    native_tests,
    "\n\ndef test_pause_sequence_is_native_and_exported() -> None:\n",
    '''\n\ndef test_pipe_response_waits_for_client_drain() -> None:
    assert "#define PIPE_CLIENT_DRAIN_TIMEOUT_MS 5000" in SOURCE
    assert "static int wait_for_pipe_io_timeout(" in SOURCE
    assert "static void wait_for_client_close(" in SOURCE
    assert "error == ERROR_PIPE_NOT_CONNECTED" in SOURCE
    assert "wait_for_client_close(pipe, &ov);" in SOURCE
    assert "FlushFileBuffers" not in SOURCE


def test_pause_sequence_is_native_and_exported() -> None:
''',
    "native drain regression test",
)
NATIVE_TESTS.write_text(native_tests, encoding="utf-8")

readme = README.read_text(encoding="utf-8")
readme = replace_once(
    readme,
    "- interruptible overlapped pipe I/O for clean plugin shutdown\n- reproducible 32-bit MSVC build and export validation",
    "- interruptible overlapped pipe I/O for clean plugin shutdown\n- bounded response-drain handshake before the server disconnects\n- reproducible 32-bit MSVC build and export validation",
    "README feature",
)
readme = replace_once(
    readme,
    "The unit tests use a fake transport and do not require OllyDbg. They also assert\nthat the native source retains the local-only pipe, interruptible shutdown,\npause sequencing, UI-thread dispatch, bounded parser, bounded response,\nbounded pagination and native-build protections. A manual smoke test remains\navailable when a genuine-SDK plugin is loaded:",
    "Most unit tests use a fake transport and do not require OllyDbg. A dedicated\nWindows suite also exercises the Python client against real local named pipes,\nincluding fragmented replies, malformed replies, size limits, disconnects and\ntimeouts. Source assertions retain the local-only pipe, interruptible shutdown,\nresponse-drain handshake, pause sequencing, UI-thread dispatch, bounded parser,\nbounded response, bounded pagination and native-build protections. A manual\nsmoke test remains available when a genuine-SDK plugin is loaded:",
    "README testing",
)
readme = replace_once(
    readme,
    "GitHub Actions runs linting and unit tests on Windows with Python 3.10 and 3.12,\ncompiles the native parser harness with strict C89 warnings on Ubuntu, and\ncompiles, links and inspects the complete 32-bit DLL on Windows.",
    "GitHub Actions runs linting and unit tests on Windows with Python 3.10 and 3.12,\nexercises the transport through real Windows named pipes, compiles the native\nparser harness with strict C89 warnings on Ubuntu, and compiles, links and\ninspects the complete 32-bit DLL on Windows.",
    "README CI",
)
README.write_text(readme, encoding="utf-8")
