from pathlib import Path


PATH = Path("tools/apply_ui_thread.py")
source = PATH.read_text(encoding="utf-8")
replacements = (
    ("new_dispatch = '''", "new_dispatch = r'''") ,
    (
        "    '''        request[read] = '\\0'; dispatch_request(request, response, sizeof(response));",
        "    r'''        request[read] = '\\0'; dispatch_request(request, response, sizeof(response));",
    ),
    (
        "    '''        char command[64];\n        request[read] = '\\0';",
        "    r'''        char command[64];\n        request[read] = '\\0';",
    ),
    (
        "    '''\"overlapped_pipe\\\":true,\\\"remote_clients\\\":false'''",
        "    r'''\\\"overlapped_pipe\\\":true,\\\"remote_clients\\\":false'''",
    ),
    (
        "    '''\"overlapped_pipe\\\":true,\\\"ui_thread_dispatch\\\":true,"
        "\\\"remote_clients\\\":false'''",
        "    r'''\\\"overlapped_pipe\\\":true,\\\"ui_thread_dispatch\\\":true,"
        "\\\"remote_clients\\\":false'''",
    ),
    (
        """replace_once(
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
''',
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_bridge_request.done_event); g_bridge_request.done_event = NULL;
    CloseHandle(g_exec_request.done_event);
''',
    "stop event failure cleanup",
)
""",
        """replace_once(
    '''  if (g_stop_event == NULL) {
    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
''',
    '''  if (g_stop_event == NULL) {
    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_bridge_request.done_event); g_bridge_request.done_event = NULL;
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
''',
    "stop event failure cleanup",
)
""",
    ),
)
for old, new in replacements:
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"patch preparation expected 1 match, found {matches}: {old!r}")
    source = source.replace(old, new, 1)
PATH.write_text(source, encoding="utf-8", newline="\n")
