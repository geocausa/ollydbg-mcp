from pathlib import Path


PATH = Path("plugin_stub/ollydbg110_bridge.c")
source = PATH.read_text(encoding="utf-8")


def replace_once(old: str, new: str, name: str) -> None:
    global source
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"{name}: expected 1 match, found {matches}")
    source = source.replace(old, new, 1)


replace_once(
    "#define OLLYBRIDGE_WM_EXEC (WM_APP + 0x110)\n",
    "#define OLLYBRIDGE_WM_EXEC (WM_APP + 0x110)\n"
    "#define OLLYBRIDGE_WM_REQUEST (WM_APP + 0x111)\n",
    "request message",
)
replace_once(
    "static HWND g_command_window = NULL;\n",
    "static HWND g_command_window = NULL;\nstatic DWORD g_ui_thread_id = 0;\n",
    "ui thread id",
)
replace_once(
    '''static t_exec_request g_exec_request = {0};
''',
    '''static t_exec_request g_exec_request = {0};

typedef struct t_bridge_request {
  volatile LONG pending;
  char request[PIPE_BUFFER_SIZE];
  char response[PIPE_BUFFER_SIZE];
  HANDLE done_event;
} t_bridge_request;

static t_bridge_request g_bridge_request = {0};

static void dispatch_request(const char *json, char *out, size_t out_size);
''',
    "bridge request state",
)

old_dispatch = '''static LRESULT CALLBACK ollybridge_window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
  (void)hwnd;
  (void)wparam;
  (void)lparam;
  if (message == OLLYBRIDGE_WM_EXEC) {
    g_exec_request.result = 0;
    g_exec_request.thread_id = g_getcputhreadid();
    switch (g_exec_request.command) {
      case EXEC_RUN:
        g_exec_request.result = g_go(0, g_exec_request.address, STEP_RUN, g_exec_request.give_chance, 1);
        break;
      case EXEC_STEP_IN:
        g_exec_request.result = g_go(0, 0, STEP_IN, 0, 1);
        break;
      case EXEC_STEP_OVER:
        g_exec_request.result = g_go(0, 0, STEP_OVER, 0, 1);
        break;
      case EXEC_CONTINUE:
        g_exec_request.result = g_go(0, 0, STEP_RUN, 0, 1);
        break;
      default:
        g_exec_request.result = -1;
        break;
    }
    g_exec_request.debug_status = (int)g_getstatus();
    InterlockedExchange(&g_exec_request.pending, 0);
    if (g_exec_request.done_event != NULL) {
      SetEvent(g_exec_request.done_event);
    }
    return 0;
  }
  return DefWindowProcA(hwnd, message, wparam, lparam);
}

static int execute_on_ui_thread(int command, ulong address, int give_chance) {
  if (g_command_window == NULL || g_exec_request.done_event == NULL) {
    return WAIT_FAILED;
  }
  ResetEvent(g_exec_request.done_event);
  g_exec_request.command = command;
  g_exec_request.address = address;
  g_exec_request.give_chance = give_chance;
  g_exec_request.result = 0;
  g_exec_request.debug_status = (int)g_getstatus();
  g_exec_request.thread_id = g_getcputhreadid();
  InterlockedExchange(&g_exec_request.pending, 1);
  if (!PostMessageA(g_command_window, OLLYBRIDGE_WM_EXEC, 0, 0)) {
    InterlockedExchange(&g_exec_request.pending, 0);
    return WAIT_FAILED;
  }
  return (int)WaitForSingleObject(g_exec_request.done_event, 2000);
}
'''
new_dispatch = '''static void execute_command_now(int command, ulong address, int give_chance) {
  g_exec_request.result = 0;
  g_exec_request.thread_id = g_getcputhreadid();
  switch (command) {
    case EXEC_RUN:
      g_exec_request.result = g_go(0, address, STEP_RUN, give_chance, 1);
      break;
    case EXEC_STEP_IN:
      g_exec_request.result = g_go(0, 0, STEP_IN, 0, 1);
      break;
    case EXEC_STEP_OVER:
      g_exec_request.result = g_go(0, 0, STEP_OVER, 0, 1);
      break;
    case EXEC_CONTINUE:
      g_exec_request.result = g_go(0, 0, STEP_RUN, 0, 1);
      break;
    default:
      g_exec_request.result = -1;
      break;
  }
  g_exec_request.debug_status = (int)g_getstatus();
}

static LRESULT CALLBACK ollybridge_window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
  (void)hwnd;
  (void)wparam;
  (void)lparam;
  if (message == OLLYBRIDGE_WM_REQUEST) {
    ZeroMemory(g_bridge_request.response, sizeof(g_bridge_request.response));
    dispatch_request(
        g_bridge_request.request,
        g_bridge_request.response,
        sizeof(g_bridge_request.response));
    InterlockedExchange(&g_bridge_request.pending, 0);
    if (g_bridge_request.done_event != NULL) SetEvent(g_bridge_request.done_event);
    return 0;
  }
  if (message == OLLYBRIDGE_WM_EXEC) {
    execute_command_now(
        g_exec_request.command,
        g_exec_request.address,
        g_exec_request.give_chance);
    InterlockedExchange(&g_exec_request.pending, 0);
    if (g_exec_request.done_event != NULL) SetEvent(g_exec_request.done_event);
    return 0;
  }
  return DefWindowProcA(hwnd, message, wparam, lparam);
}

static int wait_for_ui_completion(HANDLE done_event, DWORD timeout_ms) {
  HANDLE waits[2];
  if (done_event == NULL || g_stop_event == NULL) return WAIT_FAILED;
  waits[0] = done_event;
  waits[1] = g_stop_event;
  return (int)WaitForMultipleObjects(2, waits, FALSE, timeout_ms);
}

static int execute_on_ui_thread(int command, ulong address, int give_chance) {
  int wait_result;
  if (g_command_window == NULL || g_exec_request.done_event == NULL) return WAIT_FAILED;
  if (GetCurrentThreadId() == g_ui_thread_id) {
    execute_command_now(command, address, give_chance);
    return WAIT_OBJECT_0;
  }
  ResetEvent(g_exec_request.done_event);
  g_exec_request.command = command;
  g_exec_request.address = address;
  g_exec_request.give_chance = give_chance;
  InterlockedExchange(&g_exec_request.pending, 1);
  if (!PostMessageA(g_command_window, OLLYBRIDGE_WM_EXEC, 0, 0)) {
    InterlockedExchange(&g_exec_request.pending, 0);
    return WAIT_FAILED;
  }
  wait_result = wait_for_ui_completion(g_exec_request.done_event, 5000);
  if (wait_result != WAIT_OBJECT_0) InterlockedExchange(&g_exec_request.pending, 0);
  return wait_result;
}

static int execute_request_on_ui_thread(const char *json, char *out, size_t out_size) {
  int wait_result;
  size_t request_length;
  if (json == NULL || out == NULL || out_size == 0 || g_command_window == NULL ||
      g_bridge_request.done_event == NULL) return 0;
  if (GetCurrentThreadId() == g_ui_thread_id) {
    dispatch_request(json, out, out_size);
    return 1;
  }
  request_length = strlen(json);
  if (request_length >= sizeof(g_bridge_request.request)) return 0;
  ResetEvent(g_bridge_request.done_event);
  memcpy(g_bridge_request.request, json, request_length + 1);
  g_bridge_request.response[0] = '\0';
  InterlockedExchange(&g_bridge_request.pending, 1);
  if (!PostMessageA(g_command_window, OLLYBRIDGE_WM_REQUEST, 0, 0)) {
    InterlockedExchange(&g_bridge_request.pending, 0);
    return 0;
  }
  wait_result = wait_for_ui_completion(g_bridge_request.done_event, 5000);
  if (wait_result != WAIT_OBJECT_0) {
    InterlockedExchange(&g_bridge_request.pending, 0);
    return 0;
  }
  strncpy(out, g_bridge_request.response, out_size - 1);
  out[out_size - 1] = '\0';
  return 1;
}
'''
replace_once(old_dispatch, new_dispatch, "UI dispatch implementation")

replace_once(
    '''static void handle_wait_for_pause(const char *json, char *out, size_t out_size) {
''',
    '''static void handle_wait_for_pause_worker(const char *json, char *out, size_t out_size) {
''',
    "worker wait name",
)
replace_once(
    '''    if (seq > after_sequence) { handle_status(out, out_size); return; }
''',
    '''    if (seq > after_sequence) {
      if (!execute_request_on_ui_thread("{\\\"command\\\":\\\"status\\\"}", out, out_size))
        respond_error(out, out_size, "Unable to collect paused debugger status");
      return;
    }
''',
    "worker status collection",
)
replace_once(
    '''  else if (strcmp(command, "wait_for_pause") == 0) {
    handle_wait_for_pause(json, out, out_size);
  }
''',
    '''  else if (strcmp(command, "wait_for_pause") == 0) {
    respond_error(out, out_size, "wait_for_pause must run on the pipe worker");
  }
''',
    "UI wait guard",
)
replace_once(
    '''        request[read] = '\0'; dispatch_request(request, response, sizeof(response));
''',
    '''        char command[64];
        request[read] = '\0';
        if (extract_string_field(request, "command", command, sizeof(command)) &&
            strcmp(command, "wait_for_pause") == 0) {
          handle_wait_for_pause_worker(request, response, sizeof(response));
        }
        else if (!execute_request_on_ui_thread(request, response, sizeof(response))) {
          respond_error(response, sizeof(response), "UI-thread request dispatch failed");
        }
''',
    "pipe dispatch",
)
replace_once(
    '''  WNDCLASSA window_class;
  if (ollydbgversion < PLUGIN_VERSION) {
''',
    '''  WNDCLASSA window_class;
  g_ui_thread_id = GetCurrentThreadId();
  if (ollydbgversion < PLUGIN_VERSION) {
''',
    "capture UI thread",
)
replace_once(
    '''  g_exec_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_exec_request.done_event == NULL) {
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
  g_pause_event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (g_pause_event == NULL) {
    CloseHandle(g_exec_request.done_event); g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
''',
    '''  g_exec_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_exec_request.done_event == NULL) {
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
  g_bridge_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_bridge_request.done_event == NULL) {
    CloseHandle(g_exec_request.done_event); g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
  g_pause_event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (g_pause_event == NULL) {
    CloseHandle(g_bridge_request.done_event); g_bridge_request.done_event = NULL;
    CloseHandle(g_exec_request.done_event); g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
''',
    "request event init",
)
replace_once(
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
''',
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_bridge_request.done_event); g_bridge_request.done_event = NULL;
    CloseHandle(g_exec_request.done_event);
''',
    "stop event failure cleanup",
)
replace_once(
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
''',
    '''    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_bridge_request.done_event); g_bridge_request.done_event = NULL;
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
''',
    "thread failure cleanup",
)
replace_once(
    '''  if (g_exec_request.done_event != NULL) {
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
  }
''',
    '''  if (g_bridge_request.done_event != NULL) {
    CloseHandle(g_bridge_request.done_event);
    g_bridge_request.done_event = NULL;
  }
  if (g_exec_request.done_event != NULL) {
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
  }
''',
    "destroy request event",
)
replace_once(
    '''  UnregisterClassA(OLLYBRIDGE_WINDOW_CLASS, g_instance);
}
''',
    '''  g_ui_thread_id = 0;
  UnregisterClassA(OLLYBRIDGE_WINDOW_CLASS, g_instance);
}
''',
    "destroy UI id",
)
replace_once(
    '''"overlapped_pipe\":true,\"remote_clients\":false''',
    '''"overlapped_pipe\":true,\"ui_thread_dispatch\":true,\"remote_clients\":false''',
    "status capability",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
