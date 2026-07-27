from pathlib import Path

P = Path('plugin_stub/ollydbg110_bridge.c')

def rep(s, a, b, name):
    n = s.count(a)
    if n != 1:
        raise RuntimeError(f'{name}: expected 1 match, found {n}')
    return s.replace(a, b, 1)

s = P.read_text(encoding='utf-8')
s = rep(s,
'''#include <windows.h>
#include <ctype.h>
#include <stdio.h>
''',
'''#include <windows.h>
#include <sddl.h>
#include <ctype.h>
#include <stdio.h>
''', 'headers')
s = rep(s, '#define OLLYBRIDGE_WM_EXEC (WM_APP + 0x110)\n',
'''#define OLLYBRIDGE_WM_EXEC (WM_APP + 0x110)
#define BRIDGE_PROTOCOL_VERSION 2
#define BRIDGE_PLUGIN_VERSION "2.0"
#ifndef PIPE_REJECT_REMOTE_CLIENTS
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008
#endif
''', 'constants')
s = rep(s, 'static HANDLE g_pipe_thread = NULL;\n',
            'static HANDLE g_pipe_thread = NULL;\nstatic HANDLE g_pause_event = NULL;\n', 'pause event')
s = rep(s, 'static volatile ULONG_PTR g_last_pause_eip = 0;\n',
            'static volatile ULONG_PTR g_last_pause_eip = 0;\nstatic volatile LONG g_pause_sequence = 0;\n', 'sequence')
old = r'''static int extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
  char needle[64];
  const char *start;
  const char *end;
  size_t length;

  snprintf(needle, sizeof(needle), "\"%s\"", field);
  start = strstr(json, needle);
  if (start == NULL) {
    return 0;
  }
  start = strchr(start + strlen(needle), ':');
  if (start == NULL) {
    return 0;
  }
  start++;
  while (*start == ' ' || *start == '\t') {
    start++;
  }
  if (*start != '"') {
    return 0;
  }
  start++;
  end = strchr(start, '"');
  if (end == NULL) {
    return 0;
  }
  length = (size_t)(end - start);
  if (length >= out_size) {
    length = out_size - 1;
  }
  memcpy(out, start, length);
  out[length] = '\0';
  return 1;
}
'''
new = r'''static int extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
  char needle[64];
  const char *cursor;
  size_t used = 0;
  if (json == NULL || field == NULL || out == NULL || out_size == 0) return 0;
  snprintf(needle, sizeof(needle), "\"%s\"", field);
  cursor = strstr(json, needle);
  if (cursor == NULL) return 0;
  cursor = strchr(cursor + strlen(needle), ':');
  if (cursor == NULL) return 0;
  cursor++;
  while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') cursor++;
  if (*cursor++ != '"') return 0;
  while (*cursor != '\0') {
    char ch = *cursor++;
    if (ch == '"') { out[used] = '\0'; return 1; }
    if (ch == '\\') {
      ch = *cursor++;
      if (ch == '\0' || ch == 'u') return 0;
      if (ch == 'b') ch = '\b';
      else if (ch == 'f') ch = '\f';
      else if (ch == 'n') ch = '\n';
      else if (ch == 'r') ch = '\r';
      else if (ch == 't') ch = '\t';
      else if (!(ch == '"' || ch == '\\' || ch == '/')) return 0;
    }
    if (used + 1 >= out_size) return 0;
    out[used++] = ch;
  }
  return 0;
}
'''
s = rep(s, old, new, 'string parser')
old = r'''static void handle_status(char *out, size_t out_size) {
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"pipe\":\"\\\\\\\\.\\\\pipe\\\\OllyBridge110\",\"debug_status\":%d,\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\"}\n",
      (int)g_getstatus(),
      g_last_pause_reason,
      g_last_pause_reasonex,
      (ulong)g_last_pause_eip);
}
'''
new = r'''static void handle_status(char *out, size_t out_size) {
  snprintf(out, out_size,
      "{\"ok\":true,\"protocol_version\":%d,\"plugin_version\":\"%s\",\"pipe\":\"\\\\\\\\.\\\\pipe\\\\OllyBridge110\",\"debug_status\":%d,\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\",\"pause_sequence\":%ld,\"capabilities\":{\"native_wait_for_pause\":true,\"owner_only_pipe\":true,\"overlapped_pipe\":true,\"remote_clients\":false}}\n",
      BRIDGE_PROTOCOL_VERSION, BRIDGE_PLUGIN_VERSION, (int)g_getstatus(),
      g_last_pause_reason, g_last_pause_reasonex, (ulong)g_last_pause_eip,
      InterlockedCompareExchange(&g_pause_sequence, 0, 0));
}

static void handle_wait_for_pause(const char *json, char *out, size_t out_size) {
  int after_sequence = (int)InterlockedCompareExchange(&g_pause_sequence, 0, 0);
  int timeout_ms = 5000;
  DWORD started = GetTickCount();
  HANDLE waits[2];
  extract_int_field(json, "after_sequence", &after_sequence);
  extract_int_field(json, "timeout_ms", &timeout_ms);
  if (after_sequence < 0 || timeout_ms <= 0 || timeout_ms > 300000) {
    respond_error(out, out_size, "Invalid pause wait parameters"); return;
  }
  waits[0] = g_stop_event; waits[1] = g_pause_event;
  for (;;) {
    LONG seq = InterlockedCompareExchange(&g_pause_sequence, 0, 0);
    DWORD elapsed, wr;
    if (seq > after_sequence) { handle_status(out, out_size); return; }
    elapsed = GetTickCount() - started;
    if (elapsed >= (DWORD)timeout_ms) {
      snprintf(out, out_size, "{\"ok\":false,\"timed_out\":true,\"error\":\"Timed out waiting for OllyDbg to pause\",\"pause_sequence\":%ld}\n", seq); return;
    }
    wr = WaitForMultipleObjects(2, waits, FALSE, (DWORD)timeout_ms - elapsed);
    if (wr == WAIT_OBJECT_0) { respond_error(out, out_size, "Plugin is shutting down"); return; }
    if (wr == WAIT_TIMEOUT) {
      seq = InterlockedCompareExchange(&g_pause_sequence, 0, 0);
      snprintf(out, out_size, "{\"ok\":false,\"timed_out\":true,\"error\":\"Timed out waiting for OllyDbg to pause\",\"pause_sequence\":%ld}\n", seq); return;
    }
    if (wr != WAIT_OBJECT_0 + 1) { respond_error(out, out_size, "Pause wait failed"); return; }
  }
}
'''
s = rep(s, old, new, 'status')
s = rep(s,
'''  if (strcmp(command, "status") == 0) {
    handle_status(out, out_size);
  }
  else if (strcmp(command, "goto") == 0) {
''',
'''  if (strcmp(command, "status") == 0) {
    handle_status(out, out_size);
  }
  else if (strcmp(command, "wait_for_pause") == 0) {
    handle_wait_for_pause(json, out, out_size);
  }
  else if (strcmp(command, "goto") == 0) {
''', 'dispatch')
s = rep(s,
'''  g_exec_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_exec_request.done_event == NULL) {
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
  log_line("OllyBridge110 plugin loaded");
''',
'''  g_exec_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_exec_request.done_event == NULL) {
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
  g_pause_event = CreateEventA(NULL, FALSE, FALSE, NULL);
  if (g_pause_event == NULL) {
    CloseHandle(g_exec_request.done_event); g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window); g_command_window = NULL; return -1;
  }
  log_line("OllyBridge110 plugin loaded");
''', 'pause init')
s = rep(s, '  if (g_stop_event == NULL) {\n    CloseHandle(g_exec_request.done_event);\n',
'''  if (g_stop_event == NULL) {
    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
''', 'stop cleanup')
s = rep(s,
'''    CloseHandle(g_stop_event);
    g_stop_event = NULL;
    CloseHandle(g_exec_request.done_event);
''',
'''    CloseHandle(g_stop_event);
    g_stop_event = NULL;
    CloseHandle(g_pause_event); g_pause_event = NULL;
    CloseHandle(g_exec_request.done_event);
''', 'thread cleanup')
s = rep(s,
'''  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  return 0;
}

extc __declspec(dllexport) int cdecl _ODBG_Pausedex''',
'''  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  InterlockedIncrement(&g_pause_sequence);
  if (g_pause_event != NULL) SetEvent(g_pause_event);
  return 0;
}

extc __declspec(dllexport) int cdecl _ODBG_Pausedex''', 'paused')
s = rep(s,
'''  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  return 0;
}

extc __declspec(dllexport) void cdecl _ODBG_Plugindestroy''',
'''  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  InterlockedIncrement(&g_pause_sequence);
  if (g_pause_event != NULL) SetEvent(g_pause_event);
  return 0;
}

extc __declspec(dllexport) void cdecl _ODBG_Plugindestroy''', 'pausedex')
s = rep(s, '    WaitForSingleObject(g_pipe_thread, 1500);\n',
            '    WaitForSingleObject(g_pipe_thread, INFINITE);\n', 'shutdown wait')
s = rep(s, '  if (g_exec_request.done_event != NULL) {\n',
'''  if (g_pause_event != NULL) {
    CloseHandle(g_pause_event); g_pause_event = NULL;
  }
  if (g_exec_request.done_event != NULL) {
''', 'destroy pause')
P.write_text(s, encoding='utf-8', newline='\n')
