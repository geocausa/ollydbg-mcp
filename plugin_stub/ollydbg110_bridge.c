#define STRICT
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Plugin.h"

#define PIPE_NAME "\\\\.\\pipe\\OllyBridge110"
#define PIPE_BUFFER_SIZE 8192
#define OLLYBRIDGE_WINDOW_CLASS "OllyBridge110Window"
#define OLLYBRIDGE_WM_EXEC (WM_APP + 0x110)

typedef int (cdecl *fn_addtolist_t)(ulong addr, int highlight, const char *format, ...);
typedef void (cdecl *fn_setcpu_t)(ulong threadid, ulong asmaddr, ulong dumpaddr, ulong stackaddr, int mode);
typedef ulong (cdecl *fn_readmemory_t)(void *buf, ulong addr, ulong size, int mode);
typedef ulong (cdecl *fn_writememory_t)(void *buf, ulong addr, ulong size, int mode);
typedef ulong (cdecl *fn_disasm_t)(uchar *src, ulong srcsize, ulong srcip, uchar *srcdec, t_disasm *disasm, int disasmmode, ulong threadid);
typedef int (cdecl *fn_plugingetvalue_t)(int type);
typedef ulong (cdecl *fn_getcputhreadid_t)(void);
typedef t_thread *(cdecl *fn_findthread_t)(ulong threadid);
typedef t_memory *(cdecl *fn_findmemory_t)(ulong addr);
typedef t_module *(cdecl *fn_findmodule_t)(ulong addr);
typedef int (cdecl *fn_setbreakpoint_t)(ulong addr, ulong type, uchar cmd);
typedef void (cdecl *fn_deletebreakpoints_t)(ulong addr0, ulong addr1, int silent);
typedef int (cdecl *fn_sethardwarebreakpoint_t)(ulong addr, int size, int type);
typedef int (cdecl *fn_deletehardwarebreakpoint_t)(int index);
typedef int (cdecl *fn_insertname_t)(ulong addr, int type, char *name);
typedef int (cdecl *fn_go_t)(ulong threadid, ulong tilladdr, int stepmode, int givechance, int backupregs);
typedef t_status (cdecl *fn_getstatus_t)(void);
typedef int (cdecl *fn_suspendprocess_t)(int processevents);
typedef void (cdecl *fn_sendshortcut_t)(int where, ulong addr, int msg, int ctrl, int shift, int vkcode);

static HINSTANCE g_instance = NULL;
static HANDLE g_stop_event = NULL;
static HANDLE g_pipe_thread = NULL;
static volatile LONG g_running = 0;
static HWND g_command_window = NULL;
static volatile LONG g_last_pause_reason = 0;
static volatile LONG g_last_pause_reasonex = 0;
static volatile ULONG_PTR g_last_pause_eip = 0;
static t_hardbpoint g_hardware_breakpoints[4];
static int g_hardware_breakpoints_valid[4] = {0, 0, 0, 0};

enum {
  EXEC_NONE = 0,
  EXEC_RUN = 1,
  EXEC_STEP_IN = 2,
  EXEC_STEP_OVER = 3,
  EXEC_CONTINUE = 4
};

typedef struct t_exec_request {
  volatile LONG pending;
  int command;
  ulong address;
  int give_chance;
  int result;
  int debug_status;
  ulong thread_id;
  HANDLE done_event;
} t_exec_request;

static t_exec_request g_exec_request = {0};

static fn_addtolist_t g_addtolist = NULL;
static fn_setcpu_t g_setcpu = NULL;
static fn_readmemory_t g_readmemory = NULL;
static fn_writememory_t g_writememory = NULL;
static fn_disasm_t g_disasm = NULL;
static fn_plugingetvalue_t g_plugingetvalue = NULL;
static fn_getcputhreadid_t g_getcputhreadid = NULL;
static fn_findthread_t g_findthread = NULL;
static fn_findmemory_t g_findmemory = NULL;
static fn_findmodule_t g_findmodule = NULL;
static fn_setbreakpoint_t g_setbreakpoint = NULL;
static fn_deletebreakpoints_t g_deletebreakpoints = NULL;
static fn_sethardwarebreakpoint_t g_sethardwarebreakpoint = NULL;
static fn_deletehardwarebreakpoint_t g_deletehardwarebreakpoint = NULL;
static fn_insertname_t g_insertname = NULL;
static fn_go_t g_go = NULL;
static fn_getstatus_t g_getstatus = NULL;
static fn_suspendprocess_t g_suspendprocess = NULL;
static fn_sendshortcut_t g_sendshortcut = NULL;

static FARPROC resolve_export(const char *name) {
  HMODULE module = GetModuleHandleA("OLLYDBG.EXE");
  if (module == NULL) {
    return NULL;
  }
  return GetProcAddress(module, name);
}

static int bind_exports(void) {
  g_addtolist = (fn_addtolist_t)resolve_export("_Addtolist");
  g_setcpu = (fn_setcpu_t)resolve_export("_Setcpu");
  g_readmemory = (fn_readmemory_t)resolve_export("_Readmemory");
  g_writememory = (fn_writememory_t)resolve_export("_Writememory");
  g_disasm = (fn_disasm_t)resolve_export("_Disasm");
  g_plugingetvalue = (fn_plugingetvalue_t)resolve_export("_Plugingetvalue");
  g_getcputhreadid = (fn_getcputhreadid_t)resolve_export("_Getcputhreadid");
  g_findthread = (fn_findthread_t)resolve_export("_Findthread");
  g_findmemory = (fn_findmemory_t)resolve_export("_Findmemory");
  g_findmodule = (fn_findmodule_t)resolve_export("_Findmodule");
  g_setbreakpoint = (fn_setbreakpoint_t)resolve_export("_Setbreakpoint");
  g_deletebreakpoints = (fn_deletebreakpoints_t)resolve_export("_Deletebreakpoints");
  g_sethardwarebreakpoint = (fn_sethardwarebreakpoint_t)resolve_export("_Sethardwarebreakpoint");
  g_deletehardwarebreakpoint = (fn_deletehardwarebreakpoint_t)resolve_export("_Deletehardwarebreakpoint");
  g_insertname = (fn_insertname_t)resolve_export("_Insertname");
  g_go = (fn_go_t)resolve_export("_Go");
  g_getstatus = (fn_getstatus_t)resolve_export("_Getstatus");
  g_suspendprocess = (fn_suspendprocess_t)resolve_export("_Suspendprocess");
  g_sendshortcut = (fn_sendshortcut_t)resolve_export("_Sendshortcut");
  return g_addtolist != NULL && g_setcpu != NULL && g_readmemory != NULL &&
         g_writememory != NULL &&
         g_disasm != NULL && g_plugingetvalue != NULL &&
         g_getcputhreadid != NULL && g_findthread != NULL &&
         g_findmemory != NULL && g_findmodule != NULL &&
         g_setbreakpoint != NULL && g_deletebreakpoints != NULL &&
         g_sethardwarebreakpoint != NULL && g_deletehardwarebreakpoint != NULL &&
         g_insertname != NULL && g_go != NULL && g_getstatus != NULL &&
         g_suspendprocess != NULL && g_sendshortcut != NULL;
}

static void log_line(const char *text) {
  if (g_addtolist != NULL) {
    g_addtolist(0, 0, "%s", text);
  }
}

static void dispatch_main_key(int vkcode) {
  HWND main_window = (HWND)(ULONG_PTR)g_plugingetvalue(VAL_HWMAIN);
  if (main_window != NULL) {
    PostMessageA(main_window, WM_KEYDOWN, (WPARAM)vkcode, 0);
    PostMessageA(main_window, WM_KEYUP, (WPARAM)vkcode, 0);
  }
  g_sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 0, vkcode);
}

static LRESULT CALLBACK ollybridge_window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
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

static void json_escape_append(char *out, size_t out_size, size_t *used, const char *src) {
  while (*src != '\0' && *used + 2 < out_size) {
    char ch = *src++;
    if (ch == '\\' || ch == '"') {
      if (*used + 2 >= out_size) {
        return;
      }
      out[(*used)++] = '\\';
      out[(*used)++] = ch;
    }
    else if (ch == '\r' || ch == '\n') {
      if (*used + 2 >= out_size) {
        return;
      }
      out[(*used)++] = '\\';
      out[(*used)++] = 'n';
    }
    else if ((unsigned char)ch < 0x20) {
      out[(*used)++] = ' ';
    }
    else {
      out[(*used)++] = ch;
    }
  }
  out[*used] = '\0';
}

static int parse_hex_value(const char *text, unsigned long *value) {
  char *end_ptr = NULL;
  unsigned long parsed;
  if (text == NULL) {
    return 0;
  }
  while (*text == ' ' || *text == '\t' || *text == '"' || *text == ':') {
    text++;
  }
  if (*text == '0' && (text[1] == 'x' || text[1] == 'X')) {
    text += 2;
  }
  parsed = strtoul(text, &end_ptr, 16);
  if (end_ptr == text) {
    return 0;
  }
  *value = parsed;
  return 1;
}

static int parse_hex_bytes(const char *text, unsigned char *out, int max_bytes) {
  int count = 0;
  int high_nibble = -1;
  while (*text != '\0' && count < max_bytes) {
    int value = -1;
    char ch = *text++;
    if (ch >= '0' && ch <= '9') value = ch - '0';
    else if (ch >= 'a' && ch <= 'f') value = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') value = ch - 'A' + 10;
    else continue;
    if (high_nibble < 0) {
      high_nibble = value;
    }
    else {
      out[count++] = (unsigned char)((high_nibble << 4) | value);
      high_nibble = -1;
    }
  }
  if (high_nibble >= 0) {
    return -1;
  }
  return count;
}

static int extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
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

static int extract_int_field(const char *json, const char *field, int *value) {
  char needle[64];
  const char *start;
  char *end_ptr = NULL;

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
  *value = (int)strtol(start, &end_ptr, 10);
  return end_ptr != start;
}

static int extract_bool_field(const char *json, const char *field, int *value) {
  char needle[64];
  const char *start;
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
  if (strncmp(start, "true", 4) == 0) {
    *value = 1;
    return 1;
  }
  if (strncmp(start, "false", 5) == 0) {
    *value = 0;
    return 1;
  }
  return 0;
}

static void respond_error(char *out, size_t out_size, const char *message) {
  char escaped[512];
  size_t used = 0;
  escaped[0] = '\0';
  json_escape_append(escaped, sizeof(escaped), &used, message);
  snprintf(out, out_size, "{\"ok\":false,\"error\":\"%s\"}\n", escaped);
}

static void respond_stateful_error(char *out, size_t out_size, const char *message) {
  char escaped[512];
  size_t used = 0;
  escaped[0] = '\0';
  json_escape_append(escaped, sizeof(escaped), &used, message);
  snprintf(
      out,
      out_size,
      "{\"ok\":false,\"error\":\"%s\",\"debug_status\":%d,\"cpu_thread_id\":\"0x%08lX\",\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\"}\n",
      escaped,
      (int)g_getstatus(),
      g_getcputhreadid(),
      g_last_pause_reason,
      g_last_pause_reasonex,
      (ulong)g_last_pause_eip);
}

static void handle_status(char *out, size_t out_size) {
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"pipe\":\"\\\\\\\\.\\\\pipe\\\\OllyBridge110\",\"debug_status\":%d,\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\"}\n",
      (int)g_getstatus(),
      g_last_pause_reason,
      g_last_pause_reasonex,
      (ulong)g_last_pause_eip);
}

static void handle_goto(const char *json, char *out, size_t out_size) {
  char address_text[64];
  unsigned long address;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  g_setcpu(0, address, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS);
  snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\"}\n", address);
}

static void handle_read_memory(const char *json, char *out, size_t out_size) {
  char address_text[64];
  unsigned long address;
  int size = 0;
  unsigned char *buffer;
  unsigned long read;
  int index;
  size_t used = 0;

  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  if (!extract_int_field(json, "size", &size) || size <= 0 || size > 1024) {
    respond_error(out, out_size, "Missing or invalid size");
    return;
  }

  buffer = (unsigned char *)malloc((size_t)size);
  if (buffer == NULL) {
    respond_error(out, out_size, "Allocation failed");
    return;
  }
  read = g_readmemory(buffer, address, (ulong)size, MM_RESTORE | MM_SILENT);
  if (read == 0) {
    free(buffer);
    respond_error(out, out_size, "Readmemory returned zero bytes");
    return;
  }

  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\",\"size\":%lu,\"hex\":\"", address, read);
  for (index = 0; index < (int)read && used + 2 < out_size; index++) {
    used += (size_t)snprintf(out + used, out_size - used, "%02X", buffer[index]);
  }
  snprintf(out + used, out_size - used, "\"}\n");
  free(buffer);
}

static void handle_disasm(const char *json, char *out, size_t out_size) {
  char address_text[64];
  unsigned long address;
  int count = 0;
  int line_index;
  size_t used = 0;

  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  if (!extract_int_field(json, "count", &count) || count <= 0 || count > 32) {
    respond_error(out, out_size, "Missing or invalid count");
    return;
  }

  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\",\"lines\":[", address);
  for (line_index = 0; line_index < count && used + 128 < out_size; line_index++) {
    unsigned char bytes[16];
    t_disasm disasm;
    unsigned long read = g_readmemory(bytes, address, sizeof(bytes), MM_RESTORE | MM_SILENT);
    unsigned long size;
    char escaped[TEXTLEN * 2];
    size_t escaped_used = 0;

    if (read == 0) {
      break;
    }
    memset(&disasm, 0, sizeof(disasm));
    size = g_disasm(bytes, read, address, NULL, &disasm, DISASM_ALL, 0);
    if (size == 0) {
      size = 1;
    }
    escaped[0] = '\0';
    json_escape_append(escaped, sizeof(escaped), &escaped_used, disasm.result);
    used += (size_t)snprintf(
        out + used,
        out_size - used,
        "%s{\"address\":\"0x%08lX\",\"instruction\":\"%s\",\"size\":%lu}",
        line_index == 0 ? "" : ",",
        address,
        escaped,
        size);
    address += size;
  }
  snprintf(out + used, out_size - used, "]}\n");
}

static void handle_registers(char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  t_reg *reg;
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  reg = &thread->reg;
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"registers\":{\"eax\":\"0x%08lX\",\"ecx\":\"0x%08lX\",\"edx\":\"0x%08lX\","
      "\"ebx\":\"0x%08lX\",\"esp\":\"0x%08lX\",\"ebp\":\"0x%08lX\",\"esi\":\"0x%08lX\","
      "\"edi\":\"0x%08lX\",\"eip\":\"0x%08lX\"}}\n",
      reg->r[REG_EAX], reg->r[REG_ECX], reg->r[REG_EDX], reg->r[REG_EBX],
      reg->r[REG_ESP], reg->r[REG_EBP], reg->r[REG_ESI], reg->r[REG_EDI], reg->ip);
}

static void handle_get_eip(char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  snprintf(out, out_size, "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"eip\":\"0x%08lX\"}\n", thread_id, thread->reg.ip);
}

static void handle_current_instruction(char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  {
    char nested_request[128];
    char nested_response[PIPE_BUFFER_SIZE];
    snprintf(nested_request, sizeof(nested_request), "{\"address\":\"0x%08lX\",\"count\":1}", thread->reg.ip);
    handle_disasm(nested_request, nested_response, sizeof(nested_response));
    if (strncmp(nested_response, "{\"ok\":true", 10) != 0) {
      strncpy(out, nested_response, out_size - 1);
      out[out_size - 1] = '\0';
      return;
    }
    snprintf(out, out_size, "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"eip\":\"0x%08lX\"%s", thread_id, thread->reg.ip, nested_response + 10);
  }
}

static void handle_goto_eip(char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  g_setcpu(0, thread->reg.ip, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS);
  snprintf(out, out_size, "{\"ok\":true,\"eip\":\"0x%08lX\"}\n", thread->reg.ip);
}

static void handle_read_stack(const char *json, char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  int size = 64;
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  extract_int_field(json, "size", &size);
  if (size <= 0 || size > 1024) {
    respond_error(out, out_size, "Missing or invalid size");
    return;
  }
  {
    char nested[PIPE_BUFFER_SIZE];
    char request[128];
    snprintf(request, sizeof(request), "{\"address\":\"0x%08lX\",\"size\":%d}", thread->reg.r[REG_ESP], size);
    handle_read_memory(request, nested, sizeof(nested));
    if (strncmp(nested, "{\"ok\":true", 10) != 0) {
      strncpy(out, nested, out_size - 1);
      out[out_size - 1] = '\0';
      return;
    }
    {
      char *insert = strstr(nested, "\"address\":");
      if (insert != NULL) {
        snprintf(out, out_size, "{\"ok\":true,\"esp\":\"0x%08lX\",%s", thread->reg.r[REG_ESP], insert);
      }
      else {
        respond_error(out, out_size, "Unexpected stack read response");
      }
    }
  }
}

static void handle_disasm_from_stack(const char *json, char *out, size_t out_size) {
  ulong thread_id = g_getcputhreadid();
  t_thread *thread = g_findthread(thread_id);
  int offset = 0;
  int count = 8;
  ulong target = 0;
  if (thread == NULL) {
    respond_error(out, out_size, "Current CPU thread is not available");
    return;
  }
  extract_int_field(json, "offset", &offset);
  extract_int_field(json, "count", &count);
  if (count <= 0 || count > 32) {
    respond_error(out, out_size, "Missing or invalid count");
    return;
  }
  if (g_readmemory(&target, thread->reg.r[REG_ESP] + (ulong)offset, sizeof(target), MM_RESTORE | MM_SILENT) != sizeof(target)) {
    respond_error(out, out_size, "Unable to read target pointer from stack");
    return;
  }
  {
    char nested_request[128];
    char nested_response[PIPE_BUFFER_SIZE];
    snprintf(nested_request, sizeof(nested_request), "{\"address\":\"0x%08lX\",\"count\":%d}", target, count);
    handle_disasm(nested_request, nested_response, sizeof(nested_response));
    if (strncmp(nested_response, "{\"ok\":true", 10) != 0) {
      strncpy(out, nested_response, out_size - 1);
      out[out_size - 1] = '\0';
      return;
    }
    {
      char *insert = strstr(nested_response, "\"address\":");
      if (insert != NULL) {
        snprintf(out, out_size, "{\"ok\":true,\"esp\":\"0x%08lX\",\"offset\":%d,\"target\":\"0x%08lX\",%s", thread->reg.r[REG_ESP], offset, target, insert);
      }
      else {
        respond_error(out, out_size, "Unexpected stack disassembly response");
      }
    }
  }
}

static void handle_set_breakpoint(const char *json, char *out, size_t out_size) {
  char address_text[64];
  unsigned long address;
  int result;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  result = g_setbreakpoint(address, TY_ACTIVE, 0);
  if (result != 0) {
    respond_error(out, out_size, "Setbreakpoint failed");
    return;
  }
  snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\"}\n", address);
}

static void handle_clear_breakpoint(const char *json, char *out, size_t out_size) {
  char address_text[64];
  unsigned long address;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  g_deletebreakpoints(address, address + 1, 1);
  snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\"}\n", address);
}

static int parse_hwbp_type(const char *text) {
  if (_stricmp(text, "execute") == 0) {
    return HB_CODE;
  }
  if (_stricmp(text, "access") == 0) {
    return HB_ACCESS;
  }
  if (_stricmp(text, "write") == 0) {
    return HB_WRITE;
  }
  return 0;
}

static void handle_set_hardware_breakpoint(const char *json, char *out, size_t out_size) {
  char address_text[64];
  char type_text[32];
  unsigned long address;
  int size = 1;
  int slot = -1;
  int type;
  int result;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  if (!extract_string_field(json, "type", type_text, sizeof(type_text))) {
    strncpy(type_text, "execute", sizeof(type_text) - 1);
    type_text[sizeof(type_text) - 1] = '\0';
  }
  extract_int_field(json, "size", &size);
  if (!(size == 1 || size == 2 || size == 4)) {
    respond_error(out, out_size, "Hardware breakpoint size must be 1, 2 or 4");
    return;
  }
  type = parse_hwbp_type(type_text);
  if (type == 0) {
    respond_error(out, out_size, "Hardware breakpoint type must be execute, access, or write");
    return;
  }
  result = g_sethardwarebreakpoint(address, size, type);
  if (result != 0) {
    respond_error(out, out_size, "Sethardwarebreakpoint failed");
    return;
  }
  for (slot = 0; slot < 4; slot++) {
    if (!g_hardware_breakpoints_valid[slot]) {
      g_hardware_breakpoints[slot].addr = address;
      g_hardware_breakpoints[slot].size = size;
      g_hardware_breakpoints[slot].type = type;
      g_hardware_breakpoints_valid[slot] = 1;
      break;
    }
  }
  snprintf(out, out_size, "{\"ok\":true,\"index\":%d,\"address\":\"0x%08lX\",\"size\":%d,\"type\":\"%s\"}\n", slot, address, size, type_text);
}

static void handle_clear_hardware_breakpoint(const char *json, char *out, size_t out_size) {
  int index = -1;
  if (!extract_int_field(json, "index", &index) || index < 0) {
    respond_error(out, out_size, "Missing or invalid hardware breakpoint index");
    return;
  }
  if (g_deletehardwarebreakpoint(index) != 0) {
    respond_error(out, out_size, "Deletehardwarebreakpoint failed");
    return;
  }
  if (index >= 0 && index < 4) {
    g_hardware_breakpoints_valid[index] = 0;
    memset(&g_hardware_breakpoints[index], 0, sizeof(g_hardware_breakpoints[index]));
  }
  snprintf(out, out_size, "{\"ok\":true,\"index\":%d}\n", index);
}

static void handle_list_hardware_breakpoints(char *out, size_t out_size) {
  size_t used = 0;
  int first = 1;
  int index;
  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"breakpoints\":[");
  for (index = 0; index < 4 && used + 128 < out_size; index++) {
    if (!g_hardware_breakpoints_valid[index]) {
      continue;
    }
    used += (size_t)snprintf(
        out + used,
        out_size - used,
        "%s{\"index\":%d,\"address\":\"0x%08lX\",\"size\":%d,\"type\":%d}",
        first ? "" : ",",
        index,
        g_hardware_breakpoints[index].addr,
        g_hardware_breakpoints[index].size,
        g_hardware_breakpoints[index].type);
    first = 0;
  }
  snprintf(out + used, out_size - used, "]}\n");
}

static void handle_write_memory(const char *json, char *out, size_t out_size) {
  char address_text[64];
  char hex_text[2048];
  unsigned long address;
  unsigned char bytes[1024];
  int count;
  ulong written;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  if (!extract_string_field(json, "hex", hex_text, sizeof(hex_text))) {
    respond_error(out, out_size, "Missing hex");
    return;
  }
  count = parse_hex_bytes(hex_text, bytes, (int)(sizeof(bytes)));
  if (count <= 0) {
    respond_error(out, out_size, "Invalid hex payload");
    return;
  }
  written = g_writememory(bytes, address, (ulong)count, MM_RESTORE | MM_SILENT | MM_DELANAL);
  if (written != (ulong)count) {
    respond_error(out, out_size, "Writememory wrote fewer bytes than requested");
    return;
  }
  snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\",\"size\":%d}\n", address, count);
}

static void handle_lookup_address(const char *json, char *out, size_t out_size) {
  char address_text[64];
  char module_name[SHORTLEN + 1];
  char module_name_escaped[(SHORTLEN * 2) + 2];
  unsigned long address;
  t_memory *memory;
  t_module *module;
  char path_escaped[MAX_PATH * 2];
  char sect_escaped[SHORTLEN * 2];
  size_t module_name_used = 0;
  size_t path_used = 0;
  size_t sect_used = 0;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  memory = g_findmemory(address);
  module = g_findmodule(address);
  memset(module_name, 0, sizeof(module_name));
  path_escaped[0] = '\0';
  sect_escaped[0] = '\0';
  module_name_escaped[0] = '\0';
  if (module != NULL) {
    memcpy(module_name, module->name, SHORTLEN);
    module_name[SHORTLEN] = '\0';
    json_escape_append(module_name_escaped, sizeof(module_name_escaped), &module_name_used, module_name);
  }
  if (module != NULL) json_escape_append(path_escaped, sizeof(path_escaped), &path_used, module->path);
  if (memory != NULL) json_escape_append(sect_escaped, sizeof(sect_escaped), &sect_used, memory->sect);
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"address\":\"0x%08lX\",\"memory\":{\"present\":%s,\"base\":\"0x%08lX\",\"size\":\"0x%08lX\",\"type\":\"0x%08lX\",\"access\":\"0x%08lX\",\"section\":\"%s\"},\"module\":{\"present\":%s,\"base\":\"0x%08lX\",\"size\":\"0x%08lX\",\"name\":\"%s\",\"path\":\"%s\",\"entry\":\"0x%08lX\",\"codebase\":\"0x%08lX\",\"codesize\":\"0x%08lX\"}}\n",
      address,
      memory != NULL ? "true" : "false",
      memory != NULL ? memory->base : 0,
      memory != NULL ? memory->size : 0,
      memory != NULL ? memory->type : 0,
      memory != NULL ? memory->access : 0,
      memory != NULL ? sect_escaped : "",
      module != NULL ? "true" : "false",
      module != NULL ? module->base : 0,
      module != NULL ? module->size : 0,
      module != NULL ? module_name_escaped : "",
      module != NULL ? path_escaped : "",
      module != NULL ? module->entry : 0,
      module != NULL ? module->codebase : 0,
      module != NULL ? module->codesize : 0);
}

static void handle_list_breakpoints(char *out, size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_BREAKPOINTS);
  size_t used = 0;
  int index;
  if (table == NULL) {
    respond_error(out, out_size, "Breakpoint table is not available");
    return;
  }
  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"count\":%d,\"breakpoints\":[", table->data.n);
  for (index = 0; index < table->data.n && used + 128 < out_size; index++) {
    t_bpoint *bp = (t_bpoint *)((char *)table->data.data + (table->data.itemsize * index));
    used += (size_t)snprintf(
        out + used,
        out_size - used,
        "%s{\"index\":%d,\"address\":\"0x%08lX\",\"type\":\"0x%08lX\",\"cmd\":\"0x%02X\",\"passcount\":%lu}",
        index == 0 ? "" : ",",
        index,
        bp->addr,
        bp->type,
        (unsigned char)bp->cmd,
        bp->passcount);
  }
  snprintf(out + used, out_size - used, "]}\n");
}

static void handle_list_modules(char *out, size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_MODULES);
  size_t used = 0;
  int index;
  if (table == NULL) {
    respond_error(out, out_size, "Module table is not available");
    return;
  }
  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"count\":%d,\"modules\":[", table->data.n);
  for (index = 0; index < table->data.n && used + 256 < out_size; index++) {
    t_module *mod = (t_module *)((char *)table->data.data + (table->data.itemsize * index));
    char name[SHORTLEN + 1];
    char path[MAX_PATH + 1];
    char name_escaped[(SHORTLEN * 2) + 2];
    char path_escaped[(MAX_PATH * 2) + 2];
    size_t name_used = 0;
    size_t path_used = 0;
    memset(name, 0, sizeof(name));
    memset(path, 0, sizeof(path));
    memcpy(name, mod->name, SHORTLEN);
    memcpy(path, mod->path, MAX_PATH);
    name_escaped[0] = '\0';
    path_escaped[0] = '\0';
    json_escape_append(name_escaped, sizeof(name_escaped), &name_used, name);
    json_escape_append(path_escaped, sizeof(path_escaped), &path_used, path);
    used += (size_t)snprintf(
        out + used,
        out_size - used,
        "%s{\"index\":%d,\"name\":\"%s\",\"path\":\"%s\",\"base\":\"0x%08lX\",\"size\":\"0x%08lX\",\"entry\":\"0x%08lX\"}",
        index == 0 ? "" : ",",
        index,
        name_escaped,
        path_escaped,
        mod->base,
        mod->size,
        mod->entry);
  }
  snprintf(out + used, out_size - used, "]}\n");
}

static void handle_list_threads(char *out, size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_THREADS);
  ulong cpu_thread_id = g_getcputhreadid();
  size_t used = 0;
  int index;
  if (table == NULL) {
    respond_error(out, out_size, "Thread table is not available");
    return;
  }
  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"count\":%d,\"cpu_thread_id\":\"0x%08lX\",\"threads\":[", table->data.n, cpu_thread_id);
  for (index = 0; index < table->data.n && used + 256 < out_size; index++) {
    t_thread *thr = (t_thread *)((char *)table->data.data + (table->data.itemsize * index));
    used += (size_t)snprintf(
        out + used,
        out_size - used,
        "%s{\"index\":%d,\"thread_id\":\"0x%08lX\",\"entry\":\"0x%08lX\",\"stacktop\":\"0x%08lX\",\"stackbottom\":\"0x%08lX\",\"suspendcount\":%d,\"regvalid\":%s,\"eip\":\"0x%08lX\"}",
        index == 0 ? "" : ",",
        index,
        thr->threadid,
        thr->entry,
        thr->stacktop,
        thr->stackbottom,
        thr->suspendcount,
        thr->regvalid ? "true" : "false",
        thr->reg.ip);
  }
  snprintf(out + used, out_size - used, "]}\n");
}

static void handle_set_name(const char *json, char *out, size_t out_size, int name_type) {
  char address_text[64];
  char text[TEXTLEN];
  unsigned long address;
  if (!extract_string_field(json, "address", address_text, sizeof(address_text)) ||
      !parse_hex_value(address_text, &address)) {
    respond_error(out, out_size, "Missing or invalid address");
    return;
  }
  if (!extract_string_field(json, "text", text, sizeof(text))) {
    respond_error(out, out_size, "Missing text");
    return;
  }
  if (g_insertname(address, name_type, text) == 0) {
    respond_error(out, out_size, "Insertname failed");
    return;
  }
  snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\",\"text\":\"", address);
  {
    size_t used = strlen(out);
    json_escape_append(out, out_size, &used, text);
    snprintf(out + used, out_size - used, "\"}\n");
  }
}

static void handle_go_command(const char *json, char *out, size_t out_size, int stepmode) {
  char address_text[64];
  unsigned long address = 0;
  int give_chance = 0;
  if (extract_string_field(json, "address", address_text, sizeof(address_text))) {
    if (!parse_hex_value(address_text, &address)) {
      respond_error(out, out_size, "Invalid address");
      return;
    }
  }
  if (!extract_bool_field(json, "give_chance", &give_chance)) {
    extract_bool_field(json, "restore_int3", &give_chance);
  }
  if (execute_on_ui_thread(EXEC_RUN, address, give_chance) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread run dispatch failed");
    return;
  }
  if (g_exec_request.result != 0) {
    respond_stateful_error(out, out_size, "Go failed");
    return;
  }
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"stepmode\":%d,\"address\":\"0x%08lX\",\"give_chance\":%d,\"debug_status\":%d}\n",
      g_exec_request.thread_id,
      stepmode,
      address,
      give_chance,
      g_exec_request.debug_status);
}

static void handle_step_shortcut(char *out, size_t out_size, int vkcode, int stepmode) {
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

static void handle_continue(char *out, size_t out_size) {
  if (execute_on_ui_thread(EXEC_CONTINUE, 0, 0) != WAIT_OBJECT_0) {
    respond_stateful_error(out, out_size, "UI-thread continue dispatch failed");
    return;
  }
  snprintf(
      out,
      out_size,
      "{\"ok\":true,\"thread_id\":\"0x%08lX\",\"debug_status\":%d}\n",
      g_exec_request.thread_id,
      g_exec_request.debug_status);
}

static void handle_pause(char *out, size_t out_size) {
  if (g_suspendprocess(0) != 0) {
    respond_stateful_error(out, out_size, "Suspendprocess failed");
    return;
  }
  snprintf(out, out_size, "{\"ok\":true,\"debug_status\":%d}\n", (int)g_getstatus());
}

static void dispatch_request(const char *json, char *out, size_t out_size) {
  char command[64];
  if (!extract_string_field(json, "command", command, sizeof(command))) {
    respond_error(out, out_size, "Missing command");
    return;
  }
  if (strcmp(command, "status") == 0) {
    handle_status(out, out_size);
  }
  else if (strcmp(command, "goto") == 0) {
    handle_goto(json, out, out_size);
  }
  else if (strcmp(command, "read_memory") == 0) {
    handle_read_memory(json, out, out_size);
  }
  else if (strcmp(command, "read_disasm") == 0) {
    handle_disasm(json, out, out_size);
  }
  else if (strcmp(command, "get_registers") == 0) {
    handle_registers(out, out_size);
  }
  else if (strcmp(command, "get_eip") == 0) {
    handle_get_eip(out, out_size);
  }
  else if (strcmp(command, "current_instruction") == 0) {
    handle_current_instruction(out, out_size);
  }
  else if (strcmp(command, "goto_eip") == 0) {
    handle_goto_eip(out, out_size);
  }
  else if (strcmp(command, "read_stack") == 0) {
    handle_read_stack(json, out, out_size);
  }
  else if (strcmp(command, "disasm_from_stack") == 0) {
    handle_disasm_from_stack(json, out, out_size);
  }
  else if (strcmp(command, "write_memory") == 0) {
    handle_write_memory(json, out, out_size);
  }
  else if (strcmp(command, "lookup_address") == 0) {
    handle_lookup_address(json, out, out_size);
  }
  else if (strcmp(command, "list_breakpoints") == 0) {
    handle_list_breakpoints(out, out_size);
  }
  else if (strcmp(command, "list_modules") == 0) {
    handle_list_modules(out, out_size);
  }
  else if (strcmp(command, "list_threads") == 0) {
    handle_list_threads(out, out_size);
  }
  else if (strcmp(command, "set_breakpoint") == 0) {
    handle_set_breakpoint(json, out, out_size);
  }
  else if (strcmp(command, "clear_breakpoint") == 0) {
    handle_clear_breakpoint(json, out, out_size);
  }
  else if (strcmp(command, "set_hardware_breakpoint") == 0) {
    handle_set_hardware_breakpoint(json, out, out_size);
  }
  else if (strcmp(command, "clear_hardware_breakpoint") == 0) {
    handle_clear_hardware_breakpoint(json, out, out_size);
  }
  else if (strcmp(command, "list_hardware_breakpoints") == 0) {
    handle_list_hardware_breakpoints(out, out_size);
  }
  else if (strcmp(command, "set_label") == 0) {
    handle_set_name(json, out, out_size, NM_LABEL);
  }
  else if (strcmp(command, "set_comment") == 0) {
    handle_set_name(json, out, out_size, NM_COMMENT);
  }
  else if (strcmp(command, "run") == 0) {
    handle_go_command(json, out, out_size, STEP_RUN);
  }
  else if (strcmp(command, "step_into") == 0) {
    handle_step_shortcut(out, out_size, VK_F7, STEP_IN);
  }
  else if (strcmp(command, "step_over") == 0) {
    handle_step_shortcut(out, out_size, VK_F8, STEP_OVER);
  }
  else if (strcmp(command, "pause") == 0) {
    handle_pause(out, out_size);
  }
  else if (strcmp(command, "continue") == 0) {
    handle_continue(out, out_size);
  }
  else {
    respond_error(out, out_size, "Unknown command");
  }
}

static DWORD WINAPI pipe_thread_main(LPVOID param) {
  (void)param;
  InterlockedExchange(&g_running, 1);
  while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
    HANDLE pipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        250,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
      Sleep(250);
      continue;
    }

    if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
      char request[PIPE_BUFFER_SIZE];
      char response[PIPE_BUFFER_SIZE];
      DWORD read = 0;
      DWORD written = 0;
      ZeroMemory(request, sizeof(request));
      ZeroMemory(response, sizeof(response));
      if (ReadFile(pipe, request, sizeof(request) - 1, &read, NULL) && read > 0) {
        request[read] = '\0';
        dispatch_request(request, response, sizeof(response));
      }
      else {
        respond_error(response, sizeof(response), "Failed to read from pipe");
      }
      WriteFile(pipe, response, (DWORD)strlen(response), &written, NULL);
      FlushFileBuffers(pipe);
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
  InterlockedExchange(&g_running, 0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    g_instance = instance;
  }
  return TRUE;
}

extc __declspec(dllexport) int cdecl _ODBG_Plugindata(char shortname[32]) {
  lstrcpynA(shortname, "OllyBridge110", 32);
  return PLUGIN_VERSION;
}

extc __declspec(dllexport) int cdecl _ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features) {
  (void)hw;
  (void)features;
  WNDCLASSA window_class;
  if (ollydbgversion < PLUGIN_VERSION) {
    return -1;
  }
  if (!bind_exports()) {
    return -1;
  }
  ZeroMemory(&window_class, sizeof(window_class));
  window_class.lpfnWndProc = ollybridge_window_proc;
  window_class.hInstance = g_instance;
  window_class.lpszClassName = OLLYBRIDGE_WINDOW_CLASS;
  RegisterClassA(&window_class);
  g_command_window = CreateWindowExA(
      0,
      OLLYBRIDGE_WINDOW_CLASS,
      "OllyBridge110",
      0,
      0,
      0,
      0,
      0,
      HWND_MESSAGE,
      NULL,
      g_instance,
      NULL);
  if (g_command_window == NULL) {
    return -1;
  }
  g_exec_request.done_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_exec_request.done_event == NULL) {
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
  log_line("OllyBridge110 plugin loaded");
  log_line("  Named pipe: \\\\.\\pipe\\OllyBridge110");
  g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
  if (g_stop_event == NULL) {
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
  g_pipe_thread = CreateThread(NULL, 0, pipe_thread_main, NULL, 0, NULL);
  if (g_pipe_thread == NULL) {
    CloseHandle(g_stop_event);
    g_stop_event = NULL;
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
    DestroyWindow(g_command_window);
    g_command_window = NULL;
    return -1;
  }
  return 0;
}

extc __declspec(dllexport) int cdecl _ODBG_Pluginmenu(int origin, char data[4096], void *item) {
  (void)item;
  if (origin != PM_MAIN) {
    return 0;
  }
  strcpy(data, "0 &Bridge status");
  return 1;
}

extc __declspec(dllexport) void cdecl _ODBG_Pluginaction(int origin, int action, void *item) {
  (void)item;
  if (origin == PM_MAIN && action == 0) {
    char message[256];
    snprintf(message, sizeof(message), "OllyBridge110: %s", InterlockedCompareExchange(&g_running, 0, 0) ? "pipe thread running" : "pipe thread stopped");
    log_line(message);
  }
}

extc __declspec(dllexport) int cdecl _ODBG_Pluginclose(void) {
  return 0;
}

extc __declspec(dllexport) int cdecl _ODBG_Paused(int reason, t_reg *reg) {
  g_last_pause_reason = reason;
  g_last_pause_reasonex = reason;
  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  return 0;
}

extc __declspec(dllexport) int cdecl _ODBG_Pausedex(int reasonex, int dummy, t_reg *reg, DEBUG_EVENT *debugevent) {
  (void)dummy;
  (void)debugevent;
  g_last_pause_reason = (reasonex & PP_MAIN);
  g_last_pause_reasonex = reasonex;
  g_last_pause_eip = (reg != NULL) ? reg->ip : 0;
  return 0;
}

extc __declspec(dllexport) void cdecl _ODBG_Plugindestroy(void) {
  if (g_stop_event != NULL) {
    SetEvent(g_stop_event);
  }
  if (g_pipe_thread != NULL) {
    WaitForSingleObject(g_pipe_thread, 1500);
    CloseHandle(g_pipe_thread);
    g_pipe_thread = NULL;
  }
  if (g_stop_event != NULL) {
    CloseHandle(g_stop_event);
    g_stop_event = NULL;
  }
  if (g_exec_request.done_event != NULL) {
    CloseHandle(g_exec_request.done_event);
    g_exec_request.done_event = NULL;
  }
  if (g_command_window != NULL) {
    DestroyWindow(g_command_window);
    g_command_window = NULL;
  }
  UnregisterClassA(OLLYBRIDGE_WINDOW_CLASS, g_instance);
}
