from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin_stub" / "ollydbg110_bridge.c"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


text = PLUGIN.read_text(encoding="utf-8")
text = replace_once(
    text,
    '#define BRIDGE_PLUGIN_VERSION "2.3"',
    '#define BRIDGE_PLUGIN_VERSION "2.4"',
    "plugin version",
)
text = replace_once(
    text,
    "static volatile LONG g_pause_sequence = 0;\nstatic t_hardbpoint",
    "static volatile LONG g_pause_sequence = 0;\n"
    "static volatile LONG g_mutations_enabled = 0;\n"
    "static t_hardbpoint",
    "mutation state",
)
helpers = r'''static int text_equals_ignore_case(const char *left, const char *right) {
  unsigned char left_char;
  unsigned char right_char;
  if (left == NULL || right == NULL) return 0;
  while (*left != '\0' && *right != '\0') {
    left_char = (unsigned char)*left;
    right_char = (unsigned char)*right;
    if (tolower(left_char) != tolower(right_char)) return 0;
    left++;
    right++;
  }
  return *left == '\0' && *right == '\0';
}

static int environment_truthy(const char *name) {
  char value[16];
  DWORD length;
  if (name == NULL) return 0;
  length = GetEnvironmentVariableA(name, value, (DWORD)sizeof(value));
  if (length == 0 || length >= sizeof(value)) return 0;
  value[length] = '\0';
  return strcmp(value, "1") == 0 ||
         text_equals_ignore_case(value, "true") ||
         text_equals_ignore_case(value, "yes") ||
         text_equals_ignore_case(value, "on");
}

static int command_requires_mutation(const char *command) {
  if (command == NULL) return 0;
  return strcmp(command, "write_memory") == 0 ||
         strcmp(command, "set_breakpoint") == 0 ||
         strcmp(command, "clear_breakpoint") == 0 ||
         strcmp(command, "set_hardware_breakpoint") == 0 ||
         strcmp(command, "clear_hardware_breakpoint") == 0 ||
         strcmp(command, "set_label") == 0 ||
         strcmp(command, "set_comment") == 0;
}

'''
text = replace_once(
    text,
    "static void respond_error(char *out, size_t out_size, const char *message) {",
    helpers + "static void respond_error(char *out, size_t out_size, const char *message) {",
    "mutation helpers",
)
old_status = r'''static void handle_status(char *out, size_t out_size) {
  snprintf(out, out_size,
      "{\"ok\":true,\"protocol_version\":%d,\"plugin_version\":\"%s\",\"pipe\":\"\\\\\\\\.\\\\pipe\\\\OllyBridge110\",\"debug_status\":%d,\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\",\"pause_sequence\":%ld,\"capabilities\":{\"native_wait_for_pause\":true,\"owner_only_pipe\":true,\"overlapped_pipe\":true,\"ui_thread_dispatch\":true,\"bounded_json_parser\":true,\"paged_tables\":true,\"client_drain_wait\":true,\"remote_clients\":false}}\n",
      BRIDGE_PROTOCOL_VERSION, BRIDGE_PLUGIN_VERSION, (int)g_getstatus(),
      g_last_pause_reason, g_last_pause_reasonex, (ulong)g_last_pause_eip,
      InterlockedCompareExchange(&g_pause_sequence, 0, 0));
}
'''
new_status = r'''static void handle_status(char *out, size_t out_size) {
  LONG mutations_enabled =
      InterlockedCompareExchange(&g_mutations_enabled, 0, 0);
  snprintf(out, out_size,
      "{\"ok\":true,\"protocol_version\":%d,\"plugin_version\":\"%s\",\"pipe\":\"\\\\\\\\.\\\\pipe\\\\OllyBridge110\",\"debug_status\":%d,\"last_pause_reason\":%ld,\"last_pause_reasonex\":%ld,\"last_pause_eip\":\"0x%08lX\",\"pause_sequence\":%ld,\"mutations_enabled\":%s,\"capabilities\":{\"native_wait_for_pause\":true,\"owner_only_pipe\":true,\"overlapped_pipe\":true,\"ui_thread_dispatch\":true,\"bounded_json_parser\":true,\"paged_tables\":true,\"client_drain_wait\":true,\"mutation_gate\":true,\"remote_clients\":false}}\n",
      BRIDGE_PROTOCOL_VERSION, BRIDGE_PLUGIN_VERSION, (int)g_getstatus(),
      g_last_pause_reason, g_last_pause_reasonex, (ulong)g_last_pause_eip,
      InterlockedCompareExchange(&g_pause_sequence, 0, 0),
      mutations_enabled ? "true" : "false");
}
'''
text = replace_once(text, old_status, new_status, "status response")
text = replace_once(
    text,
    r'''  if (!extract_string_field(json, "command", command, sizeof(command))) {
    respond_error(out, out_size, "Missing command");
    return;
  }
  if (strcmp(command, "status") == 0) {
'''.replace('\\"', '"'),
    r'''  if (!extract_string_field(json, "command", command, sizeof(command))) {
    respond_error(out, out_size, "Missing command");
    return;
  }
  if (command_requires_mutation(command) &&
      InterlockedCompareExchange(&g_mutations_enabled, 0, 0) == 0) {
    respond_error(
        out,
        out_size,
        "Native mutation gate is disabled; restart OllyDbg with "
        "OLLYBRIDGE_ALLOW_MUTATIONS=1");
    return;
  }
  if (strcmp(command, "status") == 0) {
'''.replace('\\"', '"'),
    "dispatch gate",
)
text = replace_once(
    text,
    "  WNDCLASSA window_class;\n  g_ui_thread_id = GetCurrentThreadId();",
    "  WNDCLASSA window_class;\n"
    "  g_ui_thread_id = GetCurrentThreadId();\n"
    "  InterlockedExchange(\n"
    "      &g_mutations_enabled,\n"
    "      environment_truthy(\"OLLYBRIDGE_ALLOW_MUTATIONS\"));",
    "initialise mutation gate",
)
text = replace_once(
    text,
    '  log_line("OllyBridge110 plugin loaded");\n',
    '  log_line("OllyBridge110 plugin loaded");\n'
    '  log_line(InterlockedCompareExchange(&g_mutations_enabled, 0, 0)\n'
    '      ? "  Native mutations: enabled"\n'
    '      : "  Native mutations: disabled (read-only gate)");\n',
    "mutation log",
)
text = replace_once(
    text,
    "  g_ui_thread_id = 0;\n  UnregisterClassA",
    "  g_ui_thread_id = 0;\n"
    "  InterlockedExchange(&g_mutations_enabled, 0);\n"
    "  UnregisterClassA",
    "reset mutation gate",
)

if text.count("static int command_requires_mutation(") != 1:
    raise RuntimeError("mutation command helper count is not one")
if text.count("OLLYBRIDGE_ALLOW_MUTATIONS") != 2:
    raise RuntimeError("unexpected mutation environment-variable count")

PLUGIN.write_text(text, encoding="utf-8")
