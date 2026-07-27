from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "plugin_stub" / "ollydbg110_bridge.c"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


text = SOURCE.read_text(encoding="utf-8")
text = replace_once(
    text,
    '#include "bridge_json.h"\n',
    '#include "bridge_json.h"\n#include "bridge_values.h"\n',
    "value parser include",
)
text = replace_once(
    text,
    '#define BRIDGE_PLUGIN_VERSION "2.4"',
    '#define BRIDGE_PLUGIN_VERSION "2.5"',
    "plugin version",
)
old_parsers = r'''static int parse_hex_value(const char *text, unsigned long *value) {
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
'''
new_parsers = r'''static int parse_hex_value(const char *text, unsigned long *value) {
  return bridge_parse_u32_hex(text, value);
}

static int parse_hex_bytes(const char *text, unsigned char *out, int max_bytes) {
  return bridge_parse_hex_bytes(text, out, max_bytes);
}
'''
text = replace_once(text, old_parsers, new_parsers, "strict parser wrappers")
text = replace_once(
    text,
    '\\"client_drain_wait\\":true,\\"mutation_gate\\":true,\\"remote_clients\\":false',
    '\\"client_drain_wait\\":true,\\"mutation_gate\\":true,'
    '\\"strict_native_values\\":true,\\"hardware_breakpoint_validation\\":true,'
    '\\"remote_clients\\":false',
    "native capabilities",
)
old_set = r'''  result = g_sethardwarebreakpoint(address, size, type);
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
'''
new_set = r'''  if (type == HB_CODE && size != 1) {
    respond_error(out, out_size, "Execute hardware breakpoints must have size 1");
    return;
  }
  if (type != HB_CODE && size > 1 && (address % (unsigned long)size) != 0) {
    respond_error(out, out_size, "Data hardware breakpoint address is not aligned to its size");
    return;
  }
  for (slot = 0; slot < 4; slot++) {
    if (!g_hardware_breakpoints_valid[slot]) break;
  }
  if (slot >= 4) {
    respond_error(out, out_size, "No free tracked hardware breakpoint slot");
    return;
  }
  result = g_sethardwarebreakpoint(address, size, type);
  if (result != 0) {
    respond_error(out, out_size, "Sethardwarebreakpoint failed");
    return;
  }
  g_hardware_breakpoints[slot].addr = address;
  g_hardware_breakpoints[slot].size = size;
  g_hardware_breakpoints[slot].type = type;
  g_hardware_breakpoints_valid[slot] = 1;
  snprintf(out, out_size, "{\"ok\":true,\"index\":%d,\"address\":\"0x%08lX\",\"size\":%d,\"type\":\"%s\"}\n", slot, address, size, type_text);
'''
text = replace_once(text, old_set, new_set, "hardware breakpoint set")
old_clear = r'''  if (!extract_int_field(json, "index", &index) || index < 0) {
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
'''
new_clear = r'''  if (!extract_int_field(json, "index", &index) || index < 0 || index >= 4) {
    respond_error(out, out_size, "Hardware breakpoint index must be between 0 and 3");
    return;
  }
  if (!g_hardware_breakpoints_valid[index]) {
    respond_error(out, out_size, "Hardware breakpoint slot is not tracked by this plugin");
    return;
  }
  if (g_deletehardwarebreakpoint(index) != 0) {
    respond_error(out, out_size, "Deletehardwarebreakpoint failed");
    return;
  }
  g_hardware_breakpoints_valid[index] = 0;
  memset(&g_hardware_breakpoints[index], 0, sizeof(g_hardware_breakpoints[index]));
'''
text = replace_once(text, old_clear, new_clear, "hardware breakpoint clear")

if text.count('#include "bridge_values.h"') != 1:
    raise RuntimeError("bridge_values include count is not one")
if "strtoul(" in text:
    raise RuntimeError("legacy permissive address parser remains")

SOURCE.write_text(text, encoding="utf-8")
