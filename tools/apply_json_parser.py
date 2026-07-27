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
    '''#include "Plugin.h"
''',
    '''#include "Plugin.h"
#include "bridge_json.h"
''',
    "parser include",
)

replace_once(
    r'''static int extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
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
''',
    '''static int extract_string_field(const char *json, const char *field, char *out, size_t out_size) {
  return bridge_json_extract_string(json, field, out, out_size);
}

static int extract_int_field(const char *json, const char *field, int *value) {
  return bridge_json_extract_int(json, field, value);
}

static int extract_bool_field(const char *json, const char *field, int *value) {
  return bridge_json_extract_bool(json, field, value);
}
''',
    "field extractors",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
