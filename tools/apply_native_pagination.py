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
    "#define PIPE_BUFFER_SIZE 8192\n",
    "#define PIPE_BUFFER_SIZE 8192\n"
    "#define BREAKPOINT_PAGE_LIMIT 32\n"
    "#define MODULE_PAGE_LIMIT 8\n"
    "#define THREAD_PAGE_LIMIT 32\n",
    "page limits",
)

replace_once(
    '''static int extract_bool_field(const char *json, const char *field, int *value) {
  return bridge_json_extract_bool(json, field, value);
}
''',
    '''static int extract_bool_field(const char *json, const char *field, int *value) {
  return bridge_json_extract_bool(json, field, value);
}

static int extract_optional_int_field(
    const char *json,
    const char *field,
    int default_value,
    int *value) {
  bridge_json_value field_value;
  int found = bridge_json_find_field(json, field, &field_value);
  if (found < 0) return 0;
  if (found == 0) {
    *value = default_value;
    return 1;
  }
  return bridge_json_extract_int(json, field, value);
}

static int parse_page_request(
    const char *json,
    int total,
    int default_limit,
    int maximum_limit,
    int *offset,
    int *limit) {
  if (!extract_optional_int_field(json, "offset", 0, offset) ||
      !extract_optional_int_field(json, "limit", default_limit, limit)) return 0;
  if (*offset < 0 || *limit <= 0 || *limit > maximum_limit || total < 0) return 0;
  if (*offset > total) *offset = total;
  return 1;
}
''',
    "page request helpers",
)

start_marker = "static void handle_list_breakpoints("
end_marker = "static void handle_set_name("
if source.count(start_marker) != 1 or source.count(end_marker) != 1:
    raise RuntimeError("table handler markers are not unique")
start = source.index(start_marker)
end = source.index(end_marker, start)

handlers = r'''static void handle_list_breakpoints(
    const char *json,
    char *out,
    size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_BREAKPOINTS);
  size_t used = 0;
  int offset;
  int limit;
  int end_index;
  int returned;
  int index;
  int first = 1;
  if (table == NULL) {
    respond_error(out, out_size, "Breakpoint table is not available");
    return;
  }
  if (!parse_page_request(
          json, table->data.n, BREAKPOINT_PAGE_LIMIT, BREAKPOINT_PAGE_LIMIT,
          &offset, &limit)) {
    respond_error(out, out_size, "Invalid breakpoint page request");
    return;
  }
  end_index = offset;
  if (limit > table->data.n - offset) end_index = table->data.n;
  else end_index = offset + limit;
  returned = end_index - offset;
  out[0] = '\0';
  if (!append_format(out, out_size, &used,
      "{\"ok\":true,\"count\":%d,\"offset\":%d,\"limit\":%d,"
      "\"returned\":%d,\"has_more\":%s,\"next_offset\":%d,"
      "\"breakpoints\":[",
      table->data.n, offset, limit, returned,
      end_index < table->data.n ? "true" : "false", end_index)) {
    respond_error(out, out_size, "Breakpoint response exceeds pipe buffer");
    return;
  }
  for (index = offset; index < end_index; index++) {
    t_bpoint *bp =
        (t_bpoint *)((char *)table->data.data + (table->data.itemsize * index));
    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"address\":\"0x%08lX\","
        "\"type\":\"0x%08lX\",\"cmd\":\"0x%02X\",\"passcount\":%lu}",
        first ? "" : ",", index, bp->addr, bp->type,
        (unsigned char)bp->cmd, bp->passcount)) {
      respond_error(out, out_size, "Breakpoint response exceeds pipe buffer");
      return;
    }
    first = 0;
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Breakpoint response exceeds pipe buffer");
}

static void handle_list_modules(
    const char *json,
    char *out,
    size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_MODULES);
  size_t used = 0;
  int offset;
  int limit;
  int end_index;
  int returned;
  int index;
  int first = 1;
  if (table == NULL) {
    respond_error(out, out_size, "Module table is not available");
    return;
  }
  if (!parse_page_request(
          json, table->data.n, MODULE_PAGE_LIMIT, MODULE_PAGE_LIMIT,
          &offset, &limit)) {
    respond_error(out, out_size, "Invalid module page request");
    return;
  }
  end_index = offset;
  if (limit > table->data.n - offset) end_index = table->data.n;
  else end_index = offset + limit;
  returned = end_index - offset;
  out[0] = '\0';
  if (!append_format(out, out_size, &used,
      "{\"ok\":true,\"count\":%d,\"offset\":%d,\"limit\":%d,"
      "\"returned\":%d,\"has_more\":%s,\"next_offset\":%d,"
      "\"modules\":[",
      table->data.n, offset, limit, returned,
      end_index < table->data.n ? "true" : "false", end_index)) {
    respond_error(out, out_size, "Module response exceeds pipe buffer");
    return;
  }
  for (index = offset; index < end_index; index++) {
    t_module *mod =
        (t_module *)((char *)table->data.data + (table->data.itemsize * index));
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
    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"name\":\"%s\",\"path\":\"%s\","
        "\"base\":\"0x%08lX\",\"size\":\"0x%08lX\","
        "\"entry\":\"0x%08lX\"}",
        first ? "" : ",", index, name_escaped, path_escaped,
        mod->base, mod->size, mod->entry)) {
      respond_error(out, out_size, "Module response exceeds pipe buffer");
      return;
    }
    first = 0;
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Module response exceeds pipe buffer");
}

static void handle_list_threads(
    const char *json,
    char *out,
    size_t out_size) {
  t_table *table = (t_table *)(ULONG_PTR)g_plugingetvalue(VAL_THREADS);
  ulong cpu_thread_id = g_getcputhreadid();
  size_t used = 0;
  int offset;
  int limit;
  int end_index;
  int returned;
  int index;
  int first = 1;
  if (table == NULL) {
    respond_error(out, out_size, "Thread table is not available");
    return;
  }
  if (!parse_page_request(
          json, table->data.n, THREAD_PAGE_LIMIT, THREAD_PAGE_LIMIT,
          &offset, &limit)) {
    respond_error(out, out_size, "Invalid thread page request");
    return;
  }
  end_index = offset;
  if (limit > table->data.n - offset) end_index = table->data.n;
  else end_index = offset + limit;
  returned = end_index - offset;
  out[0] = '\0';
  if (!append_format(out, out_size, &used,
      "{\"ok\":true,\"count\":%d,\"offset\":%d,\"limit\":%d,"
      "\"returned\":%d,\"has_more\":%s,\"next_offset\":%d,"
      "\"cpu_thread_id\":\"0x%08lX\",\"threads\":[",
      table->data.n, offset, limit, returned,
      end_index < table->data.n ? "true" : "false", end_index,
      cpu_thread_id)) {
    respond_error(out, out_size, "Thread response exceeds pipe buffer");
    return;
  }
  for (index = offset; index < end_index; index++) {
    t_thread *thr =
        (t_thread *)((char *)table->data.data + (table->data.itemsize * index));
    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"thread_id\":\"0x%08lX\","
        "\"entry\":\"0x%08lX\",\"stacktop\":\"0x%08lX\","
        "\"stackbottom\":\"0x%08lX\",\"suspendcount\":%d,"
        "\"regvalid\":%s,\"eip\":\"0x%08lX\"}",
        first ? "" : ",", index, thr->threadid, thr->entry,
        thr->stacktop, thr->stackbottom, thr->suspendcount,
        thr->regvalid ? "true" : "false", thr->reg.ip)) {
      respond_error(out, out_size, "Thread response exceeds pipe buffer");
      return;
    }
    first = 0;
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Thread response exceeds pipe buffer");
}

'''

source = source[:start] + handlers + source[end:]

replace_once(
    '''  else if (strcmp(command, "list_breakpoints") == 0) {
    handle_list_breakpoints(out, out_size);
  }
  else if (strcmp(command, "list_modules") == 0) {
    handle_list_modules(out, out_size);
  }
  else if (strcmp(command, "list_threads") == 0) {
    handle_list_threads(out, out_size);
  }
''',
    '''  else if (strcmp(command, "list_breakpoints") == 0) {
    handle_list_breakpoints(json, out, out_size);
  }
  else if (strcmp(command, "list_modules") == 0) {
    handle_list_modules(json, out, out_size);
  }
  else if (strcmp(command, "list_threads") == 0) {
    handle_list_threads(json, out, out_size);
  }
''',
    "paged dispatch",
)

replace_once(
    '#define BRIDGE_PLUGIN_VERSION "2.1"',
    '#define BRIDGE_PLUGIN_VERSION "2.2"',
    "plugin version",
)
replace_once(
    r'\"bounded_json_parser\":true,\"remote_clients\":false',
    r'\"bounded_json_parser\":true,\"paged_tables\":true,'
    r'\"remote_clients\":false',
    "pagination capability",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
