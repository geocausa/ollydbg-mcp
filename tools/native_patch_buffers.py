from pathlib import Path
P = Path('plugin_stub/ollydbg110_bridge.c')

def rep(s, a, b, name):
    n = s.count(a)
    if n != 1:
        raise RuntimeError(f'{name}: expected 1 match, found {n}')
    return s.replace(a, b, 1)

s = P.read_text(encoding='utf-8')
if 'static int append_format(' not in s:
    s = rep(s,
'''#include <ctype.h>
#include <stdio.h>
''',
'''#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
''', 'stdarg header')
    marker = 'static void json_escape_append(char *out, size_t out_size, size_t *used, const char *src) {\n'
    helper = r'''static int append_format(char *out, size_t out_size, size_t *used, const char *format, ...) {
  int written;
  size_t remaining;
  va_list args;
  if (out == NULL || used == NULL || format == NULL || out_size == 0 || *used >= out_size) return 0;
  remaining = out_size - *used;
  va_start(args, format);
#if defined(_MSC_VER)
  written = _vsnprintf(out + *used, remaining, format, args);
#else
  written = vsnprintf(out + *used, remaining, format, args);
#endif
  va_end(args);
  if (written < 0 || (size_t)written >= remaining) {
    out[out_size - 1] = '\0';
    return 0;
  }
  *used += (size_t)written;
  return 1;
}

'''
    s = rep(s, marker, helper + marker, 'append helper')

s = rep(s,
r'''  used = (size_t)snprintf(out, out_size, "{\"ok\":true,\"address\":\"0x%08lX\",\"size\":%lu,\"hex\":\"", address, read);
  for (index = 0; index < (int)read && used + 2 < out_size; index++) {
    used += (size_t)snprintf(out + used, out_size - used, "%02X", buffer[index]);
  }
  snprintf(out + used, out_size - used, "\"}\n");
  free(buffer);
''',
r'''  if (!append_format(out, out_size, &used, "{\"ok\":true,\"address\":\"0x%08lX\",\"size\":%lu,\"hex\":\"", address, read)) {
    free(buffer); respond_error(out, out_size, "Memory response exceeds pipe buffer"); return;
  }
  for (index = 0; index < (int)read; index++) {
    if (!append_format(out, out_size, &used, "%02X", buffer[index])) {
      free(buffer); respond_error(out, out_size, "Memory response exceeds pipe buffer"); return;
    }
  }
  free(buffer);
  if (!append_format(out, out_size, &used, "\"}\n"))
    respond_error(out, out_size, "Memory response exceeds pipe buffer");
''', 'memory response')

s = rep(s,
r'''    used += (size_t)snprintf(
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
''',
r'''    if (!append_format(out, out_size, &used,
        "%s{\"address\":\"0x%08lX\",\"instruction\":\"%s\",\"size\":%lu}",
        line_index == 0 ? "" : ",", address, escaped, size)) {
      respond_error(out, out_size, "Disassembly response exceeds pipe buffer"); return;
    }
    address += size;
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Disassembly response exceeds pipe buffer");
''', 'disassembly response')

s = rep(s,
r'''    used += (size_t)snprintf(
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
''',
r'''    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"address\":\"0x%08lX\",\"size\":%d,\"type\":%d}",
        first ? "" : ",", index, g_hardware_breakpoints[index].addr,
        g_hardware_breakpoints[index].size, g_hardware_breakpoints[index].type)) {
      respond_error(out, out_size, "Hardware breakpoint response exceeds pipe buffer"); return;
    }
    first = 0;
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Hardware breakpoint response exceeds pipe buffer");
''', 'hardware breakpoint response')

s = rep(s,
r'''    used += (size_t)snprintf(
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
''',
r'''    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"address\":\"0x%08lX\",\"type\":\"0x%08lX\",\"cmd\":\"0x%02X\",\"passcount\":%lu}",
        index == 0 ? "" : ",", index, bp->addr, bp->type,
        (unsigned char)bp->cmd, bp->passcount)) {
      respond_error(out, out_size, "Breakpoint response exceeds pipe buffer"); return;
    }
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Breakpoint response exceeds pipe buffer");
''', 'breakpoint response')

s = rep(s,
r'''    used += (size_t)snprintf(
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
''',
r'''    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"name\":\"%s\",\"path\":\"%s\",\"base\":\"0x%08lX\",\"size\":\"0x%08lX\",\"entry\":\"0x%08lX\"}",
        index == 0 ? "" : ",", index, name_escaped, path_escaped,
        mod->base, mod->size, mod->entry)) {
      respond_error(out, out_size, "Module response exceeds pipe buffer"); return;
    }
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Module response exceeds pipe buffer");
''', 'module response')

s = rep(s,
r'''    used += (size_t)snprintf(
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
''',
r'''    if (!append_format(out, out_size, &used,
        "%s{\"index\":%d,\"thread_id\":\"0x%08lX\",\"entry\":\"0x%08lX\",\"stacktop\":\"0x%08lX\",\"stackbottom\":\"0x%08lX\",\"suspendcount\":%d,\"regvalid\":%s,\"eip\":\"0x%08lX\"}",
        index == 0 ? "" : ",", index, thr->threadid, thr->entry,
        thr->stacktop, thr->stackbottom, thr->suspendcount,
        thr->regvalid ? "true" : "false", thr->reg.ip)) {
      respond_error(out, out_size, "Thread response exceeds pipe buffer"); return;
    }
  }
  if (!append_format(out, out_size, &used, "]}\n"))
    respond_error(out, out_size, "Thread response exceeds pipe buffer");
''', 'thread response')

s = rep(s,
'''#include "Plugin.h"
''',
'''#include "Plugin.h"

#if defined(_MSC_VER)
#pragma comment(lib, "Advapi32.lib")
#endif
''', 'advapi link')
P.write_text(s, encoding='utf-8', newline='\n')
