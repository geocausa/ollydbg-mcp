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
    '''  ResetEvent(g_exec_request.done_event);
  g_exec_request.command = command;
  g_exec_request.address = address;
  g_exec_request.give_chance = give_chance;
  InterlockedExchange(&g_exec_request.pending, 1);
''',
    '''  if (InterlockedCompareExchange(&g_exec_request.pending, 1, 0) != 0)
    return WAIT_TIMEOUT;
  ResetEvent(g_exec_request.done_event);
  g_exec_request.command = command;
  g_exec_request.address = address;
  g_exec_request.give_chance = give_chance;
''',
    "execution request ownership",
)
replace_once(
    '''  wait_result = wait_for_ui_completion(g_exec_request.done_event, 5000);
  if (wait_result != WAIT_OBJECT_0) InterlockedExchange(&g_exec_request.pending, 0);
  return wait_result;
''',
    '''  wait_result = wait_for_ui_completion(g_exec_request.done_event, 5000);
  return wait_result;
''',
    "execution timeout ownership",
)
replace_once(
    '''  ResetEvent(g_bridge_request.done_event);
  memcpy(g_bridge_request.request, json, request_length + 1);
  g_bridge_request.response[0] = '\0';
  InterlockedExchange(&g_bridge_request.pending, 1);
''',
    '''  if (InterlockedCompareExchange(&g_bridge_request.pending, 1, 0) != 0)
    return 0;
  ResetEvent(g_bridge_request.done_event);
  memcpy(g_bridge_request.request, json, request_length + 1);
  g_bridge_request.response[0] = '\0';
''',
    "bridge request ownership",
)
replace_once(
    '''  wait_result = wait_for_ui_completion(g_bridge_request.done_event, 5000);
  if (wait_result != WAIT_OBJECT_0) {
    InterlockedExchange(&g_bridge_request.pending, 0);
    return 0;
  }
''',
    '''  wait_result = wait_for_ui_completion(g_bridge_request.done_event, 5000);
  if (wait_result != WAIT_OBJECT_0) return 0;
''',
    "bridge timeout ownership",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
