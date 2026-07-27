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
    '#define BRIDGE_PLUGIN_VERSION "2.0"',
    '#define BRIDGE_PLUGIN_VERSION "2.1"',
    "plugin version",
)
replace_once(
    r'\"ui_thread_dispatch\":true,\"remote_clients\":false',
    r'\"ui_thread_dispatch\":true,\"bounded_json_parser\":true,'
    r'\"remote_clients\":false',
    "parser capability",
)

PATH.write_text(source, encoding="utf-8", newline="\n")
