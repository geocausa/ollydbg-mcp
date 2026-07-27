from pathlib import Path


PATH = Path("tools/apply_ui_thread.py")
source = PATH.read_text(encoding="utf-8")
replacements = (
    ("new_dispatch = '''", "new_dispatch = r'''") ,
    (
        "    '''        request[read] = '\\0'; dispatch_request(request, response, sizeof(response));",
        "    r'''        request[read] = '\\0'; dispatch_request(request, response, sizeof(response));",
    ),
    (
        "    '''        char command[64];\n        request[read] = '\\0';",
        "    r'''        char command[64];\n        request[read] = '\\0';",
    ),
)
for old, new in replacements:
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"escape preparation expected 1 match, found {matches}: {old!r}")
    source = source.replace(old, new, 1)
PATH.write_text(source, encoding="utf-8", newline="\n")
