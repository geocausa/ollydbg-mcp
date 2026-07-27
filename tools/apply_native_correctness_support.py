from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


workflow = ROOT / ".github" / "workflows" / "python.yml"
replace_once(
    workflow,
    '''      - name: Run bounded JSON parser harness
        run: ./native_json_harness
''',
    '''      - name: Run bounded JSON parser harness
        run: ./native_json_harness
      - name: Compile strict native value parser harness
        run: cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_values_harness.c -o native_values_harness
      - name: Run strict native value parser harness
        run: ./native_values_harness
''',
    "native value CI",
)

smoke = ROOT / "ollydbg_mcp" / "smoke.py"
replace_once(
    smoke,
    '    "mutation_gate",\n)',
    '    "mutation_gate",\n    "strict_native_values",\n    "hardware_breakpoint_validation",\n)',
    "smoke capabilities",
)

client = ROOT / "ollydbg_mcp" / "client.py"
replace_once(
    client,
    '''                "mutations_enabled": status.get("mutations_enabled") is True,
                "atomic_snapshot": False,
''',
    '''                "mutations_enabled": status.get("mutations_enabled") is True,
                "strict_native_values": bool(
                    status.get("capabilities", {}).get("strict_native_values")
                ),
                "hardware_breakpoint_validation": bool(
                    status.get("capabilities", {}).get(
                        "hardware_breakpoint_validation"
                    )
                ),
                "atomic_snapshot": False,
''',
    "client capabilities",
)

smoke_tests = ROOT / "tests" / "test_smoke.py"
replace_once(
    smoke_tests,
    '            "plugin_version": "2.4",',
    '            "plugin_version": "2.5",',
    "fake plugin version",
)
replace_once(
    smoke_tests,
    '''                "mutation_gate": True,
                "remote_clients": False,
''',
    '''                "mutation_gate": True,
                "strict_native_values": True,
                "hardware_breakpoint_validation": True,
                "remote_clients": False,
''',
    "fake native capabilities",
)

native_tests = ROOT / "tests" / "test_native_source.py"
replace_once(
    native_tests,
    '''PARSER = (ROOT / "plugin_stub" / "bridge_json.h").read_text(encoding="utf-8")
EXPORTS = (ROOT / "plugin_stub" / "OllyBridge110.def").read_text(encoding="utf-8")
''',
    '''PARSER = (ROOT / "plugin_stub" / "bridge_json.h").read_text(encoding="utf-8")
VALUES = (ROOT / "plugin_stub" / "bridge_values.h").read_text(encoding="utf-8")
EXPORTS = (ROOT / "plugin_stub" / "OllyBridge110.def").read_text(encoding="utf-8")
''',
    "value parser source",
)
replace_once(
    native_tests,
    '''\n\ndef test_native_tables_are_paginated_with_bounded_page_sizes() -> None:
''',
    '''\n\ndef test_native_values_are_strict_and_portable() -> None:
    assert '#include "bridge_values.h"' in SOURCE
    assert "return bridge_parse_u32_hex(text, value);" in SOURCE
    assert "return bridge_parse_hex_bytes(text, out, max_bytes);" in SOURCE
    assert "strtoul(" not in SOURCE
    assert "bridge_parse_u32_hex(" in VALUES
    assert "bridge_parse_hex_bytes(" in VALUES
    assert "digits >= 8" in VALUES
    assert "*text != '\\0'" in VALUES
    assert "length > (size_t)max_bytes * 2" in VALUES


def test_hardware_breakpoints_are_validated_before_api_calls() -> None:
    assert "Execute hardware breakpoints must have size 1" in SOURCE
    assert "Data hardware breakpoint address is not aligned to its size" in SOURCE
    assert "No free tracked hardware breakpoint slot" in SOURCE
    assert "Hardware breakpoint index must be between 0 and 3" in SOURCE
    assert "Hardware breakpoint slot is not tracked by this plugin" in SOURCE
    assert SOURCE.index("if (slot >= 4)") < SOURCE.index(
        "result = g_sethardwarebreakpoint(address, size, type);"
    )
    clear_start = SOURCE.index("static void handle_clear_hardware_breakpoint(")
    clear_end = SOURCE.index("static void handle_list_hardware_breakpoints(")
    clear_source = SOURCE[clear_start:clear_end]
    assert clear_source.index("index < 0 || index >= 4") < clear_source.index(
        "g_deletehardwarebreakpoint(index)"
    )
    assert "index >= 0 && index < 4" not in clear_source


def test_native_tables_are_paginated_with_bounded_page_sizes() -> None:
''',
    "native correctness assertions",
)
replace_once(
    native_tests,
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.4\\\"" in SOURCE',
    '    assert "#define BRIDGE_PLUGIN_VERSION \\\"2.5\\\"" in SOURCE',
    "native version assertion",
)
replace_once(
    native_tests,
    '        "mutation_gate",\n        "remote_clients",',
    '        "mutation_gate",\n        "strict_native_values",\n        "hardware_breakpoint_validation",\n        "remote_clients",',
    "native capabilities assertion",
)

readme = ROOT / "README.md"
replace_once(
    readme,
    '''- strict bounded native JSON parsing with UTF-8 and Unicode-escape validation
- address lookup, labels and comments
''',
    '''- strict bounded native JSON parsing with UTF-8 and Unicode-escape validation
- strict native 32-bit address and byte-payload validation
- hardware-breakpoint slot, size, index and alignment validation
- address lookup, labels and comments
''',
    "README features",
)
replace_once(
    readme,
    '''plugin_stub/ollydbg110_bridge.c
plugin_stub/bridge_json.h
''',
    '''plugin_stub/ollydbg110_bridge.c
plugin_stub/bridge_json.h
plugin_stub/bridge_values.h
''',
    "README native sources",
)
replace_once(
    readme,
    '''The native parser independently validates the complete JSON document, exact
field names, field types, integer ranges, UTF-8, escaped Unicode, duplicate
requested fields, nesting depth and destination-buffer bounds.
''',
    '''The native parser independently validates the complete JSON document, exact
field names, field types, integer ranges, UTF-8, escaped Unicode, duplicate
requested fields, nesting depth and destination-buffer bounds. Native value
parsers also reject addresses outside eight hexadecimal digits, signs, trailing
junk and malformed or oversized byte payloads. Hardware-breakpoint size,
alignment, tracked-slot availability and clear indexes are checked again inside
the DLL before an OllyDbg API is called.
''',
    "README validation",
)
replace_once(
    readme,
    '''cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_json_harness.c -o native_json_harness
./native_json_harness
''',
    '''cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_json_harness.c -o native_json_harness
./native_json_harness
cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_values_harness.c -o native_values_harness
./native_values_harness
''',
    "README parser harnesses",
)
replace_once(
    readme,
    '''response-drain handshake, pause sequencing, UI-thread dispatch, bounded parser,
bounded response, bounded pagination, native-build and runtime-harness
protections.
''',
    '''response-drain handshake, pause sequencing, UI-thread dispatch, bounded parser,
strict native values, hardware-breakpoint validation, bounded response, bounded
pagination, native-build and runtime-harness protections.
''',
    "README source assertions",
)
replace_once(
    readme,
    '''exercises the transport through real Windows named pipes, compiles the native
parser harness with strict C89 warnings on Ubuntu, compiles and inspects the
complete 32-bit DLL, and compiles and inspects the controlled x86 target.
''',
    '''exercises the transport through real Windows named pipes, compiles both native
parser harnesses with strict C89 warnings on Ubuntu, compiles and inspects the
complete 32-bit DLL, and compiles and inspects the controlled x86 target.
''',
    "README CI",
)
