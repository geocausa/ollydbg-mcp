# OllyDbg MCP Bridge

An MCP bridge for **OllyDbg 1.10**. It connects an MCP client to a small native
OllyDbg plugin over a local Windows named pipe.

The repository is source-first. Compiled DLLs, SDK files, caches, samples and
machine-specific paths are intentionally excluded.

## Architecture

```text
MCP client
    |
    | stdio / streamable HTTP / SSE
    v
Python MCP server
    |
    | JSON over \\.\pipe\OllyBridge110
    v
OllyDbg 1.10 plugin
    |
    v
OllyDbg debugger APIs
```

The Python package validates and normalizes tool arguments before sending a
request to the native bridge. Addresses are represented canonically as unsigned
32-bit hexadecimal values such as `0x00401000`.

## Features

- debugger status and decoded pause metadata
- register, memory, stack and disassembly reads
- complete module, thread and breakpoint enumeration through bounded pages
- software and hardware breakpoint management
- pause, continue, run, step and run-to-address helpers
- debugger operations marshalled through OllyDbg's UI thread
- event-driven native pause sequencing with an automatic legacy fallback
- strict bounded native JSON parsing with UTF-8 and Unicode-escape validation
- address lookup, labels and comments
- guarded debuggee-memory writes
- combined debugger snapshots
- bridge capability and protocol-version reporting
- bounded native response construction
- serialized Python requests with bounded response waits
- owner-restricted, local-only named-pipe access
- interruptible overlapped pipe I/O for clean plugin shutdown

## Safety defaults

Operations that can unexpectedly destroy debugger state require explicit
confirmation:

- `olly_write_memory(..., confirm=true)`
- `olly_clear_all_breakpoints(confirm=true)`
- `olly_prepare_session(clear_breakpoints=true, confirm_clear=true)`

Session preparation no longer clears breakpoints by default.

The native pipe rejects remote clients and applies an owner-only Windows access
rule. This reduces accidental cross-user access, but it is not a substitute for
running the debugger and MCP server under a trusted Windows account. Do not
expose the MCP server to untrusted networks or users.

## Requirements

- Windows
- Python 3.10 or newer
- OllyDbg 1.10
- a 32-bit C compiler compatible with the OllyDbg 1.10 plugin SDK
- the OllyDbg 1.10 `Plugin.h` header and import environment

The Python dependency is pinned to the compatible MCP Python SDK v1 line until
the project is deliberately migrated to SDK v2.

## Install the Python server

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Run it through the installed console command:

```powershell
ollydbg-mcp --transport stdio
```

The source-checkout entry point remains available:

```powershell
python .\server.py --transport stdio
```

Optional configuration:

```powershell
$env:OLLYDBG_PIPE_NAME = '\\.\pipe\OllyBridge110'
$env:OLLYDBG_TIMEOUT_SECONDS = '5'
```

Equivalent command-line options are available:

```powershell
ollydbg-mcp --pipe-name '\\.\pipe\OllyBridge110' --timeout 5
```

## Build the plugin

The native source lives at:

```text
plugin_stub/ollydbg110_bridge.c
plugin_stub/bridge_json.h
```

Build a 32-bit `OllyBridge110.dll` against the OllyDbg 1.10 SDK. The build must:

- include the SDK `Plugin.h`
- keep `bridge_json.h` beside `ollydbg110_bridge.c`
- use the structure packing and unsigned-character settings required by the SDK
- export the OllyDbg plugin entry points
- produce a 32-bit DLL
- link the Windows `Advapi32` library for the owner-only pipe security descriptor

MSVC builds receive the `Advapi32` link directive from the source. Other
Windows toolchains may need the library added explicitly to their linker flags.

Copy the DLL into the plugin directory configured by `ollydbg.ini` and restart
OllyDbg.

## Safer launcher

The helper script validates paths, backs up `ollydbg.ini` before changing its
plugin path and does not terminate an existing OllyDbg process unless
`-RestartOlly` is explicitly supplied.

```powershell
powershell -ExecutionPolicy Bypass -File .\start_olly_bridge.ps1 `
  -OllyDir 'C:\Tools\OllyDbg' `
  -PluginDir 'C:\Tools\OllyDbg\Plugins' `
  -RestartOlly
```

Pass `-TargetExe` to open a specific executable.

## MCP tools

Inspection:

- `olly_status`
- `olly_get_capabilities`
- `olly_snapshot`
- `olly_get_registers`
- `olly_get_eip`
- `olly_current_instruction`
- `olly_read_memory`
- `olly_read_disasm`
- `olly_read_stack`
- `olly_disasm_from_stack`
- `olly_lookup_address`
- `olly_list_modules`
- `olly_list_threads`
- `olly_list_breakpoints`
- `olly_list_hardware_breakpoints`

Navigation and metadata:

- `olly_goto_address`
- `olly_goto_eip`
- `olly_set_label`
- `olly_set_comment`

Breakpoints and mutation:

- `olly_set_breakpoint`
- `olly_clear_breakpoint`
- `olly_clear_all_breakpoints`
- `olly_set_hardware_breakpoint`
- `olly_clear_hardware_breakpoint`
- `olly_write_memory`

Execution:

- `olly_run`
- `olly_run_to_address`
- `olly_step_into`
- `olly_step_over`
- `olly_pause`
- `olly_continue`
- `olly_wait_for_pause`
- `olly_prepare_session`

## Table pagination

The native plugin keeps every table response within the 8 KB pipe buffer:

- modules: at most 8 entries per native page
- threads: at most 32 entries per native page
- software breakpoints: at most 32 entries per native page

The Python client follows all pages automatically. Existing MCP tools therefore
still return one complete `modules`, `threads`, or `breakpoints` list instead of
exposing page management to the caller. It rejects empty intermediate pages,
non-progressing offsets, malformed item fields, excessive page counts and
unreasonably large aggregate tables.

A new Python server remains compatible with an older unpaged plugin DLL. To
receive complete large tables from plugin version 2.2 or newer, update the
Python server and plugin DLL together; an older Python client would only see the
first native page.

## Validation limits

The Python boundary currently enforces:

- addresses from `0x00000000` through `0xFFFFFFFF`
- memory reads and writes of at most 1024 bytes
- disassembly requests of at most 32 instructions
- hardware breakpoint indexes from 0 through 3
- execute hardware breakpoints of one byte
- aligned two-byte and four-byte data breakpoints
- operation timeouts of at most 300 seconds
- at most 4096 native table pages and 100,000 aggregate table items

The native parser independently validates the complete JSON document, exact
field names, field types, integer ranges, UTF-8, escaped Unicode, duplicate
requested fields, nesting depth and destination-buffer bounds.

## Testing

Install development dependencies and run:

```powershell
python -m pip install -e '.[dev]'
python -m ruff check .
python -m pytest
```

The standalone parser harness can also be compiled without the OllyDbg SDK:

```text
cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_json_harness.c -o native_json_harness
./native_json_harness
```

The unit tests use a fake transport and do not require OllyDbg. They also assert
that the native source retains the local-only pipe, interruptible shutdown,
pause sequencing, UI-thread dispatch, bounded parser, bounded response and
bounded pagination protections. A manual smoke test remains available when the
plugin is loaded:

```powershell
python .\test_olly_bridge.py
```

GitHub Actions runs linting and unit tests on Windows with Python 3.10 and 3.12,
and compiles the native parser harness with strict C89 warnings on Ubuntu.

## Current native limitations

The native bridge remains intentionally small and compatible with OllyDbg 1.10.
Remaining work includes:

- compiling and exercising the DLL in CI when a redistributable SDK-compatible
  build environment is available
- adding automated integration tests against a real OllyDbg 1.10 instance

The current bridge is substantially safer for normal local use, but it should
still be treated as trusted-user debugger automation rather than a hardened
service for hostile inputs.

## License

MIT. See [LICENSE](./LICENSE).
