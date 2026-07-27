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
- native run, step and continue result validation
- debugger operations marshalled through OllyDbg's UI thread
- event-driven native pause sequencing with an automatic legacy fallback
- strict bounded native JSON parsing with UTF-8 and Unicode-escape validation
- strict native 32-bit address and byte-payload validation
- hardware-breakpoint slot, size, index and alignment validation
- address lookup, labels and comments
- guarded debuggee-memory writes
- combined debugger snapshots
- bridge capability and protocol-version reporting
- bounded native response construction
- serialized Python requests with bounded response waits
- owner-restricted, local-only named-pipe access
- interruptible overlapped pipe I/O for clean plugin shutdown
- bounded response-drain handshake before the server disconnects
- native read-only-by-default gate for debugger mutations
- reproducible 32-bit MSVC build and export validation
- controlled x86 runtime target with a structured smoke-test report

## Safety defaults

Operations that can unexpectedly destroy debugger state require explicit
confirmation:

- `olly_write_memory(..., confirm=true)`
- `olly_clear_all_breakpoints(confirm=true)`
- `olly_prepare_session(clear_breakpoints=true, confirm_clear=true)`

Session preparation no longer clears breakpoints by default.

The native plugin independently blocks memory writes, software and hardware
breakpoint changes, labels and comments unless OllyDbg was started with
`OLLYBRIDGE_ALLOW_MUTATIONS=1`. The supplied launcher forces this setting to
`0` by default and enables it only with `-EnableNativeMutations`. This protects
direct same-user pipe access as well as MCP calls; MCP confirmation remains a
second, separate safety layer.

The native pipe rejects remote clients and applies an owner-only Windows access
rule. This reduces accidental cross-user access, but it is not a substitute for
running the debugger and MCP server under a trusted Windows account. Do not
expose the MCP server to untrusted networks or users.

## Requirements

- Windows
- Python 3.10 or newer
- OllyDbg 1.10
- 32-bit Microsoft Visual C++ build tools
- the genuine OllyDbg 1.10 `Plugin.h` header

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
plugin_stub/bridge_values.h
```

Open a **32-bit Visual Studio Native Tools** PowerShell or command prompt, then
run the supplied build script with the directory containing the genuine
OllyDbg 1.10 `Plugin.h`:

```powershell
.\plugin_stub\build_plugin.ps1 `
  -SdkDir 'C:\Path\To\OllyDbg110SDK' `
  -OutputDir '.\build\native'
```

The build script:

- refuses to use the repository's test-only SDK shim for a real build
- compiles C code with unsigned-character mode (`/J`)
- treats compiler warnings as errors
- links an x86 Windows DLL
- links `Kernel32`, `User32` and `Advapi32`
- verifies the PE image is 32-bit x86
- verifies all eight required OllyDbg callback exports

A successful real build produces:

```text
build/native/OllyBridge110.dll
```

Copy that DLL into the plugin directory configured by `ollydbg.ini` and restart
OllyDbg.

## CI native build validation

GitHub Actions compiles and links the complete DLL on a Windows x86 MSVC
environment using `tests/ollydbg_sdk_stub/Plugin.h`. That header is a clearly
marked **test-only compile shim** containing only the names and fields needed to
check this source tree. CI verifies syntax, warning cleanliness, linking, x86
machine type and callback exports, then deletes the generated DLL without
uploading it.

The CI DLL must never be distributed or loaded into OllyDbg. It does not prove
binary compatibility with the real SDK. Only the genuine-SDK command above
produces a candidate plugin for runtime testing.

## Safer launcher

The helper script validates paths, backs up `ollydbg.ini` before changing its
plugin path and does not terminate an existing OllyDbg process unless
`-RestartOlly` is explicitly supplied.

```powershell
powershell -ExecutionPolicy Bypass -File .\start_olly_bridge.ps1 `
  -OllyDir 'C:\Tools\OllyDbg' `
  -PluginDir 'C:\Tools\OllyDbg\Plugins' `
  -RestartOlly

# Explicitly enable native writes, breakpoint changes, labels and comments.
.\start_olly_bridge.ps1 `
  -OllyDir 'C:\Tools\OllyDbg' `
  -PluginDir 'C:\Tools\OllyDbg\Plugins' `
  -EnableNativeMutations `
  -RestartOlly
```

Pass `-TargetExe` to open a specific executable. `-PluginDllPath` selects a DLL
outside the repository root, and `-SkipServer` launches only OllyDbg when a
direct named-pipe client such as the smoke runner is being used.

## Genuine-SDK runtime smoke test

The runtime harness builds the plugin with the genuine SDK, builds a controlled
32-bit target, launches that target in OllyDbg and writes a structured JSON
report. From an ordinary PowerShell prompt:

```powershell
.\integration\run_runtime_smoke.ps1 `
  -OllyDir 'C:\Tools\OllyDbg' `
  -PluginDir 'C:\Tools\OllyDbg\Plugins' `
  -SdkDir 'C:\Path\To\OllyDbg110SDK' `
  -RestartOlly
```

The controlled executable is linked at the fixed `0x00400000` image base with
ASLR disabled. It exports a probe function and counter. The target build records
their virtual addresses in `olly_smoke_manifest.json`, so the smoke runner can
validate the loaded module, memory reads, address lookup and disassembly without
hard-coded guesses.

The default run is read-only. Two independent opt-ins extend it:

```powershell
# Temporarily set, verify and clear a software breakpoint.
.\integration\run_runtime_smoke.ps1 ... -AllowMutations

# Run to the exported probe and execute one single step.
.\integration\run_runtime_smoke.ps1 ... -AllowExecution
```

The mutation check automatically launches OllyDbg with the native mutation
gate enabled and preserves a breakpoint that already existed at the probe. The
execution-only check does not enable native mutations. The execution check
changes debuggee state and therefore remains separate. The
launcher still refuses to terminate an existing OllyDbg instance unless
`-RestartOlly` is supplied. Pass `-SkipIniUpdate` only when the configured plugin
directory is already correct.

Generated files are placed below `build/runtime-smoke/`. The final report is:

```text
build/runtime-smoke/olly_smoke_report.json
```

The runner can also be called directly after the target and genuine-SDK plugin
have been built and loaded:

```powershell
ollydbg-smoke `
  --manifest .\build\runtime-smoke\target\olly_smoke_manifest.json `
  --timeout 30
```

`python .\test_olly_bridge.py` remains a compatibility entry point for the same
structured runner.

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
requested fields, nesting depth and destination-buffer bounds. Native value
parsers also reject addresses outside eight hexadecimal digits, signs, trailing
junk and malformed or oversized byte payloads. Hardware-breakpoint size,
alignment, tracked-slot availability and clear indexes are checked again inside
the DLL before an OllyDbg API is called.

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
cc -std=c89 -pedantic -Wall -Wextra -Werror tests/native_values_harness.c -o native_values_harness
./native_values_harness
```

Most unit tests use a fake transport and do not require OllyDbg. A dedicated
Windows suite exercises the Python client against real local named pipes,
including fragmented replies, malformed replies, size limits, disconnects and
timeouts. The controlled runtime target is compiled as fixed-base x86 in CI and
its exported-address manifest is validated; the generated executable is then
deleted and is never uploaded.

Source assertions retain the local-only pipe, interruptible shutdown,
response-drain handshake, pause sequencing, UI-thread dispatch, bounded parser,
strict native values, hardware-breakpoint validation, execution-result
validation, bounded response, bounded pagination, native-build and runtime-harness
protections.

GitHub Actions runs linting and unit tests on Windows with Python 3.10 and 3.12,
exercises the transport through real Windows named pipes, compiles both native
parser harnesses with strict C89 warnings on Ubuntu, compiles and inspects the
complete 32-bit DLL, and compiles and inspects the controlled x86 target.

## Current native limitations

The native bridge remains intentionally small and compatible with OllyDbg 1.10.
The repository can now build and validate the controlled target automatically,
but GitHub-hosted CI cannot legally or practically load a genuine OllyDbg 1.10
installation and proprietary SDK. Runtime ABI confirmation therefore remains a
local Windows step through `integration/run_runtime_smoke.ps1`.

The current bridge is substantially safer for normal local use, but it should
still be treated as trusted-user debugger automation rather than a hardened
service for hostile inputs.

## License

MIT. See [LICENSE](./LICENSE).
