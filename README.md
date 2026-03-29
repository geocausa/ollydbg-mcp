# OllyDbg MCP Bridge

An MCP bridge for **OllyDbg 1.10** that lets an MCP client inspect and lightly control the debugger through a small plugin and a Python server.

The project is split into two parts:

- a native OllyDbg plugin that exposes a named pipe at `\\.\pipe\OllyBridge110`
- a Python MCP server that translates tool calls into pipe requests and JSON responses

This repo is source-first. Compiled binaries, caches, and machine-specific paths are intentionally excluded.

## Features

- debugger status, pause metadata, and current instruction helpers
- register, memory, stack, and disassembly reads
- module, thread, and breakpoint enumeration
- software and hardware breakpoint helpers
- basic execution controls such as pause, continue, run, and step helpers
- address lookup and light session cleanup helpers

## Repository Layout

- `server.py`
  Python MCP server
- `start_olly_bridge.ps1`
  Convenience launcher for local testing
- `test_olly_bridge.py`
  Small smoke test for the Python side
- `plugin_stub/ollydbg110_bridge.c`
  OllyDbg 1.10 plugin bridge source
- `plugin_stub/OllyBridge110.def`
  Export definition file for the plugin

## Architecture

1. An MCP client calls a tool exposed by `server.py`.
2. The server sends a JSON request over `\\.\pipe\OllyBridge110`.
3. The OllyDbg plugin performs the debugger action on the UI/debugger side.
4. The plugin returns JSON back through the pipe.

## Requirements

- Windows
- Python 3
- the Python `mcp` package
- OllyDbg 1.10
- the OllyDbg 1.10 plugin SDK headers and import libraries needed to build a plugin

## Building the Plugin

The source lives in [`plugin_stub/ollydbg110_bridge.c`](./plugin_stub/ollydbg110_bridge.c).

Build an `OllyBridge110.dll` against the OllyDbg 1.10 SDK using your preferred Windows C toolchain. The resulting DLL should be copied into the plugin directory configured in `ollydbg.ini`.

At a minimum, the build needs to:

- include the OllyDbg 1.10 SDK headers such as `Plugin.h`
- export the expected plugin entry points
- produce a 32-bit DLL compatible with OllyDbg 1.10

The plugin uses real OllyDbg 1.10 APIs including:

- `ODBG_Plugindata`
- `ODBG_Plugininit`
- `ODBG_Pluginmenu`
- `ODBG_Pluginaction`
- `Readmemory`
- `Writememory`
- `Disasm`
- `Setcpu`
- `Plugingetvalue(...)`

## Running the Server

From the repository root:

```powershell
python .\server.py --transport stdio
```

You can also use the helper launcher:

```powershell
powershell -ExecutionPolicy Bypass -File .\start_olly_bridge.ps1 -OllyDir 'C:\Path\To\OllyDbg' -PluginDir 'C:\Path\To\OllyPlugins'
```

By default the Python side expects:

```text
\\.\pipe\OllyBridge110
```

You can override the defaults with environment variables:

- `OLLYDBG_PIPE_NAME`
- `OLLYDBG_BRIDGE_URL`

## Exposed Tool Surface

Current tools include:

- `olly_status`
- `olly_goto_address`
- `olly_read_memory`
- `olly_read_disasm`
- `olly_get_registers`
- `olly_get_eip`
- `olly_current_instruction`
- `olly_goto_eip`
- `olly_read_stack`
- `olly_disasm_from_stack`
- `olly_write_memory`
- `olly_lookup_address`
- `olly_list_breakpoints`
- `olly_list_modules`
- `olly_list_threads`
- `olly_set_breakpoint`
- `olly_clear_breakpoint`
- `olly_set_hardware_breakpoint`
- `olly_clear_hardware_breakpoint`
- `olly_list_hardware_breakpoints`
- `olly_set_label`
- `olly_set_comment`
- `olly_run`
- `olly_step_into`
- `olly_step_over`
- `olly_pause`
- `olly_continue`
- `olly_run_to_address`
- `olly_clear_all_breakpoints`
- `olly_prepare_session`

## Stability Notes

Most reliable in testing:

- status and pause metadata
- register, stack, memory, and disassembly reads
- module, thread, and address lookup helpers
- software breakpoint management
- hardware breakpoint tracking through the bridge
- pause and clean session preparation

Less reliable, especially around unusual target states or packed samples:

- `olly_run` reporting right around startup
- `olly_step_into`
- `olly_step_over`
- `olly_set_label`
- `olly_set_comment`

`olly_write_memory` is intentionally guarded on the Python side and requires `confirm=True`.

## Smoke Test

Run:

```powershell
python .\test_olly_bridge.py
```

Then manually spot-check:

1. `status`
2. `get_eip`
3. `current_instruction`
4. `read_memory`
5. `read_disasm`
6. `lookup_address`
7. `set_breakpoint` and `clear_breakpoint`

## Notes

- This bridge targets OllyDbg 1.10 specifically, not newer debugger families.
- The project is most useful for controlled inspection and automation, not as a replacement for a modern debugger.
- If you publish binaries, prefer GitHub releases or local build output rather than checking them into source control.

## License

MIT. See [`LICENSE`](./LICENSE).
