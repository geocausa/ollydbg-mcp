# OllyDbg MCP Bridge

This folder contains a working MCP bridge for **OllyDbg 1.10** so Codex can read and lightly control the debugger without scraping the UI.

## What is here

- `server.py`
  - the MCP server built with the installed Python `mcp` package
  - talks directly to `\\.\pipe\OllyBridge110`
- `plugin_stub/ollydbg110_bridge.c`
  - the OllyDbg 1.10 plugin bridge source
- `test_olly_bridge.py`
  - a smoke-test script for the bridge
- `start_olly_bridge.ps1`
  - convenience launcher for the MCP server

## Architecture

1. Codex talks to the MCP server.
2. The MCP server calls a named pipe exposed by the OllyDbg plugin.
3. The plugin performs the requested debugger action and returns JSON.

This keeps the bridge small and practical while still covering the reverse-engineering tasks we care about.

## Quick start

Run the MCP server in a terminal:

```powershell
python .\server.py --transport stdio
```

Or use the helper script:

```powershell
powershell -ExecutionPolicy Bypass -File .\start_olly_bridge.ps1 -OllyDir 'C:\Path\To\OllyDbg' -PluginDir 'C:\Path\To\OllyPlugins'
```

By default the server expects the pipe:

```text
\\.\pipe\OllyBridge110
```

## OllyDbg 1.10 target

This build is aimed at **OllyDbg 1.10**.

You will need:

- an OllyDbg 1.10 installation
- the OllyDbg 1.10 plugin SDK
- a plugin directory configured in `ollydbg.ini`

The plugin uses real 1.10 API entry points such as:

- `ODBG_Plugindata`
- `ODBG_Plugininit`
- `ODBG_Pluginmenu`
- `ODBG_Pluginaction`
- `Readmemory`
- `Writememory`
- `Disasm`
- `Setcpu`
- `Plugingetvalue(...)`

## Exposed tools

Current tool surface:

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

## Stability notes

Most reliable today:

- reads and disassembly
- EIP/current-instruction helpers
- module/address lookup
- native run-to-address / continue on the UI thread
- clean session preparation / breakpoint cleanup
- decoded pause and trap metadata
- software breakpoints
- hardware breakpoints tracked through the bridge
- stack helpers
- pause

Less reliable in the current Windows-on-ARM setup:

- `olly_run` state reporting right around startup can still be noisy
- `olly_step_into`
- `olly_step_over`
- `olly_set_label`
- `olly_set_comment`

`olly_write_memory` is intentionally guarded on the Python side and requires `confirm=True`.

The plugin now also reports native pause metadata from OllyDbg:

- `last_pause_reason`
- `last_pause_reasonex`
- `last_pause_eip`

The MCP layer decodes these into:

- `debug_status_name`
- `pause_info.main`
- `pause_info.flags`
- `pause_info.summary`

## Recommended smoke test

Run:

```powershell
python .\ollydbg_mcp\test_olly_bridge.py
```

Then manually spot-check:

1. `status`
2. `get_eip`
3. `current_instruction`
4. `read_memory`
5. `read_disasm`
6. `lookup_address`
7. `set_breakpoint` / `clear_breakpoint`

## Public repo notes

This repository is intentionally source-first:

- generated Python cache files are excluded
- local build artifacts such as `.dll`, `.pdb`, `.lib`, and `.o` are excluded
- machine-specific launch paths are not hardcoded into the checked-in scripts

If you publish this bridge, keep compiled plugin binaries in local build output or release assets rather than in the main source tree.
