from __future__ import annotations

import argparse
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from .client import OllyBridgeClient
from .protocol import DEFAULT_PIPE_NAME, DEFAULT_TIMEOUT_SECONDS, positive


def build_server(client: OllyBridgeClient | None = None) -> FastMCP:
    bridge = client or OllyBridgeClient()
    mcp = FastMCP(
        name="ollydbg-bridge",
        instructions=(
            "Connects to a localhost named-pipe bridge for controlled OllyDbg 1.10 "
            "inspection and debugging automation. Write and bulk-clear operations "
            "require explicit confirmation arguments."
        ),
    )

    @mcp.tool(description="Check whether the local OllyDbg bridge is reachable.")
    def olly_status() -> dict[str, Any]:
        return bridge.status()

    @mcp.tool(description="Report bridge protocol and client capability information.")
    def olly_get_capabilities() -> dict[str, Any]:
        return bridge.get_capabilities()

    @mcp.tool(description="Capture status, registers, EIP, stack and nearby disassembly.")
    def olly_snapshot(stack_size: int = 64, disasm_count: int = 8) -> dict[str, Any]:
        return bridge.snapshot(stack_size, disasm_count)

    @mcp.tool(description="Move the OllyDbg CPU/disassembly view to a specific address.")
    def olly_goto_address(address: str) -> dict[str, Any]:
        return bridge.goto_address(address)

    @mcp.tool(description="Read up to 1024 bytes of debuggee memory as hexadecimal.")
    def olly_read_memory(address: str, size: int) -> dict[str, Any]:
        return bridge.read_memory(address, size)

    @mcp.tool(description="Read up to 32 disassembly lines starting at an address.")
    def olly_read_disasm(address: str, count: int = 8) -> dict[str, Any]:
        return bridge.read_disasm(address, count)

    @mcp.tool(description="Read the current general-purpose register snapshot.")
    def olly_get_registers() -> dict[str, Any]:
        return bridge.get_registers()

    @mcp.tool(description="Read the current EIP from the active CPU thread.")
    def olly_get_eip() -> dict[str, Any]:
        return bridge.get_eip()

    @mcp.tool(description="Read the current disassembly line at EIP.")
    def olly_current_instruction() -> dict[str, Any]:
        return bridge.current_instruction()

    @mcp.tool(description="Move the CPU/disassembly view to the current EIP.")
    def olly_goto_eip() -> dict[str, Any]:
        return bridge.goto_eip()

    @mcp.tool(description="Read bytes from the current stack pointer.")
    def olly_read_stack(size: int = 64) -> dict[str, Any]:
        return bridge.read_stack(size)

    @mcp.tool(description="Treat a DWORD on the stack as a code pointer and disassemble it.")
    def olly_disasm_from_stack(offset: int = 0, count: int = 8) -> dict[str, Any]:
        return bridge.disasm_from_stack(offset, count)

    @mcp.tool(description="Write debuggee memory. Requires confirm=true.")
    def olly_write_memory(address: str, hex_bytes: str, confirm: bool = False) -> dict[str, Any]:
        return bridge.write_memory(address, hex_bytes, confirm)

    @mcp.tool(description="Look up module and memory-block information for an address.")
    def olly_lookup_address(address: str) -> dict[str, Any]:
        return bridge.lookup_address(address)

    @mcp.tool(description="List software breakpoints known to OllyDbg.")
    def olly_list_breakpoints() -> dict[str, Any]:
        return bridge.list_breakpoints()

    @mcp.tool(description="Clear all software breakpoints. Requires confirm=true.")
    def olly_clear_all_breakpoints(confirm: bool = False) -> dict[str, Any]:
        return bridge.clear_all_breakpoints(confirm)

    @mcp.tool(description="List modules known to OllyDbg.")
    def olly_list_modules() -> dict[str, Any]:
        return bridge.list_modules()

    @mcp.tool(description="List active threads known to OllyDbg.")
    def olly_list_threads() -> dict[str, Any]:
        return bridge.list_threads()

    @mcp.tool(description="Set a software breakpoint at an address.")
    def olly_set_breakpoint(address: str) -> dict[str, Any]:
        return bridge.set_breakpoint(address)

    @mcp.tool(description="Clear the software breakpoint at an address.")
    def olly_clear_breakpoint(address: str) -> dict[str, Any]:
        return bridge.clear_breakpoint(address)

    @mcp.tool(description="Set a validated hardware breakpoint at an address.")
    def olly_set_hardware_breakpoint(
        address: str,
        type: Literal["execute", "access", "write"] = "execute",
        size: Literal[1, 2, 4] = 1,
    ) -> dict[str, Any]:
        return bridge.set_hardware_breakpoint(address, type, size)

    @mcp.tool(description="Clear a hardware breakpoint by slot index 0 through 3.")
    def olly_clear_hardware_breakpoint(index: int) -> dict[str, Any]:
        return bridge.clear_hardware_breakpoint(index)

    @mcp.tool(description="List hardware breakpoints tracked by this bridge.")
    def olly_list_hardware_breakpoints() -> dict[str, Any]:
        return bridge.list_hardware_breakpoints()

    @mcp.tool(description="Set a user label at an address.")
    def olly_set_label(address: str, text: str) -> dict[str, Any]:
        return bridge.set_label(address, text)

    @mcp.tool(description="Set a user comment at an address.")
    def olly_set_comment(address: str, text: str) -> dict[str, Any]:
        return bridge.set_comment(address, text)

    @mcp.tool(description="Run the debuggee, optionally toward an address.")
    def olly_run(address: str | None = None, give_chance: bool = False) -> dict[str, Any]:
        return bridge.run(address, give_chance)

    @mcp.tool(description="Step into one instruction and wait for a new pause state.")
    def olly_step_into() -> dict[str, Any]:
        return bridge.step_into()

    @mcp.tool(description="Step over one instruction and wait for a new pause state.")
    def olly_step_over() -> dict[str, Any]:
        return bridge.step_over()

    @mcp.tool(description="Pause the debuggee.")
    def olly_pause() -> dict[str, Any]:
        return bridge.pause()

    @mcp.tool(description="Continue execution.")
    def olly_continue() -> dict[str, Any]:
        return bridge.continue_execution()

    @mcp.tool(description="Wait for OllyDbg to enter a new paused state.")
    def olly_wait_for_pause(
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
        after_sequence: int | None = None,
    ) -> dict[str, Any]:
        return bridge.wait_for_pause(timeout_seconds, poll_interval_seconds, after_sequence)

    @mcp.tool(description="Run toward an address and wait until EIP reaches it.")
    def olly_run_to_address(
        address: str,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.05,
    ) -> dict[str, Any]:
        return bridge.run_to_address(address, timeout_seconds, poll_interval_seconds)

    @mcp.tool(description="Wait for a module and optionally clear breakpoints explicitly.")
    def olly_prepare_session(
        module_name: str | None = None,
        timeout_seconds: float = 5.0,
        poll_interval_seconds: float = 0.1,
        clear_breakpoints: bool = False,
        confirm_clear: bool = False,
    ) -> dict[str, Any]:
        return bridge.prepare_session(
            module_name,
            timeout_seconds,
            poll_interval_seconds,
            clear_breakpoints,
            confirm_clear,
        )

    return mcp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the OllyDbg MCP bridge server.")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http", "sse"),
        default="stdio",
        help="MCP transport to serve.",
    )
    parser.add_argument("--pipe-name", default=DEFAULT_PIPE_NAME)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    positive(args.timeout, "timeout", 300)
    client = OllyBridgeClient(pipe_name=args.pipe_name, timeout_seconds=args.timeout)
    build_server(client).run(args.transport)


if __name__ == "__main__":
    main()
