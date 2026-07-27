"""Backward-compatible entry point for the structured runtime smoke test."""

import runpy


if __name__ == "__main__":
    runpy.run_module("ollydbg_mcp.smoke", run_name="__main__")
