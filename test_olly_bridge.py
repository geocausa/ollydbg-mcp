"""Backward-compatible entry point for the structured runtime smoke test."""

from ollydbg_mcp.smoke import main


if __name__ == "__main__":
    raise SystemExit(main())
