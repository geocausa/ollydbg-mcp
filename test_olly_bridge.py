"""Manual smoke test against a running OllyDbg plugin."""

from ollydbg_mcp import OllyBridgeClient


def main() -> None:
    client = OllyBridgeClient()
    print("status:", client.status())
    print("capabilities:", client.get_capabilities())
    print("snapshot:", client.snapshot())


if __name__ == "__main__":
    main()
