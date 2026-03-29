from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ollydbg_mcp.server import OllyBridgeClient


def main() -> None:
    client = OllyBridgeClient()
    print("status:", client.status())
    print("registers:", client.get_registers())
    print("disasm:", client.read_disasm("0x01A2B34C", 3))
    print("memory:", client.read_memory("0x01A2B34C", 16))


if __name__ == "__main__":
    main()
