from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MOCK_STATE = {
    "process": "mock-target.exe",
    "pid": 31337,
    "current_address": "0x00401000",
    "registers": {
        "eax": "0x00000001",
        "ebx": "0x00405000",
        "ecx": "0x00000000",
        "edx": "0x7ffd9000",
        "esi": "0x00406000",
        "edi": "0x00407000",
        "esp": "0x0019ff10",
        "ebp": "0x0019ff6c",
        "eip": "0x00401000",
    },
}


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload: dict) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        payload = json.loads(body.decode("utf-8"))

        if self.path == "/status":
            self._send({"ok": True, **MOCK_STATE})
            return

        if self.path == "/goto-address":
            address = payload.get("address", "0x00000000")
            MOCK_STATE["current_address"] = address
            MOCK_STATE["registers"]["eip"] = address
            self._send({"ok": True, "address": address})
            return

        if self.path == "/read-memory":
            address = payload.get("address", "0x00000000")
            size = int(payload.get("size", 0))
            self._send(
                {
                    "ok": True,
                    "address": address,
                    "size": size,
                    "hex": "90" * size,
                }
            )
            return

        if self.path == "/read-disasm":
            address = payload.get("address", "0x00000000")
            count = int(payload.get("count", 8))
            lines = []
            base = int(address, 16)
            for index in range(count):
                lines.append(
                    {
                        "address": f"0x{base + (index * 2):08X}",
                        "instruction": "nop",
                        "size": 1,
                    }
                )
            self._send({"ok": True, "address": address, "lines": lines})
            return

        if self.path == "/get-registers":
            self._send({"ok": True, "registers": MOCK_STATE["registers"]})
            return

        self._send({"ok": False, "error": f"Unsupported path: {self.path}"})


def main() -> None:
    host = "127.0.0.1"
    port = 31337
    print(f"Mock OllyDbg bridge listening on http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
