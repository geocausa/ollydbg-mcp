from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


named_pipe_tests = ROOT / "tests" / "test_named_pipe_windows.py"
replace_once(
    named_pipe_tests,
    '''def make_transport(server: WindowsPipeServer, **overrides: Any) -> NamedPipeTransport:''',
    '''class WindowsPipeStallServer:
    def __init__(self, hold_seconds: float = 0.25) -> None:
        self.pipe_name = rf"\\\\.\\pipe\\OllyBridgeStall-{uuid.uuid4()}"
        self.hold_seconds = hold_seconds
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()
        if not self.ready.wait(timeout=5):
            raise AssertionError("stalled named-pipe server did not start")
        if self.error is not None:
            raise self.error

    def join(self) -> None:
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise AssertionError("stalled named-pipe server did not stop")
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        invalid_handle = ctypes.c_void_p(-1).value
        error_pipe_connected = 535

        create_named_pipe = kernel32.CreateNamedPipeW
        create_named_pipe.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_named_pipe.restype = ctypes.c_void_p

        connect_named_pipe = kernel32.ConnectNamedPipe
        connect_named_pipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        connect_named_pipe.restype = ctypes.c_int

        disconnect_named_pipe = kernel32.DisconnectNamedPipe
        disconnect_named_pipe.argtypes = [ctypes.c_void_p]
        disconnect_named_pipe.restype = ctypes.c_int

        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int

        pipe = create_named_pipe(
            self.pipe_name,
            0x00000003,
            0x00000000,
            1,
            4096,
            4096,
            1000,
            None,
        )
        if pipe == invalid_handle:
            self.error = OSError(ctypes.get_last_error(), "CreateNamedPipeW failed")
            self.ready.set()
            return

        self.ready.set()
        try:
            if not connect_named_pipe(pipe, None):
                error = ctypes.get_last_error()
                if error != error_pipe_connected:
                    raise OSError(error, "ConnectNamedPipe failed")
            time.sleep(self.hold_seconds)
        except BaseException as exc:
            self.error = exc
        finally:
            disconnect_named_pipe(pipe)
            close_handle(pipe)


def make_transport(server: WindowsPipeServer, **overrides: Any) -> NamedPipeTransport:''',
    "stalled pipe server",
)
replace_once(
    named_pipe_tests,
    '''def test_unavailable_real_named_pipe_fails_cleanly() -> None:''',
    '''def test_real_named_pipe_write_is_cancelled_at_deadline() -> None:
    server = WindowsPipeStallServer()
    server.start()
    transport = NamedPipeTransport(
        pipe_name=server.pipe_name,
        timeout_seconds=0.05,
        retries=1,
        retry_delay_seconds=0.01,
    )
    started = time.monotonic()

    with pytest.raises(BridgeError, match="timed out.*writing request"):
        transport.request({"command": "status", "padding": "x" * (4 * 1024 * 1024)})

    elapsed = time.monotonic() - started
    server.join()
    assert elapsed < 1.0


def test_unavailable_real_named_pipe_fails_cleanly() -> None:''',
    "overlapped write deadline test",
)

transport_tests = ROOT / "tests" / "test_transport.py"
transport_text = transport_tests.read_text(encoding="utf-8")
transport_text += '''


def test_transport_source_uses_cancellable_overlapped_io() -> None:
    source = (ROOT / "ollydbg_mcp" / "transport.py").read_text(encoding="utf-8")
    assert "FILE_FLAG_OVERLAPPED" in source
    assert "CancelIoEx" in source
    assert "GetOverlappedResult" in source
    assert 'finish_overlapped(write_overlapped, written, "writing request")' in source
'''
transport_text = transport_text.replace(
    "from collections.abc import Iterable\n",
    "from collections.abc import Iterable\nfrom pathlib import Path\n",
    1,
)
transport_text = transport_text.replace(
    "from ollydbg_mcp.transport import NamedPipeTransport\n",
    "from ollydbg_mcp.transport import NamedPipeTransport\n\nROOT = Path(__file__).resolve().parents[1]\n",
    1,
)
transport_tests.write_text(transport_text, encoding="utf-8")
