from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "plugin_stub" / "ollydbg110_bridge.c").read_text(encoding="utf-8")
EXPORTS = (ROOT / "plugin_stub" / "OllyBridge110.def").read_text(encoding="utf-8")


def test_pipe_is_local_owner_only_and_interruptible() -> None:
    assert '"D:P(A;;GA;;;OW)"' in SOURCE
    assert "PIPE_REJECT_REMOTE_CLIENTS" in SOURCE
    assert "FILE_FLAG_OVERLAPPED" in SOURCE
    assert "WaitForMultipleObjects" in SOURCE
    assert "CancelIo(pipe)" in SOURCE
    assert "FlushFileBuffers" not in SOURCE


def test_pause_sequence_is_native_and_exported() -> None:
    assert "g_pause_sequence" in SOURCE
    assert 'strcmp(command, "wait_for_pause") == 0' in SOURCE
    assert '\\"pause_sequence\\"' in SOURCE
    assert "WaitForSingleObject(g_pipe_thread, INFINITE)" in SOURCE
    assert "_ODBG_Paused" in EXPORTS
    assert "_ODBG_Pausedex" in EXPORTS


def test_json_and_response_construction_are_bounded() -> None:
    assert "static int append_format(" in SOURCE
    assert "used += (size_t)snprintf" not in SOURCE
    assert "end = strchr(start, '\"')" not in SOURCE
    assert "used + 1 >= out_size" in SOURCE
    assert '#pragma comment(lib, "Advapi32.lib")' in SOURCE


def test_native_protocol_identifies_capabilities() -> None:
    assert "#define BRIDGE_PROTOCOL_VERSION 2" in SOURCE
    assert "#define BRIDGE_PLUGIN_VERSION \"2.0\"" in SOURCE
    for capability in (
        "native_wait_for_pause",
        "owner_only_pipe",
        "overlapped_pipe",
        "remote_clients",
    ):
        assert capability in SOURCE
