from pathlib import Path

path = Path(__file__).resolve().parents[1] / "plugin_stub" / "ollydbg110_bridge.c"
text = path.read_text(encoding="utf-8")
block = r'''static void wait_for_client_close(HANDLE pipe, OVERLAPPED *ov) {
  char ignored;
  DWORD read = 0;
  DWORD error;
  ResetEvent(ov->hEvent);
  if (ReadFile(pipe, &ignored, 1, &read, ov)) return;
  error = GetLastError();
  if (error == ERROR_BROKEN_PIPE || error == ERROR_NO_DATA ||
      error == ERROR_PIPE_NOT_CONNECTED) return;
  if (error != ERROR_IO_PENDING) return;
  wait_for_pipe_io_timeout(
      pipe, ov, &read, PIPE_CLIENT_DRAIN_TIMEOUT_MS);
}
'''

doubled = block + "\n" + block
if doubled in text:
    text = text.replace(doubled, block, 1)
elif text.count(block) != 1:
    raise RuntimeError(
        f"expected one or two client-close helpers, found {text.count(block)}"
    )

path.write_text(text, encoding="utf-8")
