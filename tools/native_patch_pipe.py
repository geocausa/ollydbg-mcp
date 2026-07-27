from pathlib import Path
P = Path('plugin_stub/ollydbg110_bridge.c')
s = P.read_text(encoding='utf-8')
old = r'''static DWORD WINAPI pipe_thread_main(LPVOID param) {
  (void)param;
  InterlockedExchange(&g_running, 1);
  while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
    HANDLE pipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        250,
        NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
      Sleep(250);
      continue;
    }

    if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
      char request[PIPE_BUFFER_SIZE];
      char response[PIPE_BUFFER_SIZE];
      DWORD read = 0;
      DWORD written = 0;
      ZeroMemory(request, sizeof(request));
      ZeroMemory(response, sizeof(response));
      if (ReadFile(pipe, request, sizeof(request) - 1, &read, NULL) && read > 0) {
        request[read] = '\0';
        dispatch_request(request, response, sizeof(response));
      }
      else {
        respond_error(response, sizeof(response), "Failed to read from pipe");
      }
      WriteFile(pipe, response, (DWORD)strlen(response), &written, NULL);
      FlushFileBuffers(pipe);
    }
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
  }
  InterlockedExchange(&g_running, 0);
  return 0;
}
'''
new = r'''static int wait_for_pipe_io(HANDLE pipe, OVERLAPPED *ov, DWORD *done) {
  HANDLE waits[2]; DWORD wr;
  waits[0] = g_stop_event; waits[1] = ov->hEvent;
  wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
  if (wr == WAIT_OBJECT_0) {
    CancelIo(pipe); WaitForSingleObject(ov->hEvent, 1000); return 0;
  }
  if (wr != WAIT_OBJECT_0 + 1) return 0;
  return GetOverlappedResult(pipe, ov, done, FALSE) != 0;
}

static int connect_pipe_overlapped(HANDLE pipe, OVERLAPPED *ov) {
  DWORD done = 0; ResetEvent(ov->hEvent);
  if (ConnectNamedPipe(pipe, ov)) return 1;
  if (GetLastError() == ERROR_PIPE_CONNECTED) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, &done);
}

static int read_pipe_overlapped(HANDLE pipe, void *buf, DWORD size, DWORD *read, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *read = 0;
  if (ReadFile(pipe, buf, size, read, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, read);
}

static int write_pipe_overlapped(HANDLE pipe, const void *buf, DWORD size, DWORD *written, OVERLAPPED *ov) {
  ResetEvent(ov->hEvent); *written = 0;
  if (WriteFile(pipe, buf, size, written, ov)) return 1;
  if (GetLastError() != ERROR_IO_PENDING) return 0;
  return wait_for_pipe_io(pipe, ov, written);
}

static DWORD WINAPI pipe_thread_main(LPVOID param) {
  SECURITY_ATTRIBUTES sa; PSECURITY_DESCRIPTOR sd = NULL;
  (void)param; ZeroMemory(&sa, sizeof(sa)); sa.nLength = sizeof(sa);
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
          "D:P(A;;GA;;;OW)", SDDL_REVISION_1, &sd, NULL)) {
    log_line("OllyBridge110: unable to create owner-only pipe ACL"); return 1;
  }
  sa.lpSecurityDescriptor = sd;
  InterlockedExchange(&g_running, 1);
  while (WaitForSingleObject(g_stop_event, 0) == WAIT_TIMEOUT) {
    HANDLE pipe; OVERLAPPED ov; char request[PIPE_BUFFER_SIZE];
    char response[PIPE_BUFFER_SIZE]; DWORD read = 0, written = 0;
    ZeroMemory(&ov, sizeof(ov)); ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL) break;
    pipe = CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 250, &sa);
    if (pipe == INVALID_HANDLE_VALUE) {
      CloseHandle(ov.hEvent);
      if (WaitForSingleObject(g_stop_event, 250) == WAIT_OBJECT_0) break;
      continue;
    }
    if (connect_pipe_overlapped(pipe, &ov)) {
      ZeroMemory(request, sizeof(request)); ZeroMemory(response, sizeof(response));
      if (read_pipe_overlapped(pipe, request, sizeof(request) - 1, &read, &ov) && read > 0) {
        request[read] = '\0'; dispatch_request(request, response, sizeof(response));
      }
      else if (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
        respond_error(response, sizeof(response), "Failed to read from pipe");
      }
      if (response[0] != '\0' && WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0)
        write_pipe_overlapped(pipe, response, (DWORD)strlen(response), &written, &ov);
    }
    DisconnectNamedPipe(pipe); CloseHandle(pipe); CloseHandle(ov.hEvent);
  }
  InterlockedExchange(&g_running, 0); LocalFree(sd); return 0;
}
'''
if s.count(old) != 1:
    raise RuntimeError(f'pipe block: expected 1 match, found {s.count(old)}')
P.write_text(s.replace(old, new, 1), encoding='utf-8', newline='\n')
