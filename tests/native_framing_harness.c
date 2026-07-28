#include <stdio.h>
#include <string.h>

#include "../plugin_stub/bridge_framing.h"

static int failures = 0;

static void expect(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
  }
}

static void test_fragmented_request(void) {
  static const char first[] = "{\"command\":";
  static const char second[] = "\"status\"}\n";
  bridge_frame_state state;
  char output[64];
  int result;
  bridge_frame_init(&state);
  result = bridge_frame_append(
      &state, output, sizeof(output), first, sizeof(first) - 1);
  expect(result == BRIDGE_FRAME_MORE, "first fragment should remain incomplete");
  result = bridge_frame_append(
      &state, output, sizeof(output), second, sizeof(second) - 1);
  expect(result == BRIDGE_FRAME_COMPLETE, "second fragment should complete request");
  expect(strcmp(output, "{\"command\":\"status\"}") == 0, "fragments should join exactly");
}

static void test_bytewise_request(void) {
  static const char request[] = "{\"command\":\"status\"}\n";
  bridge_frame_state state;
  char output[64];
  size_t index;
  int result = BRIDGE_FRAME_MORE;
  bridge_frame_init(&state);
  for (index = 0; index < sizeof(request) - 1; index++) {
    result = bridge_frame_append(&state, output, sizeof(output), request + index, 1);
  }
  expect(result == BRIDGE_FRAME_COMPLETE, "bytewise request should complete");
  expect(strcmp(output, "{\"command\":\"status\"}") == 0, "bytewise framing should preserve request");
}

static void test_crlf_and_trailing_bytes(void) {
  static const char request[] = "{\"command\":\"status\"}\r\nignored";
  bridge_frame_state state;
  char output[64];
  int result;
  bridge_frame_init(&state);
  result = bridge_frame_append(
      &state, output, sizeof(output), request, sizeof(request) - 1);
  expect(result == BRIDGE_FRAME_COMPLETE, "CRLF request should complete");
  expect(strcmp(output, "{\"command\":\"status\"}") == 0, "CR should be removed and trailing bytes ignored");
}

static void test_overflow(void) {
  static const char request[] = "12345678";
  bridge_frame_state state;
  char output[8];
  int result;
  bridge_frame_init(&state);
  result = bridge_frame_append(
      &state, output, sizeof(output), request, sizeof(request) - 1);
  expect(result == BRIDGE_FRAME_OVERFLOW, "full buffer without newline should overflow");
  expect(state.overflowed == 1, "overflow flag should be retained");
  expect(output[sizeof(output) - 1] == '\0', "overflowed output should remain terminated");
}

int main(void) {
  test_fragmented_request();
  test_bytewise_request();
  test_crlf_and_trailing_bytes();
  test_overflow();
  if (failures != 0) return 1;
  puts("native framing harness passed");
  return 0;
}
