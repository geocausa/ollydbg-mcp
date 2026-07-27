#include <stdio.h>
#include <string.h>

#include "../plugin_stub/bridge_values.h"

static int failures = 0;

static void expect_address(const char *text, int expected_ok, unsigned long expected) {
  unsigned long value = 0xDEADBEEFUL;
  int ok = bridge_parse_u32_hex(text, &value);
  if (ok != expected_ok || (ok && value != expected)) {
    fprintf(stderr, "address parse mismatch for '%s': ok=%d value=%08lX\n", text, ok, value);
    failures++;
  }
}

static void expect_bytes(const char *text, int max_bytes, const unsigned char *expected, int expected_count) {
  unsigned char output[16];
  int count;
  memset(output, 0xCC, sizeof(output));
  count = bridge_parse_hex_bytes(text, output, max_bytes);
  if (count != expected_count) {
    fprintf(stderr, "byte parse count mismatch for '%s': %d != %d\n", text, count, expected_count);
    failures++;
    return;
  }
  if (count > 0 && memcmp(output, expected, (size_t)count) != 0) {
    fprintf(stderr, "byte parse data mismatch for '%s'\n", text);
    failures++;
  }
}

int main(void) {
  static const unsigned char bytes[] = {0x00, 0x11, 0xAA, 0xFF};

  expect_address("0", 1, 0x00000000UL);
  expect_address("0x00401000", 1, 0x00401000UL);
  expect_address(" FFFFFFFF ", 1, 0xFFFFFFFFUL);
  expect_address("0Xabcdef01", 1, 0xABCDEF01UL);
  expect_address("", 0, 0);
  expect_address("0x", 0, 0);
  expect_address("100000000", 0, 0);
  expect_address("0x00401000junk", 0, 0);
  expect_address("-1", 0, 0);
  expect_address("12:34", 0, 0);

  expect_bytes("0011AAFF", 4, bytes, 4);
  expect_bytes(" 0011aaff ", 4, bytes, 4);
  expect_bytes("", 4, bytes, -1);
  expect_bytes("0", 4, bytes, -1);
  expect_bytes("0011AAGG", 4, bytes, -1);
  expect_bytes("00 11", 4, bytes, -1);
  expect_bytes("0011AAFF00", 4, bytes, -1);

  if (failures != 0) {
    fprintf(stderr, "%d native value parser test(s) failed\n", failures);
    return 1;
  }
  puts("native value parser tests passed");
  return 0;
}
