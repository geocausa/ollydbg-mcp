#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "../plugin_stub/bridge_json.h"

static void test_exact_top_level_fields(void) {
  char output[64];
  int value;
  const char *json =
      "{\"nested\":{\"command\":\"wrong\"},\"command\":\"status\","
      "\"size\":32,\"confirm\":true}";

  assert(bridge_json_extract_string(json, "command", output, sizeof(output)) == 1);
  assert(strcmp(output, "status") == 0);
  assert(bridge_json_extract_int(json, "size", &value) == 1);
  assert(value == 32);
  assert(bridge_json_extract_bool(json, "confirm", &value) == 1);
  assert(value == 1);
  assert(bridge_json_extract_string(json, "missing", output, sizeof(output)) == 0);
}

static void test_escaped_and_unicode_strings(void) {
  char output[128];
  const unsigned char expected[] = {
      'A', 0xC2U, 0xA3U, 0xF0U, 0x9FU, 0x98U, 0x80U, 0
  };
  const char *escaped =
      "{\"text\":\"quote: \\\" slash \\\\ line\\n tab\\t\"}";
  const char *unicode = "{\"text\":\"A\\u00A3\\uD83D\\uDE00\"}";

  assert(bridge_json_extract_string(escaped, "text", output, sizeof(output)) == 1);
  assert(strcmp(output, "quote: \" slash \\ line\n tab\t") == 0);
  assert(bridge_json_extract_string(unicode, "text", output, sizeof(output)) == 1);
  assert(memcmp(output, expected, sizeof(expected)) == 0);
}

static void test_numbers_and_booleans(void) {
  char json[128];
  int value;

  sprintf(json, "{\"value\":%d}", INT_MAX);
  assert(bridge_json_extract_int(json, "value", &value) == 1);
  assert(value == INT_MAX);
  sprintf(json, "{\"value\":%d}", INT_MIN);
  assert(bridge_json_extract_int(json, "value", &value) == 1);
  assert(value == INT_MIN);
  assert(bridge_json_extract_int("{\"value\":1.5}", "value", &value) == 0);
  assert(bridge_json_extract_int("{\"value\":1e2}", "value", &value) == 0);
  assert(bridge_json_extract_bool("{\"value\":false}", "value", &value) == 1);
  assert(value == 0);
}

static void test_complete_document_validation(void) {
  char output[32];
  int value;
  const char *long_unknown_key =
      "{\"this_unknown_key_is_deliberately_much_longer_than_sixty_four_bytes_"
      "and_must_still_be_skipped_safely\":[],\"command\":\"status\"}";

  assert(bridge_json_extract_string(long_unknown_key, "command", output, sizeof(output)) == 1);
  assert(strcmp(output, "status") == 0);
  assert(bridge_json_extract_string(
      "{\"command\":\"one\",\"command\":\"two\"}",
      "command", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"nested\":{\"command\":\"wrong\"}}",
      "command", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"command\":\"status\"} trailing",
      "command", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"command\":\"bad\\q\"}",
      "command", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"command\":\"unterminated}",
      "command", output, sizeof(output)) == 0);
  assert(bridge_json_extract_int("{\"value\":01}", "value", &value) == 0);
}

static void test_bounded_output_and_invalid_unicode(void) {
  char output[5];
  char invalid_utf8[] = {
      '{', '"', 'x', '"', ':', '"', (char)0xC0, (char)0x80, '"', '}', 0
  };

  assert(bridge_json_extract_string(
      "{\"text\":\"too long\"}", "text", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"text\":\"\\u0000\"}", "text", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(
      "{\"text\":\"\\uD800\"}", "text", output, sizeof(output)) == 0);
  assert(bridge_json_extract_string(invalid_utf8, "x", output, sizeof(output)) == 0);
}

int main(void) {
  test_exact_top_level_fields();
  test_escaped_and_unicode_strings();
  test_numbers_and_booleans();
  test_complete_document_validation();
  test_bounded_output_and_invalid_unicode();
  puts("native JSON parser tests passed");
  return 0;
}
