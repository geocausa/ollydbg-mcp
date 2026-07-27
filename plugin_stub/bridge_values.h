#ifndef OLLYBRIDGE_VALUES_H
#define OLLYBRIDGE_VALUES_H

#include <stddef.h>

static int bridge_hex_digit_value(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static int bridge_is_horizontal_space(char ch) {
  return ch == ' ' || ch == '\t';
}

static int bridge_parse_u32_hex(const char *text, unsigned long *value) {
  unsigned long parsed = 0;
  int digit;
  int digits = 0;
  if (text == NULL || value == NULL) return 0;

  while (bridge_is_horizontal_space(*text)) text++;
  if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;

  while ((digit = bridge_hex_digit_value(*text)) >= 0) {
    if (digits >= 8) return 0;
    parsed = (parsed << 4) | (unsigned long)digit;
    digits++;
    text++;
  }
  if (digits == 0) return 0;
  while (bridge_is_horizontal_space(*text)) text++;
  if (*text != '\0') return 0;

  *value = parsed;
  return 1;
}

static int bridge_parse_hex_bytes(
    const char *text,
    unsigned char *out,
    int max_bytes) {
  size_t length = 0;
  int index;
  if (text == NULL || out == NULL || max_bytes <= 0) return -1;

  while (bridge_is_horizontal_space(*text)) text++;
  while (bridge_hex_digit_value(text[length]) >= 0) length++;
  if (length == 0 || (length % 2) != 0 || length > (size_t)max_bytes * 2) return -1;
  {
    const char *tail = text + length;
    while (bridge_is_horizontal_space(*tail)) tail++;
    if (*tail != '\0') return -1;
  }

  for (index = 0; index < (int)(length / 2); index++) {
    int high = bridge_hex_digit_value(text[index * 2]);
    int low = bridge_hex_digit_value(text[(index * 2) + 1]);
    if (high < 0 || low < 0) return -1;
    out[index] = (unsigned char)((high << 4) | low);
  }
  return (int)(length / 2);
}

#endif
