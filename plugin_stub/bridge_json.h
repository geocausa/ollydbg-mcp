#ifndef OLLYBRIDGE_JSON_H
#define OLLYBRIDGE_JSON_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define BRIDGE_JSON_MAX_DEPTH 16

typedef enum bridge_json_type {
  BRIDGE_JSON_INVALID = 0,
  BRIDGE_JSON_NULL,
  BRIDGE_JSON_FALSE,
  BRIDGE_JSON_TRUE,
  BRIDGE_JSON_NUMBER,
  BRIDGE_JSON_STRING,
  BRIDGE_JSON_ARRAY,
  BRIDGE_JSON_OBJECT
} bridge_json_type;

typedef struct bridge_json_value {
  const char *start;
  const char *end;
  bridge_json_type type;
} bridge_json_value;

typedef struct bridge_json_cursor {
  const char *current;
} bridge_json_cursor;

static void bridge_json_skip_whitespace(bridge_json_cursor *cursor) {
  while (*cursor->current == ' ' || *cursor->current == '\t' ||
         *cursor->current == '\r' || *cursor->current == '\n') {
    cursor->current++;
  }
}

static int bridge_json_hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static int bridge_json_parse_hex4(const char **input, unsigned long *value) {
  int index;
  unsigned long result = 0;
  for (index = 0; index < 4; index++) {
    int digit;
    if ((*input)[index] == '\0') return 0;
    digit = bridge_json_hex_digit((*input)[index]);
    if (digit < 0) return 0;
    result = (result << 4) | (unsigned long)digit;
  }
  *input += 4;
  *value = result;
  return 1;
}

static int bridge_json_is_continuation(unsigned char ch) {
  return (ch & 0xC0U) == 0x80U;
}

static int bridge_json_parse_raw_utf8(const char **input, unsigned long *codepoint) {
  const unsigned char *text = (const unsigned char *)*input;
  unsigned char first = text[0];
  unsigned long result;

  if (first < 0x80U) {
    *codepoint = first;
    *input += 1;
    return 1;
  }

  if (first >= 0xC2U && first <= 0xDFU) {
    if (text[1] == 0 || !bridge_json_is_continuation(text[1])) return 0;
    result = ((unsigned long)(first & 0x1FU) << 6) |
             (unsigned long)(text[1] & 0x3FU);
    *input += 2;
    *codepoint = result;
    return 1;
  }

  if (first >= 0xE0U && first <= 0xEFU) {
    if (text[1] == 0 || text[2] == 0 ||
        !bridge_json_is_continuation(text[1]) ||
        !bridge_json_is_continuation(text[2])) return 0;
    if (first == 0xE0U && text[1] < 0xA0U) return 0;
    if (first == 0xEDU && text[1] >= 0xA0U) return 0;
    result = ((unsigned long)(first & 0x0FU) << 12) |
             ((unsigned long)(text[1] & 0x3FU) << 6) |
             (unsigned long)(text[2] & 0x3FU);
    *input += 3;
    *codepoint = result;
    return 1;
  }

  if (first >= 0xF0U && first <= 0xF4U) {
    if (text[1] == 0 || text[2] == 0 || text[3] == 0 ||
        !bridge_json_is_continuation(text[1]) ||
        !bridge_json_is_continuation(text[2]) ||
        !bridge_json_is_continuation(text[3])) return 0;
    if (first == 0xF0U && text[1] < 0x90U) return 0;
    if (first == 0xF4U && text[1] >= 0x90U) return 0;
    result = ((unsigned long)(first & 0x07U) << 18) |
             ((unsigned long)(text[1] & 0x3FU) << 12) |
             ((unsigned long)(text[2] & 0x3FU) << 6) |
             (unsigned long)(text[3] & 0x3FU);
    if (result > 0x10FFFFUL) return 0;
    *input += 4;
    *codepoint = result;
    return 1;
  }

  return 0;
}

static int bridge_json_next_string_codepoint(
    bridge_json_cursor *cursor,
    unsigned long *codepoint,
    int *finished) {
  const char *input = cursor->current;
  unsigned long first_escape;

  *finished = 0;
  if (*input == '\0') return 0;
  if (*input == '"') {
    cursor->current = input + 1;
    *finished = 1;
    return 1;
  }
  if ((unsigned char)*input < 0x20U) return 0;

  if (*input != '\\') {
    if (!bridge_json_parse_raw_utf8(&input, codepoint)) return 0;
    cursor->current = input;
    return 1;
  }

  input++;
  if (*input == '\0') return 0;
  switch (*input) {
    case '"': *codepoint = '"'; input++; break;
    case '\\': *codepoint = '\\'; input++; break;
    case '/': *codepoint = '/'; input++; break;
    case 'b': *codepoint = 0x08UL; input++; break;
    case 'f': *codepoint = 0x0CUL; input++; break;
    case 'n': *codepoint = 0x0AUL; input++; break;
    case 'r': *codepoint = 0x0DUL; input++; break;
    case 't': *codepoint = 0x09UL; input++; break;
    case 'u':
      input++;
      if (!bridge_json_parse_hex4(&input, &first_escape)) return 0;
      if (first_escape >= 0xD800UL && first_escape <= 0xDBFFUL) {
        unsigned long second_escape;
        if (input[0] != '\\' || input[1] != 'u') return 0;
        input += 2;
        if (!bridge_json_parse_hex4(&input, &second_escape)) return 0;
        if (second_escape < 0xDC00UL || second_escape > 0xDFFFUL) return 0;
        *codepoint = 0x10000UL +
            ((first_escape - 0xD800UL) << 10) +
            (second_escape - 0xDC00UL);
      }
      else {
        if (first_escape >= 0xDC00UL && first_escape <= 0xDFFFUL) return 0;
        *codepoint = first_escape;
      }
      break;
    default:
      return 0;
  }

  cursor->current = input;
  return 1;
}

static int bridge_json_write_utf8(
    unsigned long codepoint,
    char *output,
    size_t output_size,
    size_t *used) {
  size_t required;
  if (codepoint == 0 || codepoint > 0x10FFFFUL ||
      (codepoint >= 0xD800UL && codepoint <= 0xDFFFUL)) return 0;
  if (codepoint <= 0x7FUL) required = 1;
  else if (codepoint <= 0x7FFUL) required = 2;
  else if (codepoint <= 0xFFFFUL) required = 3;
  else required = 4;
  if (*used + required >= output_size) return 0;

  if (required == 1) {
    output[(*used)++] = (char)codepoint;
  }
  else if (required == 2) {
    output[(*used)++] = (char)(0xC0U | (unsigned int)(codepoint >> 6));
    output[(*used)++] = (char)(0x80U | (unsigned int)(codepoint & 0x3FUL));
  }
  else if (required == 3) {
    output[(*used)++] = (char)(0xE0U | (unsigned int)(codepoint >> 12));
    output[(*used)++] = (char)(0x80U | (unsigned int)((codepoint >> 6) & 0x3FUL));
    output[(*used)++] = (char)(0x80U | (unsigned int)(codepoint & 0x3FUL));
  }
  else {
    output[(*used)++] = (char)(0xF0U | (unsigned int)(codepoint >> 18));
    output[(*used)++] = (char)(0x80U | (unsigned int)((codepoint >> 12) & 0x3FUL));
    output[(*used)++] = (char)(0x80U | (unsigned int)((codepoint >> 6) & 0x3FUL));
    output[(*used)++] = (char)(0x80U | (unsigned int)(codepoint & 0x3FUL));
  }
  return 1;
}

static int bridge_json_parse_string(
    bridge_json_cursor *cursor,
    char *output,
    size_t output_size,
    const char *expected,
    int *matches) {
  size_t used = 0;
  size_t expected_index = 0;
  int is_match = expected != NULL;

  if (*cursor->current != '"') return 0;
  if (output != NULL && output_size == 0) return 0;
  cursor->current++;

  for (;;) {
    unsigned long codepoint;
    int finished;
    if (!bridge_json_next_string_codepoint(cursor, &codepoint, &finished)) return 0;
    if (finished) break;

    if (is_match) {
      unsigned char expected_ch = (unsigned char)expected[expected_index];
      if (expected_ch == 0 || codepoint > 0x7FUL || expected_ch != codepoint) {
        is_match = 0;
      }
      else {
        expected_index++;
      }
    }

    if (output != NULL &&
        !bridge_json_write_utf8(codepoint, output, output_size, &used)) return 0;
  }

  if (output != NULL) output[used] = '\0';
  if (matches != NULL) {
    *matches = is_match && expected[expected_index] == '\0';
  }
  return 1;
}

static int bridge_json_skip_number(bridge_json_cursor *cursor) {
  const char *input = cursor->current;
  if (*input == '-') input++;
  if (*input == '0') {
    input++;
    if (*input >= '0' && *input <= '9') return 0;
  }
  else {
    if (*input < '1' || *input > '9') return 0;
    while (*input >= '0' && *input <= '9') input++;
  }
  if (*input == '.') {
    input++;
    if (*input < '0' || *input > '9') return 0;
    while (*input >= '0' && *input <= '9') input++;
  }
  if (*input == 'e' || *input == 'E') {
    input++;
    if (*input == '+' || *input == '-') input++;
    if (*input < '0' || *input > '9') return 0;
    while (*input >= '0' && *input <= '9') input++;
  }
  cursor->current = input;
  return 1;
}

static int bridge_json_skip_value(
    bridge_json_cursor *cursor,
    int depth,
    bridge_json_type *type) {
  bridge_json_skip_whitespace(cursor);
  if (depth > BRIDGE_JSON_MAX_DEPTH) return 0;

  if (*cursor->current == '"') {
    if (!bridge_json_parse_string(cursor, NULL, 0, NULL, NULL)) return 0;
    *type = BRIDGE_JSON_STRING;
    return 1;
  }

  if (*cursor->current == '{') {
    cursor->current++;
    bridge_json_skip_whitespace(cursor);
    if (*cursor->current == '}') {
      cursor->current++;
      *type = BRIDGE_JSON_OBJECT;
      return 1;
    }
    for (;;) {
      bridge_json_type nested_type;
      if (!bridge_json_parse_string(cursor, NULL, 0, NULL, NULL)) return 0;
      bridge_json_skip_whitespace(cursor);
      if (*cursor->current != ':') return 0;
      cursor->current++;
      if (!bridge_json_skip_value(cursor, depth + 1, &nested_type)) return 0;
      bridge_json_skip_whitespace(cursor);
      if (*cursor->current == '}') {
        cursor->current++;
        *type = BRIDGE_JSON_OBJECT;
        return 1;
      }
      if (*cursor->current != ',') return 0;
      cursor->current++;
      bridge_json_skip_whitespace(cursor);
    }
  }

  if (*cursor->current == '[') {
    cursor->current++;
    bridge_json_skip_whitespace(cursor);
    if (*cursor->current == ']') {
      cursor->current++;
      *type = BRIDGE_JSON_ARRAY;
      return 1;
    }
    for (;;) {
      bridge_json_type nested_type;
      if (!bridge_json_skip_value(cursor, depth + 1, &nested_type)) return 0;
      bridge_json_skip_whitespace(cursor);
      if (*cursor->current == ']') {
        cursor->current++;
        *type = BRIDGE_JSON_ARRAY;
        return 1;
      }
      if (*cursor->current != ',') return 0;
      cursor->current++;
      bridge_json_skip_whitespace(cursor);
    }
  }

  if (strncmp(cursor->current, "true", 4) == 0) {
    cursor->current += 4;
    *type = BRIDGE_JSON_TRUE;
    return 1;
  }
  if (strncmp(cursor->current, "false", 5) == 0) {
    cursor->current += 5;
    *type = BRIDGE_JSON_FALSE;
    return 1;
  }
  if (strncmp(cursor->current, "null", 4) == 0) {
    cursor->current += 4;
    *type = BRIDGE_JSON_NULL;
    return 1;
  }
  if (*cursor->current == '-' ||
      (*cursor->current >= '0' && *cursor->current <= '9')) {
    if (!bridge_json_skip_number(cursor)) return 0;
    *type = BRIDGE_JSON_NUMBER;
    return 1;
  }
  return 0;
}

static int bridge_json_find_field(
    const char *json,
    const char *field,
    bridge_json_value *value) {
  bridge_json_cursor cursor;
  int found = 0;
  if (json == NULL || field == NULL || value == NULL) return -1;
  cursor.current = json;
  bridge_json_skip_whitespace(&cursor);
  if (*cursor.current != '{') return -1;
  cursor.current++;
  bridge_json_skip_whitespace(&cursor);

  if (*cursor.current == '}') {
    cursor.current++;
    bridge_json_skip_whitespace(&cursor);
    return *cursor.current == '\0' ? 0 : -1;
  }

  for (;;) {
    int key_matches = 0;
    bridge_json_value candidate;
    if (!bridge_json_parse_string(&cursor, NULL, 0, field, &key_matches)) return -1;
    bridge_json_skip_whitespace(&cursor);
    if (*cursor.current != ':') return -1;
    cursor.current++;
    bridge_json_skip_whitespace(&cursor);
    candidate.start = cursor.current;
    if (!bridge_json_skip_value(&cursor, 1, &candidate.type)) return -1;
    candidate.end = cursor.current;
    if (key_matches) {
      if (found) return -1;
      *value = candidate;
      found = 1;
    }
    bridge_json_skip_whitespace(&cursor);
    if (*cursor.current == '}') {
      cursor.current++;
      bridge_json_skip_whitespace(&cursor);
      if (*cursor.current != '\0') return -1;
      return found;
    }
    if (*cursor.current != ',') return -1;
    cursor.current++;
    bridge_json_skip_whitespace(&cursor);
  }
}

static int bridge_json_extract_string(
    const char *json,
    const char *field,
    char *output,
    size_t output_size) {
  bridge_json_value value;
  bridge_json_cursor cursor;
  if (output == NULL || output_size == 0) return 0;
  if (bridge_json_find_field(json, field, &value) != 1 ||
      value.type != BRIDGE_JSON_STRING) return 0;
  cursor.current = value.start;
  if (!bridge_json_parse_string(&cursor, output, output_size, NULL, NULL)) return 0;
  return cursor.current == value.end;
}

static int bridge_json_extract_int(
    const char *json,
    const char *field,
    int *result) {
  bridge_json_value value;
  char buffer[64];
  size_t length;
  char *end_ptr;
  long parsed;
  size_t index;

  if (result == NULL) return 0;
  if (bridge_json_find_field(json, field, &value) != 1 ||
      value.type != BRIDGE_JSON_NUMBER) return 0;
  length = (size_t)(value.end - value.start);
  if (length == 0 || length >= sizeof(buffer)) return 0;
  for (index = 0; index < length; index++) {
    char ch = value.start[index];
    if (!(ch == '-' || (ch >= '0' && ch <= '9'))) return 0;
  }
  memcpy(buffer, value.start, length);
  buffer[length] = '\0';
  errno = 0;
  parsed = strtol(buffer, &end_ptr, 10);
  if (errno == ERANGE || end_ptr != buffer + length ||
      parsed < INT_MIN || parsed > INT_MAX) return 0;
  *result = (int)parsed;
  return 1;
}

static int bridge_json_extract_bool(
    const char *json,
    const char *field,
    int *result) {
  bridge_json_value value;
  if (result == NULL) return 0;
  if (bridge_json_find_field(json, field, &value) != 1) return 0;
  if (value.type == BRIDGE_JSON_TRUE) {
    *result = 1;
    return 1;
  }
  if (value.type == BRIDGE_JSON_FALSE) {
    *result = 0;
    return 1;
  }
  return 0;
}

#endif
