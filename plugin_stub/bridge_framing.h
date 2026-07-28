#ifndef OLLYBRIDGE_BRIDGE_FRAMING_H
#define OLLYBRIDGE_BRIDGE_FRAMING_H

#include <stddef.h>

#define BRIDGE_FRAME_MORE 0
#define BRIDGE_FRAME_COMPLETE 1
#define BRIDGE_FRAME_OVERFLOW (-1)

typedef struct bridge_frame_state {
  size_t used;
  int complete;
  int overflowed;
} bridge_frame_state;

static void bridge_frame_init(bridge_frame_state *state) {
  if (state == NULL) return;
  state->used = 0;
  state->complete = 0;
  state->overflowed = 0;
}

static int bridge_frame_append(
    bridge_frame_state *state,
    char *output,
    size_t output_size,
    const char *chunk,
    size_t chunk_size) {
  size_t index;
  if (state == NULL || output == NULL || output_size == 0 || chunk == NULL)
    return BRIDGE_FRAME_OVERFLOW;
  if (state->overflowed) return BRIDGE_FRAME_OVERFLOW;
  if (state->complete) return BRIDGE_FRAME_COMPLETE;

  for (index = 0; index < chunk_size; index++) {
    char value = chunk[index];
    if (value == '\n') {
      if (state->used > 0 && output[state->used - 1] == '\r') state->used--;
      output[state->used] = '\0';
      state->complete = 1;
      return BRIDGE_FRAME_COMPLETE;
    }
    if (state->used + 1 >= output_size) {
      output[output_size - 1] = '\0';
      state->overflowed = 1;
      return BRIDGE_FRAME_OVERFLOW;
    }
    output[state->used++] = value;
  }

  output[state->used] = '\0';
  return BRIDGE_FRAME_MORE;
}

#endif
