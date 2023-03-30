#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct Node_ Node;

typedef struct _Stream {
    int64_t id;

    Node *head, *tail;

    size_t sent_offset;
    size_t acked_offset;
} Stream;

Stream *stream_new(int64_t id);
void stream_free(Stream *stream);

int stream_push_data(Stream *stream, const uint8_t *data, size_t data_size);
const uint8_t *stream_peek_data(Stream *stream, size_t *data_size);
void stream_mark_sent(Stream *stream, size_t offset);
void stream_mark_acked(Stream *stream, size_t offset);
