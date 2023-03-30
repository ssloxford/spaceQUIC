#include "stream.h"

#include <stdlib.h>
#include <string.h>

typedef struct Node_ {
    struct Node_ *next;
    size_t size;
} Node;

Stream *stream_new(int64_t id) {
    Stream *stream = malloc(sizeof(Stream));
    memset(stream, 0, sizeof(Stream));
    stream->id = id;
    return stream;
}

void stream_free(Stream *stream) {
    if (!stream) return;
    free(stream);
}

int stream_push_data(Stream *stream, const uint8_t *data, size_t data_size) {
    Node *node = malloc(data_size + sizeof(Node));
    node->next = NULL;
    node->size = data_size;
    memcpy((uint8_t *) node + sizeof(Node), data, data_size);

    if (stream->tail) {
        stream->tail->next = node;
        stream->tail = node;
    } else {
        stream->head = stream->tail = node;
    }
    return 0;
}

const uint8_t *stream_peek_data(Stream *stream, size_t *data_size) {
    const size_t start_offset = stream->sent_offset - stream->acked_offset;
    size_t offset = 0;

    Node *n = stream->head;
    while (n) {
        const uint8_t *data = (uint8_t *) n + sizeof(Node);

        if (offset + n->size > start_offset) {
            *data_size = n->size - (start_offset - offset);
            return data + (start_offset - offset);
        }

        offset += n->size;
        n = n->next;
    }

    *data_size = 0;
    return NULL;
}

void stream_mark_sent(Stream *stream, size_t offset) {
    stream->sent_offset += offset;
}

void stream_mark_acked(Stream *stream, size_t offset) {
    while (stream->head) {
        if (stream->acked_offset + stream->head->size > offset)
            break;

        stream->acked_offset += stream->head->size;

        // pop head
        Node *next = stream->head->next;
        free(stream->head);
        stream->head = next;
        if (stream->head == NULL)
            stream->tail = NULL;
    }
}

