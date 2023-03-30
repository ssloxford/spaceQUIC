#pragma once

#include <ngtcp2/ngtcp2_crypto.h>
#include <stdbool.h>
#include "stream.h"

#include "ssl_includes.h"

typedef struct _Connection {
    SSL *ssl;

    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref conn_ref;

    int socket_fd;
    int timer_fd;

    int isclient;

    struct sockaddr_storage local_addr;
    size_t local_addr_size;
    struct sockaddr_storage remote_addr;
    size_t remote_addr_size;

    Stream *stream;
} Connection;

Connection *connection_new(SSL_CTX *ssl_ctx, int socket_fd);
void connection_free(Connection *connection);

void connection_set(Connection *connection, ngtcp2_conn *conn, struct sockaddr_storage *local_addr, size_t local_addr_size, struct sockaddr_storage *remote_addr, size_t remote_addr_size);

int connection_start(Connection *connection, bool server);
int connection_read(Connection *connection);
int connection_write(Connection *connection);
