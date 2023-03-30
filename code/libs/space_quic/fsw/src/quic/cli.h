#include "connection.h"
#include "utils.h"

#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>

typedef struct _Client {
    SSL_CTX *ssl_ctx;
    Connection *connection;

    int epoll_fd;

    ngtcp2_settings settings;
    ngtcp2_transport_params transport_params;
} QuicClient;

void quic_client_deinit(QuicClient *client);
void quic_client_init(QuicClient *client, bool log_print);
void quic_client_setup_epoll(QuicClient *client);
int quic_client_step(QuicClient *client, int steps);
void quic_client_connect(QuicClient *client, const char *host, const char *port);
int quic_client_write(QuicClient *client, const uint8_t *data, size_t size);