#include "connection.h"
#include "utils.h"

#include <ngtcp2/ngtcp2.h>
#include <sys/types.h>

#define BUF_SIZE 16800

typedef struct _Server {
    SSL_CTX *ssl_ctx;
    Connection *connection; // could be a list

    int epoll_fd;
    int socket_fd;
    struct sockaddr_storage local_addr;
    size_t local_addrlen;

    ngtcp2_settings settings;
} QuicServer;

void quic_server_deinit(QuicServer *server);
void quic_server_init(QuicServer *server, ngtcp2_recv_stream_data read_cb, bool log_print);
void quic_server_setup_epoll(QuicServer *server);
int quic_server_step(QuicServer *server, int steps);
void quic_server_bind(QuicServer *server, const char *host, const char *port);
