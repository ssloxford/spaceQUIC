#include "connection.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include "utils.h"

#include <assert.h>
#include <string.h>

#define BUF_SIZE 16800
static uint8_t buf[BUF_SIZE];

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    return conn_ref->user_data;
}

Connection *connection_new(SSL_CTX *ssl_ctx, int socket_fd) {
    Connection *connection = malloc(sizeof(Connection));
    memset(connection, 0, sizeof(Connection));

    /* create SSL session */
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        abort();
    }

    connection->ssl = ssl;
    connection->socket_fd = socket_fd;
    connection->timer_fd = -1;

    connection->isclient = 0;

    return connection;
}

void connection_set(Connection *connection, ngtcp2_conn *conn, struct sockaddr_storage *local_addr, size_t local_addr_size, struct sockaddr_storage *remote_addr, size_t remote_addr_size) {
    connection->conn = conn;
    memcpy(&connection->local_addr, local_addr, local_addr_size);
    connection->local_addr_size = local_addr_size;
    memcpy(&connection->remote_addr, remote_addr, remote_addr_size);
    connection->remote_addr_size = remote_addr_size;
}

void connection_free(Connection *connection) {
    if (!connection) return;

    if (connection->ssl) SSL_free(connection->ssl);
    if (connection->conn) ngtcp2_conn_del(connection->conn);
    if (connection->socket_fd >= 0) close(connection->socket_fd);
    if (connection->timer_fd >= 0) close(connection->timer_fd);
    if (connection->stream) stream_free(connection->stream);

    free(connection);
}

int connection_start(Connection *connection, bool server) {
    assert(connection->ssl && connection->conn);

    connection->conn_ref.get_conn = get_conn;
    connection->conn_ref.user_data = connection->conn;

    SSL_set_app_data(connection->ssl, &connection->conn_ref);

    if (server) {
        connection->isclient = 0;
        SSL_set_accept_state(connection->ssl);
#ifndef Wolf
        SSL_set_quic_early_data_enabled(connection->ssl, 0);
#else
        wolfSSL_set_quic_early_data_enabled(connection->ssl, 0);
#endif
    } else {
        connection->isclient = 1;
        SSL_set_connect_state(connection->ssl);
#ifndef Wolf
        SSL_set_quic_transport_version(connection->ssl, TLSEXT_TYPE_quic_transport_parameters);
#else
        wolfSSL_set_quic_transport_version(connection->ssl, 0x0039 /* just v1 */);
#endif
    }

    ngtcp2_conn_set_tls_native_handle(connection->conn, connection->ssl);

    connection->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (connection->timer_fd < 0) {
        fprintf(stdout, "timerfd_create: \n");
        return -1;
    }

    return 0;
}

int connection_read(Connection *connection) {
    ngtcp2_ssize ret;

    for (;;) {
        struct sockaddr_storage remote_addr;
        size_t remote_addrlen = sizeof(remote_addr);
        ret = recv_packet(connection->socket_fd, buf, sizeof(buf),
                          (struct sockaddr *) &remote_addr, &remote_addrlen);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            fprintf(stdout, "recv_packet: \n");
            return -1;
        }
        ssize_t len = ret;

        NET_start_measure(connection->isclient);

        ngtcp2_path path;
        memcpy(&path, ngtcp2_conn_get_path(connection->conn), sizeof(path));
        path.remote.addrlen = remote_addrlen;
        path.remote.addr = (struct sockaddr *) &remote_addr;

        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));

        ret = ngtcp2_conn_read_pkt(connection->conn, &path, &pi, buf, ret, timestamp());

        NET_stop_measure("connection_read", 10000000 * connection->isclient + len, connection->isclient);

        if (ret < 0) {
            fprintf(stdout, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(ret));
            return -1;
        }
    }

    return 0;
}

static int write_to_stream(Connection *connection, Stream *stream) {
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;
    uint64_t ts = timestamp();

    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

    for (;;) {
        NET_start_measure(connection->isclient);

        ngtcp2_vec datav;
        int64_t stream_id;

        if (stream) {
            datav.base = (void *) stream_peek_data(stream, &datav.len);
            if (datav.len == 0) {
                /* No stream data to be sent */
                stream_id = -1;

                flags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
            } else {
                stream_id = stream->id;
            }
        } else {
            datav.base = NULL;
            datav.len = 0;
            stream_id = -1;
        }

        ngtcp2_ssize n_read, n_written;

        n_written = ngtcp2_conn_writev_stream(connection->conn, &ps.path, &pi,
                                              buf, sizeof(buf),
                                              &n_read,
                                              flags,
                                              stream_id,
                                              &datav, 1,
                                              ts);

        NET_stop_measure("write_to_stream", 10000000 * connection->isclient + n_written, connection->isclient);

        if (n_written < 0) {
            if (n_written == NGTCP2_ERR_WRITE_MORE) {
                stream_mark_sent(stream, n_read);
                continue;
            }
            fprintf(stdout, "ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror((int) n_written));
            return -1;
        }

        if (n_written == 0)
            return 0;

        if (stream && n_read > 0)
            stream_mark_sent(stream, n_read);

        int ret;

        ret = send_packet(connection->socket_fd, buf, n_written,
                          (struct sockaddr *) &connection->remote_addr, connection->remote_addr_size);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            fprintf(stdout, "send_packet: %s\n", strerror(errno));
            return -1;
        }

        /* No stream data to be sent */
        if (stream && datav.len == 0)
            break;
    }

    return 0;
}

int connection_write(Connection *connection) {
    int ret;

    if (!connection->stream) {
        ret = write_to_stream(connection, NULL);
        if (ret < 0) return -1;
    } else {
        ret = write_to_stream(connection, connection->stream);
        if (ret < 0) return -1;
    }

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(connection->conn);
    ngtcp2_tstamp now = timestamp();
    struct itimerspec it;
    memset(&it, 0, sizeof(it));

    ret = timerfd_settime(connection->timer_fd, 0, &it, NULL);
    if (ret < 0) {
        fprintf(stdout, "timerfd_settime\n");
        return -1;
    }
    if (expiry < now) {
        it.it_value.tv_sec = 0;
        it.it_value.tv_nsec = 1;
    } else {
        it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
        it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
    }
    ret = timerfd_settime(connection->timer_fd, 0, &it, NULL);
    if (ret < 0) {
        return -1;
    }

    return 0;
}
