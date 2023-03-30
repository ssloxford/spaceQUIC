#include "cli.h"
#include "connection.h"
#include "utils.h"

#include <errno.h>
#include <error.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

void quic_client_deinit(QuicClient *client) {
    connection_free(client->connection);
    SSL_CTX_free(client->ssl_ctx);
}

static int recv_stream_data_cb(ngtcp2_conn *conn,
                               uint32_t flags,
                               int64_t stream_id,
                               uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data,
                               void *stream_user_data) {
    fprintf(stdout, "receiving %zu bytes from stream #%zd\n", datalen, stream_id);
    write(STDOUT_FILENO, data, datalen);
    return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn,
                                       int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data,
                                       void *stream_user_data) {
    Connection *connection = user_data;
    Stream *stream = connection->stream;
    if (stream) {
        assert(stream->id == stream_id);
        stream_mark_acked(stream, offset + datalen);
    }
    return 0;
}

int quic_client_write(QuicClient *client, const uint8_t *data, size_t size) {
    if (!client->connection->stream) {
        return -1;
    }

    {
        // push data to stream
        int ret = stream_push_data(client->connection->stream, data, size);
        if (ret < 0) abort();
//        fprintf(stdout, "buffered %zd bytes\n", size);
    }

    int ret = connection_write(client->connection);
    if (ret < 0) abort();

    return 0;
}

static int handshake_completed(ngtcp2_conn *conn, void *user_data) {
    fprintf(stdout, "QUIC handshake has completed\n");
    return 0;
}

static int extend_max_local_streams_uni(ngtcp2_conn *conn, uint64_t max_streams, void *user_data) {
    int64_t stream_id = 1;
    int ret = ngtcp2_conn_open_uni_stream(conn, &stream_id, NULL);
    if (ret < 0) {
        fprintf(stdout, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror(ret));
        return 0;
    }

    // open Stream
    Stream *stream = stream_new(stream_id);
    if (!stream) abort();
    Connection *connection = user_data;
    connection->stream = stream;

    fprintf(stdout, "opened stream #%zd\n", stream_id);
    fflush(stdout);

    return 0;
}

static ngtcp2_callbacks callbacks = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,

        .acked_stream_data_offset = acked_stream_data_offset_cb,
        .extend_max_local_streams_uni = extend_max_local_streams_uni,
        .handshake_completed = handshake_completed,
        .recv_stream_data = recv_stream_data_cb,
        .rand = rand_cb,
        .get_new_connection_id = get_new_connection_id_cb,
};

void quic_client_setup_epoll(QuicClient *client) {
    client->epoll_fd = epoll_create1(0);
    assert(client->epoll_fd >= 0);

    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = client->connection->socket_fd;
    assert(epoll_ctl(client->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) >= 0);

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client->connection->timer_fd;
    assert(epoll_ctl(client->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) >= 0);
}

int quic_client_step(QuicClient *client, int steps) {
    const int MAX_EVENTS = 4;
    struct epoll_event events[MAX_EVENTS];

    for (int i = 0; i < steps; ++i) {
        const int nfds = epoll_wait(client->epoll_fd, events, MAX_EVENTS, 0 /* no waiting */);

        for (int n = 0; n < nfds; n++) {
            int ret;

            if (events[n].data.fd == client->connection->socket_fd) {
                if (events[n].events & EPOLLIN) {
                    ret = connection_read(client->connection);
                    if (ret < 0) return -1;
                }
                if (events[n].events & EPOLLOUT) {
                    ret = connection_write(client->connection);
                    if (ret < 0) return -1;
                }
            }

            if (events[n].data.fd == client->connection->timer_fd) {
                ngtcp2_conn *conn = client->connection->conn;

                NET_start_measure(0);
                ret = ngtcp2_conn_handle_expiry(conn, timestamp());
                if (ret < 0) {
                    fprintf(stdout, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror((int) ret));
                    return -1;
                }
                NET_stop_measure("timer_expiry", 1, 0);

                ret = connection_write(client->connection);
                if (ret < 0) return -1;
            }
        }
    }
    return 0;
}

static int client_ssl_ctx_init(QuicClient *c, const char *ciphers, const char *groups) {
    c->ssl_ctx = SSL_CTX_new(
#ifdef Wolf
            TLSv1_3_client_method()
#else
            TLS_client_method()
#endif
                            );

    if (!c->ssl_ctx) {
        fprintf(stdout, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    if (SSL_CTX_set_ciphersuites(c->ssl_ctx, ciphers) != 1) {
        return -1;
    }

#ifdef Wolf
    if (wolfSSL_CTX_set_default_verify_paths(c->ssl_ctx) == WOLFSSL_NOT_IMPLEMENTED) {
        wolfSSL_CTX_set_verify(c->ssl_ctx, WOLFSSL_VERIFY_NONE, 0);
    }
    if (SSL_CTX_set1_curves_list(c->ssl_ctx, groups) != 1) {
        return -1;
    }
#else
    SSL_CTX_set_default_verify_paths(c->ssl_ctx);
    if (SSL_CTX_set1_groups_list(c->ssl_ctx, groups) != 1) {
        return -1;
    }
#endif

#ifndef Wolf
    if (ngtcp2_crypto_openssl_configure_client_context(c->ssl_ctx) != 0) {
        fprintf(stdout, "ngtcp2_crypto_openssl_configure_client_context failed\n");
        return -1;
    }
#else
    if (ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx) != 0) {
        fprintf(stdout, "ngtcp2_crypto_wolfssl_configure_client_context failed\n");
        return -1;
    }
#endif
    return 0;
}

void quic_client_init(QuicClient *client, bool log_print) {
    const char *ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
    const char *groups = "X25519:P-256:P-384:P-521";

    client->connection = NULL;
    client->epoll_fd = -1;

    ngtcp2_settings_default(&client->settings);
    client->settings.no_pmtud = 1;
    client->settings.initial_ts = timestamp();

    if (log_print) {
        client->settings.log_printf = log_printf;
    } else {
        client->settings.log_printf = NULL;
    }

    ngtcp2_transport_params_default(&client->transport_params);
    client->transport_params.initial_max_streams_uni = 1;
    client->transport_params.initial_max_stream_data_bidi_local = 0;
    client->transport_params.initial_max_data = 1024 * 1024;
    client->transport_params.active_connection_id_limit = 1;
    client->transport_params.disable_active_migration = 1;
    client->transport_params.max_idle_timeout = 5 * 60 * NGTCP2_SECONDS;

    // init client ssl ctx
    if (client_ssl_ctx_init(client, ciphers, groups) != 0) {
        abort();
    }
}

void quic_client_connect(QuicClient *client, const char *host, const char *port) {
    assert(client->connection == NULL); // can only have 1 active connection

    struct sockaddr_storage local_addr, remote_addr;
    size_t local_addrlen = sizeof(local_addr), remote_addrlen;

    const int fd = resolve_and_connect(host, port, (struct sockaddr *) &local_addr, &local_addrlen, (struct sockaddr *) &remote_addr, &remote_addrlen);
    assert(fd >= 0);

    /* Create a ngtcp2 client connection */
    ngtcp2_path path = {
            .local = {
                    .addrlen = local_addrlen,
                    .addr = (struct sockaddr *) &local_addr
            },
            .remote = {
                    .addrlen = remote_addrlen,
                    .addr = (struct sockaddr *) &remote_addr
            }
    };

    ngtcp2_cid scid, dcid;
    if (get_random_cid(&scid) < 0 || get_random_cid(&dcid) < 0) error(EXIT_FAILURE, EINVAL, "get_random_cid failed\n");

    Connection *connection = connection_new(client->ssl_ctx, fd);
    if (!connection) error(EXIT_FAILURE, EINVAL, "connection_new failed\n");

    ngtcp2_conn *conn = NULL;
    int ret = ngtcp2_conn_client_new(&conn, &dcid, &scid, &path,
                                     NGTCP2_PROTO_VER_V1,
                                     &callbacks, &client->settings, &client->transport_params, NULL,
                                     connection);
    if (ret < 0) error(EXIT_FAILURE, EINVAL, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(ret));

    connection_set(connection, conn, &local_addr, local_addrlen, &remote_addr, remote_addrlen);

    ret = connection_start(connection, false);
    if (ret < 0) error(EXIT_FAILURE, EINVAL, "connection_start failed\n");

    client->connection = connection;
}

//int main(int argc, char **argv) {
//    QuicClient client;
//
//    quic_client_init(&client, true);
//
//    quic_client_connect(&client, "127.0.0.1", "1234");
//
//    quic_client_setup_epoll(&client);
//
//    bool w = 1;
//
//    while (true) {
//        int r = quic_client_step(&client, 10);
//        if (w) {
//            int x = quic_client_write(&client, "abcd", 4);
//            if (x == 0) w = 0;
//        }
//        if (r == -1) abort();
//    }
//
//    return 0;
//}
