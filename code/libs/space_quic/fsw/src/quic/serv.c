#include "serv.h"
#include "connection.h"
#include "utils.h"

#include <errno.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

void quic_server_deinit(QuicServer *server) {
    if (server->epoll_fd >= 0) close(server->epoll_fd);
    if (server->socket_fd >= 0) close(server->socket_fd);
    if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
    if (server->connection) connection_free(server->connection);
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    Connection *connection = user_data;
    Stream *stream = NULL;

    stream = stream_new(stream_id);
    assert(connection->stream == NULL);
    connection->stream = stream;
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn,
                               uint32_t flags,
                               int64_t stream_id,
                               uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data,
                               void *stream_user_data) {
    fprintf(stderr, "-- Received stream data: %.*s\n", (int) datalen, data);
    return 0;
}

static int handshake_completed(ngtcp2_conn *conn, void *user_data) {
//    fprintf(stdout, "QUIC handshake has completed\n");
    return 0;
}

static ngtcp2_callbacks callbacks = {
        .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .handshake_completed = handshake_completed,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

        .recv_stream_data = recv_stream_data_cb,
        .stream_open = stream_open_cb,
        .rand = rand_cb,
        .get_new_connection_id = get_new_connection_id_cb,
};

static Connection *find_connection(QuicServer *server, const uint8_t *dcid, size_t dcid_size) {
    if (server->connection == NULL)
        return NULL;

    ngtcp2_conn *conn = server->connection->conn;
    size_t n_scids = ngtcp2_conn_get_num_scid(conn);
    ngtcp2_cid scids[n_scids];

    n_scids = ngtcp2_conn_get_scid(conn, scids);
    for (size_t i = 0; i < n_scids; i++) {
        if (dcid_size == scids[i].datalen && memcmp(dcid, scids[i].data, dcid_size) == 0)
            return server->connection;
    }

    abort(); // should not happen if only one connection exists. this function is essentially just a check
}

static Connection *accept_connection(QuicServer *server,
                                     struct sockaddr *remote_addr, size_t remote_addrlen,
                                     const uint8_t *data, size_t data_size) {
    ngtcp2_pkt_hd header;
    int ret;

    ret = ngtcp2_accept(&header, data, data_size);
    if (ret < 0) return NULL;

    Connection *connection = connection_new(server->ssl_ctx, server->socket_fd);

    ngtcp2_path path = {
            .local = {
                    .addrlen = server->local_addrlen,
                    .addr = (struct sockaddr *) &server->local_addr},
            .remote = {
                    .addrlen = remote_addrlen,
                    .addr = (struct sockaddr *) remote_addr}
    };

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 0;
    params.initial_max_stream_data_bidi_remote = 0;
    params.initial_max_stream_data_uni = 17000;
    params.initial_max_data = 17000;
    params.initial_max_streams_bidi = 0;
    params.initial_max_streams_uni = 1;
    params.max_idle_timeout = 5 * 60 * NGTCP2_NANOSECONDS;
    params.stateless_reset_token_present = 0;
    params.active_connection_id_limit = 1;
    params.disable_active_migration = 1;
    params.initial_max_streams_uni = 1;
    params.initial_max_data = 1024 * 1024;
    memcpy(&params.original_dcid, &header.dcid, sizeof(params.original_dcid));

    ngtcp2_cid scid;
    if (get_random_cid(&scid) < 0)
        return NULL;

    ngtcp2_conn *conn = NULL;

    ret = ngtcp2_conn_server_new(&conn,
                                 &header.scid,
                                 &scid,
                                 &path,
                                 header.version,
                                 &callbacks,
                                 &server->settings,
                                 &params,
                                 NULL,
                                 connection);
    if (ret < 0) {
        fprintf(stdout, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(ret));
        return NULL;
    }

    connection_set(connection, conn, &server->local_addr, server->local_addrlen, (struct sockaddr_storage *) remote_addr, remote_addrlen);

    assert(server->connection == NULL); // only support a single connection at a time
    server->connection = connection;

    return connection;
}

static uint8_t buf[BUF_SIZE];

static int handle_incoming(QuicServer *server) {
    for (;;) {
        ssize_t n_read;
        struct sockaddr_storage remote_addr;
        size_t remote_addrlen = sizeof(remote_addr);
        int ret;

        n_read = recv_packet(server->socket_fd, buf, sizeof(buf),
                             (struct sockaddr *) &remote_addr,
                             &remote_addrlen);
        if (n_read < 0) {
            if (n_read != EAGAIN && n_read != EWOULDBLOCK)
                return 0;
            return -1;
        }

        NET_start_measure(0);

        ngtcp2_version_cid version;
        ret = ngtcp2_pkt_decode_version_cid(&version,
                                            buf, n_read,
                                            NGTCP2_MAX_CIDLEN);
        if (ret < 0) {
            fprintf(stdout, "ngtcp2_pkt_decode_version_cid: %s\n", ngtcp2_strerror(ret));
            return -1;
        }

        /* Find any existing connection by DCID */
        Connection *connection = find_connection(server, version.dcid, version.dcidlen);
        if (!connection) {
            connection = accept_connection(server,
                                           (struct sockaddr *) &remote_addr,
                                           remote_addrlen,
                                           buf, n_read);
            if (!connection)
                return -1;

            ret = connection_start(connection, true);
            if (ret < 0)
                return -1;

            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLET;
            ev.data.fd = connection->timer_fd;
            ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev);
            if (ret < 0) {
                return -1;
            }
        }

        ngtcp2_conn *conn = connection->conn;

        ngtcp2_path path;
        memcpy(&path, ngtcp2_conn_get_path(conn), sizeof(path));
        path.remote.addrlen = remote_addrlen;
        path.remote.addr = (struct sockaddr *) &remote_addr;

        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));

        ret = ngtcp2_conn_read_pkt(conn, &path, &pi, buf, n_read, timestamp());

        NET_stop_measure("connection_read", n_read, 0);

        if (ret < 0) {
            fprintf(stdout, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(ret));

            server->connection = NULL;
            fprintf(stdout, "removed connection because of read error\n");

            ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, connection->timer_fd, NULL);
            if (ret < 0) {
                return -1;
            }
            connection->socket_fd = -1;
            connection_free(connection);
        }
    }
    return 0;
}

void quic_server_setup_epoll(QuicServer *server) {
    server->epoll_fd = epoll_create1(0);
    assert(server->epoll_fd >= 0);

    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = server->socket_fd;
    assert(epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) >= 0);
}

int quic_server_step(QuicServer *server, int steps) {
    const int MAX_EVENTS = 4;
    struct epoll_event events[MAX_EVENTS];

    for (int i = 0; i < steps; ++i) {
        const int nfds = epoll_wait(server->epoll_fd, events, MAX_EVENTS, 0 /* no waiting */);

        for (int n = 0; n < nfds; n++) {
            int ret;

            if (events[n].data.fd == server->socket_fd) {
                if (events[n].events & EPOLLIN) {
                    handle_incoming(server);
                }
                if (events[n].events & EPOLLOUT) {
                    if (server->connection)
                        connection_write(server->connection);
                }
            } else {
                /* timer fd */
                if (server->connection) {
                    Connection *connection = server->connection;
                    if (events[n].data.fd == connection->timer_fd) {
                        ngtcp2_conn *conn = connection->conn;

                        NET_start_measure(0);
                        ret = ngtcp2_conn_handle_expiry(conn, timestamp());
                        if (ret < 0) {
//                            fprintf(stdout,  "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(ret));
                            NET_stop_measure("timer_expiry", 0, 0);
                            continue;
                        }
                        NET_stop_measure("timer_expiry", 0, 0);

                        connection_write(connection);
                    }
                }
            }
        }
    }

    return 0;
}

static void keylog_callback(const SSL *ssl, const char *line) {
    FILE *keylog_file = fopen("/tmp/ssl_keylogquic", "a");
    fprintf(keylog_file, "%s\n", line);
    fclose(keylog_file);
}

static SSL_CTX *create_tls_server_context(const char *private_key_file, const char *cert_file, const char *ciphers, const char *groups) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(
#ifdef Wolf
            TLSv1_3_server_method()
#else
            TLS_server_method()
#endif
                                  );
    if (!ssl_ctx) {
        return NULL;
    }

#ifndef Wolf
    if (ngtcp2_crypto_openssl_configure_server_context(ssl_ctx) != 0) {
        return NULL;
    }
#else
    if (ngtcp2_crypto_wolfssl_configure_server_context(ssl_ctx) != 0) {
        return NULL;
    }
#endif

    SSL_CTX_set_max_early_data(ssl_ctx, UINT32_MAX);

#ifndef Wolf
    const size_t ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
                            SSL_OP_SINGLE_ECDH_USE |
                            SSL_OP_CIPHER_SERVER_PREFERENCE |
                            SSL_OP_NO_ANTI_REPLAY;
    SSL_CTX_set_options(ssl_ctx, ssl_opts);
#else
    const long ssl_opts =
            (WOLFSSL_OP_ALL & ~WOLFSSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) |
            WOLFSSL_OP_SINGLE_ECDH_USE | WOLFSSL_OP_CIPHER_SERVER_PREFERENCE;
    wolfSSL_CTX_set_options(ssl_ctx, ssl_opts);
#endif

    if (SSL_CTX_set_ciphersuites(ssl_ctx, ciphers) != 1) {
        return NULL;
    }

#ifndef Wolf
    if (SSL_CTX_set1_groups_list(ssl_ctx, groups) != 1) {
        return NULL;
    }
#else
    if (wolfSSL_CTX_set1_curves_list(ssl_ctx, groups) != 1) {
        return NULL;
    }
#endif

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_default_verify_paths(ssl_ctx);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file, SSL_FILETYPE_PEM) != 1) {
        return NULL;
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        return NULL;
    }
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        return NULL;
    }

#ifdef DontPrint
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
#endif

    return ssl_ctx;
}

void quic_server_init(QuicServer *server, ngtcp2_recv_stream_data read_cb, bool log_print) {
    server->connection = NULL;
    server->ssl_ctx = NULL;
    server->local_addrlen = sizeof(struct sockaddr_storage);
    server->epoll_fd = -1;

    const char *ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
    const char *groups = "X25519:P-256:P-384:P-521";

    const char *private_key_file = "/cert/private.key";
    const char *cert_file = "/cert/certificate.crt";

    // setup tls
    server->ssl_ctx = create_tls_server_context(private_key_file, cert_file, ciphers, groups);
    assert(server->ssl_ctx);

    if (read_cb) {
        callbacks.recv_stream_data = read_cb;
    }

    ngtcp2_settings_default(&server->settings);
    if (log_print) {
        server->settings.log_printf = log_printf;
    } else {
        server->settings.log_printf = NULL;
    }
    server->settings.initial_ts = timestamp();
    server->settings.cc_algo = NGTCP2_CC_ALGO_BBR;
    server->settings.initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
    server->settings.max_window = 0; // is disabled
    server->settings.max_stream_window = 0; // is disabled
    server->settings.handshake_timeout = NGTCP2_DEFAULT_HANDSHAKE_TIMEOUT;
    server->settings.no_pmtud = 1;
    server->settings.ack_thresh = 1; // TODO MAYBE CHANGE
}

void quic_server_bind(QuicServer *server, const char *host, const char *port) {
    server->socket_fd = resolve_and_bind(host, port, (struct sockaddr *) &server->local_addr, &server->local_addrlen);
    assert(server->socket_fd >= 0);
}

//int main(int argc, char **argv) {
//    QuicServer server;
//
//    quic_server_init(&server, 0, true);
//
//    quic_server_bind(&server, "127.0.0.1", "1234");
//
//    quic_server_setup_epoll(&server);
//
//    while (true) {
//        int r = quic_server_step(&server, 10);
//        if (r == -1) abort();
//    }
//
//    return 0;
//}
