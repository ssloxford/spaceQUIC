#include "utils.h"

#include <errno.h>
#include <netdb.h>

#include "ssl_includes.h"
#include <assert.h>

#include <ngtcp2/ngtcp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int generate_secure_random(uint8_t *data, size_t datalen) {
    if (RAND_bytes(data, (int) datalen) != 1) {
        return -1;
    }
    return 0;
}

#ifndef Wolf
int generate_secret(uint8_t *secret, size_t secretlen) {
    uint8_t rand[16], md[32];

    assert(sizeof(md) == secretlen);

    if (generate_secure_random(rand, sizeof(rand)) != 0) {
        return -1;
    }

    struct evp_md_ctx_st *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    unsigned int mdlen = sizeof(md);
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, rand, sizeof(rand)) ||
        !EVP_DigestFinal_ex(ctx, md, &mdlen)) {
        return -1;
    }

    EVP_MD_CTX_free(ctx);

    memcpy(secret, md, secretlen);

    return 0;
}
#else
int generate_secret(uint8_t *secret, size_t secretlen) {
    uint8_t rand[16], md[32];

    assert(sizeof(md) == secretlen);

    if (generate_secure_random(rand, sizeof(rand)) != 0) {
        return -1;
    }

    struct WOLFSSL_EVP_MD_CTX *ctx = wolfSSL_EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    unsigned int mdlen = sizeof(md);
    if (!wolfSSL_EVP_DigestInit_ex(ctx, wolfSSL_EVP_sha256(), NULL) ||
        !wolfSSL_EVP_DigestUpdate(ctx, rand, sizeof(rand)) ||
        !wolfSSL_EVP_DigestFinal_ex(ctx, md, &mdlen)) {
        return -1;
    }

    wolfSSL_EVP_MD_CTX_free(ctx);

    memcpy(secret, md, secretlen);

    return 0;
}
#endif

int resolve_and_connect(const char *host, const char *port,
                        struct sockaddr *local_addr, size_t *local_addrlen,
                        struct sockaddr *remote_addr, size_t *remote_addrlen) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int ret, fd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0)
        return -1;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            *remote_addrlen = rp->ai_addrlen;
            memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);

            socklen_t len = (socklen_t) *local_addrlen;
            if (getsockname(fd, local_addr, &len) == -1)
                return -1;
            *local_addrlen = len;
            break;
        }

        close(fd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return -1;

    return fd;
}

int resolve_and_bind(const char *host, const char *port, struct sockaddr *local_addr, size_t *local_addrlen) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int ret, fd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0)
        return -1;

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            *local_addrlen = rp->ai_addrlen;
            memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        close(fd);
    }

    freeaddrinfo(result);

    if (rp == NULL)
        return -1;

    return fd;
}

uint64_t timestamp(void) {
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) < 0)
        return 0;

    return (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;
}

void log_printf(void *user_data, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);

    fprintf(stdout, "\n");
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size, struct sockaddr *remote_addr, size_t *remote_addrlen) {
    struct iovec iov;
    iov.iov_base = data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    msg.msg_name = remote_addr;
    msg.msg_namelen = *remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;

    do {
        ret = recvmsg(fd, &msg, MSG_DONTWAIT);
    } while (ret < 0 && errno == EINTR);

    *remote_addrlen = msg.msg_namelen;

    return ret;
}

ssize_t send_packet(int fd, const uint8_t *data, size_t data_size, struct sockaddr *remote_addr, size_t remote_addrlen) {
    struct iovec iov;
    iov.iov_base = (void *) data;
    iov.iov_len = data_size;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = remote_addr;
    msg.msg_namelen = remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t ret;

    do {
        ret = sendmsg(fd, &msg, MSG_DONTWAIT);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

int get_random_cid(ngtcp2_cid *cid) {
    uint8_t buf[NGTCP2_MAX_CIDLEN];

    if (generate_secure_random(buf, sizeof(buf)) < 0) {
        return -1;
    }
    ngtcp2_cid_init(cid, buf, sizeof(buf));

    return 0;
}

void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
    size_t i;
    for (i = 0; i < destlen; ++i) {
        *dest = (uint8_t) random();
    }
}

int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data) {
    if (RAND_bytes(cid->data, (int) cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}