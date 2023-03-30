#pragma once

#include <ngtcp2/ngtcp2.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


int resolve_and_connect(const char *host, const char *port, struct sockaddr *local_addr, size_t *local_addrlen,
                        struct sockaddr *remote_addr, size_t *remote_addrlen);
int resolve_and_bind(const char *host, const char *port, struct sockaddr *local_addr, size_t *local_addrlen);

uint64_t timestamp(void);
void log_printf(void *user_data, const char *fmt, ...);
int get_random_cid(ngtcp2_cid *cid);

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size, struct sockaddr *remote_addr, size_t *remote_addrlen);
ssize_t send_packet(int fd, const uint8_t *data, size_t data_size, struct sockaddr *remote_addr, size_t remote_addrlen);

int generate_secure_random(uint8_t *data, size_t datalen);
int generate_secret(uint8_t *secret, size_t secretlen);

/*** ngtcp2 common between client and server ***/
void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx);
int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data);