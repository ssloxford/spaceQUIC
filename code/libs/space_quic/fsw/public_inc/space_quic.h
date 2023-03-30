#ifndef SPACE_QUIC_H
#define SPACE_QUIC_H

// avoid including any cfe headers so we can compile this in the benchmark tool
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef CFE_SUCCESS
#define CFE_SUCCESS ((int32_t)0)
#endif

#define PACKETS_TO_SEND 20
#define PAYLOAD_SIZE 128

// crypto config for all apps
#define None 0
#define Cryptolib 1

#define EncryptionType None
#define Quic
/*****/

// exported
int32_t NET_SPACE_QUIC_Init(void);

struct addrinfo *NET_get_addrinfo(const char *hostname, const char *portNum);
void NET_free_addrinfo(struct addrinfo *);

int NET_open_udp(struct addrinfo *addr);
int NET_send_udp(int fd, const uint8_t *data, int size, bool command);

void NET_print_hex(const uint8_t *data, int size);
void NET_print_char(const uint8_t *data, int size);

// writes 8 bytes to dest
void NET_PACKET_make_command_header(uint8_t *dest, uint16_t stream_id, uint8_t command_code, uint16_t payload_length, const uint8_t *payload);

// makes packet and sends via udp
int NET_PACKET_send_udp_command(int fd, uint16_t stream_id, uint8_t command_code, uint16_t payload_length, const uint8_t *payload);

// encrypts packets according to currently defined method
// returns true if dest must be freed
bool NET_encrypt(const uint8_t *data, int size, int *dest_size, uint8_t **dest, bool command);

// decrypts packets according to currently defined method
// returns true if dest must be freed
bool NET_decrypt(const uint8_t *data, int size, int *dest_size, uint8_t **dest);

void NET_start_measure(const char *name);
void NET_stop_measure(void);

#ifdef Quic
/* quic client and server */
#include "../src/quic/cli.h"
#include "../src/quic/serv.h"
#endif

#endif
