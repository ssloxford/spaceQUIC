#include "space_quic.h"

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "../../../CryptoLib/include/crypto.h"

//
char buff[16784];
TC_t tc_frame_cryptolib_dec;
uint64_t ns_start = 0;
const char *time_name;
//

int32_t NET_SPACE_QUIC_Init(void) {
    // init CryptoLib
#if EncryptionType == Cryptolib
    Crypto_Init_benchmark();
#endif

    return CFE_SUCCESS;
}

struct addrinfo *NET_get_addrinfo(const char *hostname, const char *portNum) {
    struct addrinfo hints;
    struct addrinfo *result;

    assert(hostname != NULL);
    const int port = atoi(portNum);
    assert(port != -1);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;

    const int rc = getaddrinfo(hostname, portNum, &hints, &result);
    assert(rc == 0);
    assert(result != NULL);
    return result;
}

void NET_free_addrinfo(struct addrinfo *a) {
    freeaddrinfo(a);
}

int NET_open_udp(struct addrinfo *addr) {
    const int sd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    assert(sd != -1);
    /* just sets default address because UDP is connectionless */
    const int r = connect(sd, addr->ai_addr, addr->ai_addrlen);
    assert(r != -1);
    return sd;
}

int NET_send_udp(int fd, const uint8_t *data, int size, bool command) {
    uint8_t *enc_buff;
    int enc_size;
    bool must_free = NET_encrypt((const uint8_t *) data, (int) size, &enc_size, &enc_buff, command);

    const int rc = send(fd, (char *) enc_buff, enc_size, 0);
    printf("trying to send %d encrypted bytes\n", enc_size);

    if (must_free) {
        free(enc_buff);
    }

    return rc != enc_size ? -1 : 0; // -1 if could not send whole size
}

void NET_print_hex(const uint8_t *data, int size) {
    printf("(size: %d) ", size);
    int i = 0;
    while (i < size) {
        printf("0x%02X ", data[i++] & 0xFF);
    }
    puts("");
}

void NET_print_char(const uint8_t *data, int size) {
    printf("(size: %d) ", size);
    int i = 0;
    while (i < size) {
        printf("%c", data[i++]);
    }
    puts("\n");
}

void NET_PACKET_make_command_header(uint8_t *dest, uint16_t stream_id, uint8_t command_code, uint16_t payload_length, const uint8_t *payload) {
    dest[0] = *((uint8_t *) &stream_id + 1);
    dest[1] = *((uint8_t *) &stream_id);
    dest[2] = 0xC0;
    dest[3] = 0x00;
    uint16_t packet_length = payload_length + 8;
    dest[4] = ((packet_length) - 7) >> 8;
    dest[5] = ((packet_length) - 7) & 0xFF;
    // secondary command header:
    dest[6] = command_code & 0x7F; // just 7 bits
    dest[7] = 0x00; // checksum. leave 0

    // add payload
    if (payload_length) {
        memcpy(dest + 8, payload, payload_length);
    }
}

int NET_PACKET_send_udp_command(int fd, uint16_t stream_id, uint8_t command_code, uint16_t payload_length, const uint8_t *payload) {
    uint8_t buff[8 + payload_length];
    NET_PACKET_make_command_header(buff, stream_id, command_code, payload_length, payload);
    return NET_send_udp(fd, buff, 8 + payload_length, true);
}

bool NET_encrypt(const uint8_t *data, int size, int *dest_size, uint8_t **dest, bool command) {
#if EncryptionType == Cryptolib
    uint8_t *enc_frame;
    uint16_t enc_size;

    // all zero TC header. scid = 1 if packet is command
    memset(buff, 0, sizeof(buff));
    if (command) {
        buff[1] = 1;
    }
    memcpy(buff + TC_FRAME_HEADER_SIZE, data, size);

    const int32_t enc_res = Crypto_TC_ApplySecurity((uint8_t *) buff, size + TC_FRAME_HEADER_SIZE, &enc_frame, &enc_size);
    if (enc_res != 0) {
        printf("fatal CryptoLib status code %d\n", enc_res);
        fflush(stdout);
        abort();
    }

//    NET_print_hex(enc_frame, enc_size);

    *dest = enc_frame;
    *dest_size = enc_size;
    return false;

#else
    *dest = data;
    *dest_size = size;
    return false;
#endif

    return false;
}

bool NET_decrypt(const uint8_t *data, int size, int *dest_size, uint8_t **dest) {
#if EncryptionType == Cryptolib

    memset(&tc_frame_cryptolib_dec, 0, sizeof(tc_frame_cryptolib_dec));

    const int32_t dec_res = Crypto_TC_ProcessSecurity((uint8_t *) data, &size, &tc_frame_cryptolib_dec);
    if (dec_res != 0) {
        printf("fatal CryptoLib status code %d\n", dec_res);
        fflush(stdout);
        abort();
    }

    *dest_size = tc_frame_cryptolib_dec.tc_pdu_len;
    *dest = tc_frame_cryptolib_dec.tc_pdu;

    return false;

#else
    *dest = data;
    *dest_size = size;
    return false;
#endif

    return false;
}

void NET_start_measure(const char *name) {
    assert(ns_start == 0);
    time_name = name;
    ns_start = timestamp();
}

void NET_stop_measure(void) {
    const uint64_t stop = timestamp();
    const uint64_t elapsed = stop - ns_start;
    ns_start = 0;

#ifndef DontPrint
    printf("%s elapsed %lu\n", time_name, elapsed);
#endif
}
