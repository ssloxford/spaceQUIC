#include "space_quic.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "message.h"

#define TO_ENABLE_TELEM 6
#define TO_ADD_PCKT 2

#define BENCHMARK_NOOP 0
#define BENCHMARK_START_SEND 1

#define CFS_HOST "127.0.0.1"

int received_packets = 0;
int sent_data_packets = 0;

uint8_t *shm;

void on_telemetry_message(const uint8_t *data, size_t size) {
    if (get_stream_id(data) == BENCHMARK_APP_DataPacket_TLM_MID) {
        ++received_packets;
        if (received_packets == PACKETS_TO_SEND) {
            fprintf(stderr, "start send\n");
            *shm = 1;
        }
        fprintf(stderr, "got benchmark data packet\n");
    } else {
        NET_print_hex(data, (int) size);
        print_message(data, size);
    }
}

#ifndef Quic
void listen_telemetry() {
    struct sockaddr_in si_me, si_other;

    int s, i;
    socklen_t slen = sizeof(si_other);
    ssize_t recv_len;
    const int buf_len = 16800;
    char buf[buf_len];

    //create a UDP socket
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        assert(false);
    }

    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(1235);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket to port
    if (bind(s, (struct sockaddr *) &si_me, sizeof(si_me)) == -1) {
        assert(false);
    }

    printf("listening for telemetry\n");

    while (1) {
        if ((recv_len = recvfrom(s, buf, buf_len, 0, (struct sockaddr *) &si_other, &slen)) == -1) {
            assert(false);
        }

        uint8_t *dest;
        int dest_size;
        bool must_free = NET_decrypt((const uint8_t *) buf, (int) recv_len, &dest_size, &dest);

        on_telemetry_message(dest, dest_size);

        if (must_free) {
            free(dest);
        }
    }
}
#else
static int recv_stream_data_cb(ngtcp2_conn *conn,
                               uint32_t flags,
                               int64_t stream_id,
                               uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data,
                               void *stream_user_data) {
    on_telemetry_message(data, datalen);
    return 0;
}

void listen_telemetry() {
    QuicServer server;
    quic_server_init(&server, recv_stream_data_cb, false);
    quic_server_bind(&server, CFS_HOST, "1235");
    quic_server_setup_epoll(&server);

    while (true) {
        int r = quic_server_step(&server, 10000);
        assert(r == 0);
    }
}
#endif

#ifndef Quic
void send_commands() {
// open socket
    struct addrinfo *addr = NET_get_addrinfo(CFS_HOST, "1234");
    int fd = NET_open_udp(addr);

    // enable telem for local
    char ip[16] = CFS_HOST;
    int s = NET_PACKET_send_udp_command(fd, TO_LAB_CMD_MID, TO_ENABLE_TELEM, 16, (const uint8_t *) ip);
    if (s == 0) { printf("sent TO_ENABLE_TELEM\n"); }
    else abort();

    TO_LAB_AddPacket_Payload_t add_pckt_payload;
    add_pckt_payload.Stream = get_msg_id(BENCHMARK_APP_DataPacket_TLM_MID);
    add_pckt_payload.BufLimit = 0xFF;
    // add benchmark packet to telemetry output
    s = NET_PACKET_send_udp_command(fd, TO_LAB_CMD_MID, TO_ADD_PCKT, sizeof(add_pckt_payload), (const uint8_t *) &add_pckt_payload);
    if (s == 0) { printf("sent TO_ADD_PCKT\n"); }
    else abort();

    sleep(1);

//    for (int i = 0; i < 1; ++i) {
//        s = NET_PACKET_send_udp_command(addr, BENCHMARK_APP_CMD_MID, BENCHMARK_NOOP, 0, NULL);
//        if (s == 0) { printf("sent BENCHMARK_NOOP\n"); }
//    }

    s = NET_PACKET_send_udp_command(fd, BENCHMARK_APP_CMD_MID, BENCHMARK_START_SEND, 0, NULL);
    if (s == 0) { printf("sent BENCHMARK_START_SEND\n"); }
    else abort();

    // benchmark app directed command packet with data payload as big as the telemtry packet
    uint8_t cmd_data[PAYLOAD_SIZE];
//    s = NET_PACKET_send_udp_command(fd, BENCHMARK_APP_CMD_MID, BENCHMARK_APP_DATA_CC, PAYLOAD_SIZE, cmd_data);
//    if (s == 0) { printf("sent BENCHMARK_APP_DATA_CC\n"); }
//    else abort();

    uint64_t last_send_time = 0;

    while (true) {
        if (*shm && sent_data_packets < PACKETS_TO_SEND) {
            uint64_t now = timestamp();
            if (now - last_send_time > 2 * 1000000000ULL /* 2s */) {
                last_send_time = now;

                s = NET_PACKET_send_udp_command(fd, BENCHMARK_APP_CMD_MID, BENCHMARK_APP_DATA_CC, PAYLOAD_SIZE, cmd_data);
                if (s == 0) { printf("sent BENCHMARK_APP_DATA_CC\n"); }
                else abort();

                ++sent_data_packets;
            }
        }
    }

    NET_free_addrinfo(addr);
}
#else
void send_commands() {
    QuicClient client;
    quic_client_init(&client, false);
    quic_client_connect(&client, CFS_HOST, "1234");
    quic_client_setup_epoll(&client);

    int send_seq = 0;
    struct Command {
        uint8_t *data;
        size_t size;
    } data_packet, commands[3];

    // enable telem for local
    char ip[16] = CFS_HOST;
    uint8_t buff1[8 + 16];
    NET_PACKET_make_command_header(buff1, TO_LAB_CMD_MID, TO_ENABLE_TELEM, 16, (const uint8_t *) ip);
    commands[0].data = buff1;
    commands[0].size = sizeof(buff1);

    ////
    TO_LAB_AddPacket_Payload_t add_pckt_payload;
    add_pckt_payload.Stream = get_msg_id(BENCHMARK_APP_DataPacket_TLM_MID);
    add_pckt_payload.BufLimit = 0xFF;
    uint8_t buff2[sizeof(add_pckt_payload) + 8];
    // add benchmark packet to telemetry output
    NET_PACKET_make_command_header(buff2, TO_LAB_CMD_MID, TO_ADD_PCKT, sizeof(add_pckt_payload), (const uint8_t *) &add_pckt_payload);
    commands[1].data = buff2;
    commands[1].size = sizeof(buff2);

    // START SEND BENCHMARK
    uint8_t buff3[8];
    NET_PACKET_make_command_header(buff3, BENCHMARK_APP_CMD_MID, BENCHMARK_START_SEND, 0, NULL);
    commands[2].data = buff3;
    commands[2].size = sizeof(buff3);

    // benchmark app directed command packet with data payload as big as the telemetry packet
    uint8_t cmd_data[PAYLOAD_SIZE];
    memset(cmd_data, 1, sizeof(cmd_data));
    uint8_t buff4[PAYLOAD_SIZE + 8];
    NET_PACKET_make_command_header(buff4, BENCHMARK_APP_CMD_MID, BENCHMARK_APP_DATA_CC, PAYLOAD_SIZE, cmd_data);
    data_packet.data = buff4;
    data_packet.size = sizeof(buff4);

    uint64_t last_send_time = 0;

    while (true) {
        while (send_seq < sizeof(commands) / sizeof(commands[0])) {
            if (quic_client_write(&client, commands[send_seq].data, commands[send_seq].size) == 0) {
                fprintf(stderr, "sent\n");
                ++send_seq;
            } else break;
        }

        if (*shm && sent_data_packets < PACKETS_TO_SEND) {
            uint64_t now = timestamp();
            if (now - last_send_time > 2 * 1000000000ULL /* 2s */) {
                last_send_time = now;
                if (quic_client_write(&client, data_packet.data, data_packet.size) == 0) {
                    fprintf(stderr, "sent BENCHMARK data packet\n");
                    ++sent_data_packets;
                }
            }
        }

        {
            int r = quic_client_step(&client, 10);
            assert(r == 0);
        }
    }
}
#endif

int main(int argc, char *argv[]) {
    NET_SPACE_QUIC_Init();

    int shm_fd = shm_open("benchshm", O_CREAT | O_RDWR, 0666);
    ftruncate(shm_fd, 8);
    shm = mmap(0, 8, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    *shm = 0;

    int pid = fork();
    if (pid != 0) {
        listen_telemetry();
        return 0;
    }

    send_commands();

    return 0;
}
