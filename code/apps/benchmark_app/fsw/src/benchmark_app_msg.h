#ifndef BENCHMARK_APP_MSG_H
#define BENCHMARK_APP_MSG_H

#define BENCHMARK_APP_NOOP_CC  0
#define BENCHMARK_APP_Start_CC 1
#define BENCHMARK_APP_DATA_CC 2

#include "space_quic.h"

/* commands */
typedef struct {
    CFE_MSG_CommandHeader_t CmdHeader; // CCSDS header
} BENCHMARK_APP_NoArgsCmd_t;
typedef BENCHMARK_APP_NoArgsCmd_t BENCHMARK_APP_Start_t; // when received, app starts sending data packets
typedef BENCHMARK_APP_NoArgsCmd_t BENCHMARK_APP_NOOP_t; // do nothing

// command with data payload of same size as telemetry packet
typedef struct {
    CFE_MSG_CommandHeader_t CmdHeader; // CCSDS header
    uint8_t data[PAYLOAD_SIZE];
} BENCHMARK_APP_DataCommand_c;

/* telemetry */
typedef struct {
    CFE_MSG_TelemetryHeader_t TelemetryHeader; // CCSDS header
    uint8_t data[PAYLOAD_SIZE];
} BENCHMARK_APP_DataPacket_t;

#endif
