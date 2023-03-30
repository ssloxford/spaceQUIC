#ifndef BENCHMARK_APP_H
#define BENCHMARK_APP_H

#include "cfe.h"
#include "cfe_error.h"
#include "cfe_evs.h"
#include "cfe_sb.h"
#include "cfe_es.h"

#include "benchmark_app_perfids.h"
#include "benchmark_app_msgids.h"
#include "benchmark_app_msg.h"

#define BENCHMARK_APP_PIPE_DEPTH 32

// global data
typedef struct {
    // command counter
    uint8 CmdCounter;
    uint8 ErrCounter;

    int packets_sent;
    bool send;
    BENCHMARK_APP_DataPacket_t data_packet;

    uint32 RunStatus;
    CFE_SB_PipeId_t CommandPipe;
    char PipeName[CFE_MISSION_MAX_API_LEN];
    uint16 PipeDepth;
} BENCHMARK_APP_Data_t;

/* functions */
void BENCHMARK_APP_Main(void);
int32 BENCHMARK_APP_Init(void);
void BENCHMARK_APP_ProcessCommandPacket(CFE_SB_Buffer_t *SBBufPtr);
void BENCHMARK_APP_ProcessGroundCommand(CFE_SB_Buffer_t *SBBufPtr);
void BENCHMARK_APP_SendData(void);

#endif
