#include "benchmark_app_events.h"
#include "benchmark_app.h"

#include "space_quic.h"
#include <string.h>
#include <assert.h>

BENCHMARK_APP_Data_t BENCHMARK_APP_Data;

void BENCHMARK_APP_Main(void) {
    int32 status;
    CFE_SB_Buffer_t *SBBufPtr;

    CFE_ES_PerfLogEntry(BENCHMARK_APP_PERF_ID);

    status = BENCHMARK_APP_Init();
    if (status != CFE_SUCCESS) {
        BENCHMARK_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&BENCHMARK_APP_Data.RunStatus) == true) {
        // poll for command
        status = CFE_SB_ReceiveBuffer(&SBBufPtr, BENCHMARK_APP_Data.CommandPipe, 2000 /* 2s timeout */);

        if (status == CFE_SB_TIME_OUT) {
            if (BENCHMARK_APP_Data.send && BENCHMARK_APP_Data.packets_sent < PACKETS_TO_SEND) {
                BENCHMARK_APP_SendData();
            }
            continue;
        }

        if (status == CFE_SUCCESS) {
            BENCHMARK_APP_ProcessCommandPacket(SBBufPtr);
        } else {
            CFE_EVS_SendEvent(BENCHMARK_APP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "BENCHMARK APP: SB Pipe Read Error, App Will Exit");
            BENCHMARK_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
            abort();
        }
    }

    CFE_ES_PerfLogExit(BENCHMARK_APP_PERF_ID);

    CFE_ES_ExitApp(BENCHMARK_APP_Data.RunStatus);
}

int32 BENCHMARK_APP_Init(void) {
    int32 status;

    BENCHMARK_APP_Data.RunStatus = CFE_ES_RunStatus_APP_RUN;
    BENCHMARK_APP_Data.CmdCounter = 0;
    BENCHMARK_APP_Data.ErrCounter = 0;
    BENCHMARK_APP_Data.PipeDepth = BENCHMARK_APP_PIPE_DEPTH;

    strncpy(BENCHMARK_APP_Data.PipeName, "BENCHMARK_APP_CMD_PIPE", sizeof(BENCHMARK_APP_Data.PipeName));
    BENCHMARK_APP_Data.PipeName[sizeof(BENCHMARK_APP_Data.PipeName) - 1] = 0;

    BENCHMARK_APP_Data.packets_sent = 0;
    BENCHMARK_APP_Data.send = false;

    /***/
    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS) {
        CFE_ES_WriteToSysLog("Sample App: Error Registering Events, RC = 0x%08lX\n", (unsigned long) status);
        return (status);
    }

    // initialise data packet
    // sets size and id in header
    CFE_MSG_Init(CFE_MSG_PTR(BENCHMARK_APP_Data.data_packet.TelemetryHeader), CFE_SB_ValueToMsgId(BENCHMARK_APP_DataPacket_TLM_MID), sizeof(BENCHMARK_APP_Data.data_packet));

    // create SB pipe
    status = CFE_SB_CreatePipe(&BENCHMARK_APP_Data.CommandPipe, BENCHMARK_APP_Data.PipeDepth, BENCHMARK_APP_Data.PipeName);
    if (status != CFE_SUCCESS) {
        CFE_ES_WriteToSysLog("Sample App: Error creating pipe, RC = 0x%08lX\n", (unsigned long) status);
        return (status);
    }

    // subscribe to commands
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(BENCHMARK_APP_CMD_MID), BENCHMARK_APP_Data.CommandPipe);
    if (status != CFE_SUCCESS) {
        CFE_ES_WriteToSysLog("Sample App: Error Subscribing to Command, RC = 0x%08lX\n", (unsigned long) status);
        return (status);
    }

    // disable stdout buffering
//    setbuf(stdout, NULL);

    CFE_EVS_SendEvent(BENCHMARK_APP_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION, "BENCH App Initialized");

    return (CFE_SUCCESS);

}

// processes commands received on pipe
void BENCHMARK_APP_ProcessCommandPacket(CFE_SB_Buffer_t *SBBufPtr) {
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId)) {
        case BENCHMARK_APP_CMD_MID:
            BENCHMARK_APP_ProcessGroundCommand(SBBufPtr);
            break;
        default:
            fprintf(stderr, "BENCHMARK: invalid command packet,MID = 0x%x", (unsigned int) CFE_SB_MsgIdToValue(MsgId));
            abort();
    }
}

// process ground command
void BENCHMARK_APP_ProcessGroundCommand(CFE_SB_Buffer_t *SBBufPtr) {
    CFE_MSG_FcnCode_t CommandCode = 0;
    CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &CommandCode);

    switch (CommandCode) {
        case BENCHMARK_APP_Start_CC:
            /* set send=true s.t. data will be sent next SB timeout */
            BENCHMARK_APP_Data.send = true;
            /* set data */
            memcpy(BENCHMARK_APP_Data.data_packet.data, &BENCHMARK_APP_Data.packets_sent, sizeof(BENCHMARK_APP_Data.packets_sent));
            for (int i = 4; i < sizeof(BENCHMARK_APP_Data.data_packet.data); ++i) {
                BENCHMARK_APP_Data.data_packet.data[i] = i % 0xFF;
            }
            break;
        case BENCHMARK_APP_NOOP_CC:
            BENCHMARK_APP_Data.CmdCounter++;
            CFE_EVS_SendEvent(BENCHMARK_APP_COMMANDNOP_INF_EID, CFE_EVS_EventType_INFORMATION, "BENCH: NOOP command");
            break;
        case BENCHMARK_APP_DATA_CC:
            BENCHMARK_APP_Data.CmdCounter++;
            OS_printf("BENCH: got data payload command");
//            CFE_EVS_SendEvent(BENCHMARK_APP_COMMANDNOP_INF_EID, CFE_EVS_EventType_INFORMATION, "BENCH: received data payload command");
            break;
        default:
            fprintf(stderr, "Invalid ground command code: CC = %d", CommandCode);
            abort();
    }
}

void BENCHMARK_APP_SendData() {
    // increment and transmit
    BENCHMARK_APP_Data.packets_sent++;
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(BENCHMARK_APP_Data.data_packet.TelemetryHeader));
    int r = CFE_SB_TransmitMsg(CFE_MSG_PTR(BENCHMARK_APP_Data.data_packet.TelemetryHeader), true);
    assert(r == CFE_SUCCESS);
}
