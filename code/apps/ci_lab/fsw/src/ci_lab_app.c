/************************************************************************
 * NASA Docket No. GSC-18,719-1, and identified as “core Flight System: Bootes”
 *
 * Copyright (c) 2020 United States Government as represented by the
 * Administrator of the National Aeronautics and Space Administration.
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ************************************************************************/

/**
 * \file
 *   This file contains the source code for the Command Ingest task.
 */

/*
**   Include Files:
*/

#include <assert.h>
#include "ci_lab_app.h"
#include "ci_lab_perfids.h"
#include "ci_lab_msgids.h"
#include "ci_lab_msg.h"
#include "ci_lab_events.h"
#include "ci_lab_version.h"
#include "../../../libs/space_quic/fsw/public_inc/space_quic.h"

/*
** CI global data...
*/

typedef struct {
    bool SocketConnected;
    CFE_SB_PipeId_t CommandPipe;
    osal_id_t SocketID;
    OS_SockAddr_t SocketAddress;

    CI_LAB_HkTlm_t HkTlm;

    CFE_SB_Buffer_t *NextIngestBufPtr;

#ifdef Quic
    QuicServer quic_server;
#endif

} CI_LAB_GlobalData_t;

CI_LAB_GlobalData_t CI_LAB_Global;


int32 CI_LAB_Noop(const CI_LAB_NoopCmd_t *data);
int32 CI_LAB_ResetCounters(const CI_LAB_ResetCountersCmd_t *data);
int32 CI_LAB_ReportHousekeeping(const CFE_MSG_CommandHeader_t *data);

void CI_Lab_AppMain(void) {
    int32 status;
    uint32 RunStatus = CFE_ES_RunStatus_APP_RUN;
    CFE_SB_Buffer_t *SBBufPtr;

    CFE_ES_PerfLogEntry(CI_LAB_MAIN_TASK_PERF_ID);

    CI_LAB_TaskInit();

    /*
    ** CI Runloop
    */
    while (CFE_ES_RunLoop(&RunStatus) == true) {
        CFE_ES_PerfLogExit(CI_LAB_MAIN_TASK_PERF_ID);

        /* Pend on receipt of command packet -- timeout set to 500 millisecs */
        status = CFE_SB_ReceiveBuffer(&SBBufPtr, CI_LAB_Global.CommandPipe, 500);

        CFE_ES_PerfLogEntry(CI_LAB_MAIN_TASK_PERF_ID);

        if (status == CFE_SUCCESS) {
            CI_LAB_ProcessCommandPacket(SBBufPtr);
        }

        /* Regardless of packet vs timeout, always process uplink queue      */
        if (CI_LAB_Global.SocketConnected) {
            CI_LAB_ReadUpLink();
        }
    }

    CFE_ES_ExitApp(RunStatus);

} /* End of CI_Lab_AppMain() */

/*
** CI delete callback function.
** This function will be called in the event that the CI app is killed.
** It will close the network socket for CI
*/
void CI_LAB_delete_callback(void) {
    OS_printf("CI delete callback -- Closing CI Network socket.\n");
    OS_close(CI_LAB_Global.SocketID);
}

#ifdef Quic
static int recv_stream_data_cb(ngtcp2_conn *conn,
                               uint32_t flags,
                               int64_t stream_id,
                               uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data,
                               void *stream_user_data) {
    if (CI_LAB_Global.NextIngestBufPtr == NULL) {
        CI_LAB_Global.NextIngestBufPtr = CFE_SB_AllocateMessageBuffer(CI_LAB_MAX_INGEST);
        if (CI_LAB_Global.NextIngestBufPtr == NULL) {
            CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: L%d, buffer allocation failed\n", __LINE__);
            abort();
        }
    }

//    NET_print_hex(data, datalen);

    assert(datalen < CI_LAB_MAX_INGEST);
    memcpy(CI_LAB_Global.NextIngestBufPtr, data, datalen);

    if (datalen >= (int32) sizeof(CFE_MSG_CommandHeader_t) && datalen <= ((int32) CI_LAB_MAX_INGEST)) {
        OS_printf("INFO: received CI packet of size %zu\n", datalen);

        CFE_ES_PerfLogEntry(CI_LAB_SOCKET_RCV_PERF_ID);
        CI_LAB_Global.HkTlm.Payload.IngestPackets++;
        int status = CFE_SB_TransmitBuffer(CI_LAB_Global.NextIngestBufPtr, false);
        CFE_ES_PerfLogExit(CI_LAB_SOCKET_RCV_PERF_ID);

        if (status == CFE_SUCCESS) {
            /* Set NULL so a new buffer will be obtained next time around */
            CI_LAB_Global.NextIngestBufPtr = NULL;
        } else {
            CFE_EVS_SendEvent(CI_LAB_INGEST_SEND_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: L%d, CFE_SB_TransmitBuffer() failed, status=%d\n", __LINE__, (int) status);
        }

        return 0;
    } else if (datalen > 0) {
        /* bad size, report as ingest error */
        CI_LAB_Global.HkTlm.Payload.IngestErrors++;

        uint8_t *bytes = CI_LAB_Global.NextIngestBufPtr->Msg.Byte;
        CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: L%d, cmd %0x%0x %0x%0x dropped, bad length=%d\n", __LINE__, bytes[0], bytes[1],
                          bytes[2], bytes[3], (int) datalen);
    }
    return 0;
}
#endif

void CI_LAB_TaskInit(void) {
    memset(&CI_LAB_Global, 0, sizeof(CI_LAB_Global));

    CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);

    CFE_SB_CreatePipe(&CI_LAB_Global.CommandPipe, CI_LAB_PIPE_DEPTH, "CI_LAB_CMD_PIPE");
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CI_LAB_CMD_MID), CI_LAB_Global.CommandPipe);
    CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CI_LAB_SEND_HK_MID), CI_LAB_Global.CommandPipe);

#ifndef Quic
    int32 status;
    uint16 DefaultListenPort;

    status = OS_SocketOpen(&CI_LAB_Global.SocketID, OS_SocketDomain_INET, OS_SocketType_DATAGRAM);
    if (status != OS_SUCCESS) {
        CFE_EVS_SendEvent(CI_LAB_SOCKETCREATE_ERR_EID, CFE_EVS_EventType_ERROR, "CI: create socket failed = %d", (int) status);
        abort();
    } else {
        OS_SocketAddrInit(&CI_LAB_Global.SocketAddress, OS_SocketDomain_INET);
        DefaultListenPort = CI_LAB_BASE_UDP_PORT + CFE_PSP_GetProcessorId() - 1;
        OS_SocketAddrSetPort(&CI_LAB_Global.SocketAddress, DefaultListenPort);

        status = OS_SocketBind(CI_LAB_Global.SocketID, &CI_LAB_Global.SocketAddress);

        if (status != OS_SUCCESS) {
            CFE_EVS_SendEvent(CI_LAB_SOCKETBIND_ERR_EID, CFE_EVS_EventType_ERROR, "CI: bind socket failed = %d", (int) status);
            abort();
        } else {
            CI_LAB_Global.SocketConnected = true;
            CFE_ES_WriteToSysLog("CI_LAB listening on UDP port: %u\n", (unsigned int) DefaultListenPort);
        }
    }
#else
    // QUIC
    quic_server_init(&CI_LAB_Global.quic_server, recv_stream_data_cb, false);
    quic_server_bind(&CI_LAB_Global.quic_server, "127.0.0.1", "1234");
    quic_server_setup_epoll(&CI_LAB_Global.quic_server);
    CI_LAB_Global.SocketConnected = true;
    CFE_ES_WriteToSysLog("CI_LAB QUIC listening on UDP port: 1234\n");
#endif

    CI_LAB_ResetCounters_Internal();

    /*
    ** Install the delete handler
    */
    OS_TaskInstallDeleteHandler(&CI_LAB_delete_callback);

    CFE_MSG_Init(CFE_MSG_PTR(CI_LAB_Global.HkTlm.TelemetryHeader), CFE_SB_ValueToMsgId(CI_LAB_HK_TLM_MID),
                 sizeof(CI_LAB_Global.HkTlm));

    CFE_EVS_SendEvent(CI_LAB_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION, "CI Lab Initialized.%s",
                      CI_LAB_VERSION_STRING);

} /* End of CI_LAB_TaskInit() */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/
/*  Name:  CI_LAB_ProcessCommandPacket                                        */
/*                                                                            */
/*  Purpose:                                                                  */
/*     This routine will process any packet that is received on the CI command*/
/*     pipe. The packets received on the CI command pipe are listed here:     */
/*                                                                            */
/*        1. NOOP command (from ground)                                       */
/*        2. Request to reset telemetry counters (from ground)                */
/*        3. Request for housekeeping telemetry packet (from HS task)         */
/*                                                                            */
/* * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * *  * *  * * * * */
void CI_LAB_ProcessCommandPacket(CFE_SB_Buffer_t *SBBufPtr) {
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId)) {
        case CI_LAB_CMD_MID:
            CI_LAB_ProcessGroundCommand(SBBufPtr);
            break;

        case CI_LAB_SEND_HK_MID:
            CI_LAB_ReportHousekeeping((const CFE_MSG_CommandHeader_t *) SBBufPtr);
            break;

        default:
            CI_LAB_Global.HkTlm.Payload.CommandErrorCounter++;
            CFE_EVS_SendEvent(CI_LAB_COMMAND_ERR_EID, CFE_EVS_EventType_ERROR, "CI: invalid command packet,MID = 0x%x",
                              (unsigned int) CFE_SB_MsgIdToValue(MsgId));
            break;
    }

    return;

} /* End CI_LAB_ProcessCommandPacket */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/
/*                                                                            */
/* CI_LAB_ProcessGroundCommand() -- CI ground commands                        */
/*                                                                            */
/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * **/

void CI_LAB_ProcessGroundCommand(CFE_SB_Buffer_t *SBBufPtr) {
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &CommandCode);

    /* Process "known" CI task ground commands */
    switch (CommandCode) {
        case CI_LAB_NOOP_CC:
            if (CI_LAB_VerifyCmdLength(&SBBufPtr->Msg, sizeof(CI_LAB_NoopCmd_t))) {
                CI_LAB_Noop((const CI_LAB_NoopCmd_t *) SBBufPtr);
            }
            break;

        case CI_LAB_RESET_COUNTERS_CC:
            if (CI_LAB_VerifyCmdLength(&SBBufPtr->Msg, sizeof(CI_LAB_ResetCountersCmd_t))) {
                CI_LAB_ResetCounters((const CI_LAB_ResetCountersCmd_t *) SBBufPtr);
            }
            break;

            /* default case already found during FC vs length test */
        default:
            break;
    }
}

int32 CI_LAB_Noop(const CI_LAB_NoopCmd_t *data) {
    /* Does everything the name implies */
    CI_LAB_Global.HkTlm.Payload.CommandCounter++;

    CFE_EVS_SendEvent(CI_LAB_COMMANDNOP_INF_EID, CFE_EVS_EventType_INFORMATION, "CI: NOOP command");

    return CFE_SUCCESS;
}

int32 CI_LAB_ResetCounters(const CI_LAB_ResetCountersCmd_t *data) {
    CFE_EVS_SendEvent(CI_LAB_COMMANDRST_INF_EID, CFE_EVS_EventType_INFORMATION, "CI: RESET command");
    CI_LAB_ResetCounters_Internal();
    return CFE_SUCCESS;
}

int32 CI_LAB_ReportHousekeeping(const CFE_MSG_CommandHeader_t *data) {
    CI_LAB_Global.HkTlm.Payload.SocketConnected = CI_LAB_Global.SocketConnected;
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(CI_LAB_Global.HkTlm.TelemetryHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(CI_LAB_Global.HkTlm.TelemetryHeader), true);
    return CFE_SUCCESS;

} /* End of CI_LAB_ReportHousekeeping() */

void CI_LAB_ResetCounters_Internal(void) {
    /* Status of commands processed by CI task */
    CI_LAB_Global.HkTlm.Payload.CommandCounter = 0;
    CI_LAB_Global.HkTlm.Payload.CommandErrorCounter = 0;

    /* Status of packets ingested by CI task */
    CI_LAB_Global.HkTlm.Payload.IngestPackets = 0;
    CI_LAB_Global.HkTlm.Payload.IngestErrors = 0;
} /* End of CI_LAB_ResetCounters() */

void CI_LAB_ReadUpLink(void) {
#ifndef Quic
    int i;
    int32 status;
    uint8 *bytes;
    for (i = 0; i <= 10; i++) {
        if (CI_LAB_Global.NextIngestBufPtr == NULL) {
            CI_LAB_Global.NextIngestBufPtr = CFE_SB_AllocateMessageBuffer(CI_LAB_MAX_INGEST);
            if (CI_LAB_Global.NextIngestBufPtr == NULL) {
                CFE_EVS_SendEvent(CI_LAB_INGEST_ALLOC_ERR_EID, CFE_EVS_EventType_ERROR,
                                  "CI: L%d, buffer allocation failed\n", __LINE__);
                break;
            }
        }

        // ----------
        status = OS_SocketRecvFrom(CI_LAB_Global.SocketID, CI_LAB_Global.NextIngestBufPtr, CI_LAB_MAX_INGEST,
                                   &CI_LAB_Global.SocketAddress, OS_CHECK);

        if (status >= (int32) sizeof(CFE_MSG_CommandHeader_t) && status <= ((int32) CI_LAB_MAX_INGEST)) {
            OS_printf("INFO: received CI packet of size %d\n", status);

            /*** decryption ***/
            uint8_t *dest;
            int dest_size;
            bool must_free = NET_decrypt((const uint8_t *) CI_LAB_Global.NextIngestBufPtr, (int) status, &dest_size, &dest);
            if ((uint8_t *) CI_LAB_Global.NextIngestBufPtr != dest) {
                memcpy(CI_LAB_Global.NextIngestBufPtr, dest, dest_size);
            }
            if (must_free) {
                free(dest);
            }
            ///

            CFE_ES_PerfLogEntry(CI_LAB_SOCKET_RCV_PERF_ID);
            CI_LAB_Global.HkTlm.Payload.IngestPackets++;
            status = CFE_SB_TransmitBuffer(CI_LAB_Global.NextIngestBufPtr, false);
            CFE_ES_PerfLogExit(CI_LAB_SOCKET_RCV_PERF_ID);

            if (status == CFE_SUCCESS) {
                /* Set NULL so a new buffer will be obtained next time around */
                CI_LAB_Global.NextIngestBufPtr = NULL;
            } else {
                CFE_EVS_SendEvent(CI_LAB_INGEST_SEND_ERR_EID, CFE_EVS_EventType_ERROR,
                                  "CI: L%d, CFE_SB_TransmitBuffer() failed, status=%d\n", __LINE__, (int) status);
            }
        } else if (status > 0) {
            /* bad size, report as ingest error */
            CI_LAB_Global.HkTlm.Payload.IngestErrors++;

            bytes = CI_LAB_Global.NextIngestBufPtr->Msg.Byte;
            CFE_EVS_SendEvent(CI_LAB_INGEST_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                              "CI: L%d, cmd %0x%0x %0x%0x dropped, bad length=%d\n", __LINE__, bytes[0], bytes[1],
                              bytes[2], bytes[3], (int) status);
        } else {
            break; /* no (more) messages */
        }
    }
#else
    int r = quic_server_step(&CI_LAB_Global.quic_server, 10);
    assert(r != -1);
#endif
}

bool CI_LAB_VerifyCmdLength(CFE_MSG_Message_t *MsgPtr, size_t ExpectedLength) {
    bool result = true;
    size_t ActualLength = 0;
    CFE_MSG_FcnCode_t FcnCode = 0;
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    CFE_MSG_GetSize(MsgPtr, &ActualLength);

    /*
    ** Verify the command packet length...
    */
    if (ExpectedLength != ActualLength) {
        CFE_MSG_GetMsgId(MsgPtr, &MsgId);
        CFE_MSG_GetFcnCode(MsgPtr, &FcnCode);

        CFE_EVS_SendEvent(CI_LAB_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "Invalid msg length: ID = 0x%X,  CC = %u, Len = %u, Expected = %u",
                          (unsigned int) CFE_SB_MsgIdToValue(MsgId), (unsigned int) FcnCode, (unsigned int) ActualLength,
                          (unsigned int) ExpectedLength);
        result = false;
        CI_LAB_Global.HkTlm.Payload.CommandErrorCounter++;
    }

    return (result);

}
