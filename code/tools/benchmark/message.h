#ifndef CFETOOLS_MESSAGE_H
#define CFETOOLS_MESSAGE_H

#include "space_quic.h"

#include "mirrored_includes/cfe_msg_api_typedefs.h"
#include "mirrored_includes/default_cfe_msg_hdr_pri.h"
#include "mirrored_includes/default_cfe_msg_sechdr.h"
#include "mirrored_includes/cfe_sb_extern_typedefs.h"

#include "../../apps/to_lab/fsw/platform_inc/to_lab_msgids.h"
#include "../../apps/to_lab/fsw/src/to_lab_msg.h"
#include "../../apps/benchmark_app/fsw/platform_inc/benchmark_app_msgids.h"

#include "../../apps/benchmark_app/fsw/platform_inc/benchmark_app_msgids.h"
#include "../../apps/benchmark_app/fsw/src/benchmark_app_msg.h"

struct __attribute__((__packed__)) EventMessage {
    struct CFE_MSG_TelemetryHeader telem_header;

    char AppName[20];
    uint16_t EventID;
    uint16_t EventType;
    uint32_t SpacecraftID;
    uint32_t ProcessorID;

    char Message[122];
    uint8_t Spare1;
    uint8_t Spare2;
};

void print_message(const uint8_t *msg, size_t size);
CFE_SB_MsgId_t get_msg_id(int raw);
uint16_t get_stream_id(const uint8_t *mem);

#endif
