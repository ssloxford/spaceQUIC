#include "message.h"
#include <stdio.h>
#include <netinet/in.h>

void print_message(const uint8_t *mem, size_t size) {
    const struct EventMessage *msg = (const struct EventMessage *) mem;

    const uint16_t stream_id = get_stream_id(mem);
    if (stream_id == 2056) {
        printf("(msg) length: %d; stream_id: %hu; app_name: %s; event_id: %hu, event_type: %hu; spacecraft_id: %u; proc_id: %u; message: %s\n",
               ntohs(*(uint16_t *) msg->telem_header.Msg.CCSDS.Pri.Length), stream_id, msg->AppName, msg->EventID,
               msg->EventType, msg->SpacecraftID, msg->ProcessorID, msg->Message);
    } else if (stream_id == BENCHMARK_APP_DataPacket_TLM_MID) {
        const BENCHMARK_APP_DataPacket_t *data = (const BENCHMARK_APP_DataPacket_t *) mem;
        printf("(msg) BENCHMARK DataPacket. payload hex:\n");
        NET_print_hex(data->data, sizeof(data->data));
    }
}

CFE_SB_MsgId_t get_msg_id(int raw) {
    CFE_SB_MsgId_t x;
    x.Value = raw;
    return x;
}

uint16_t get_stream_id(const uint8_t *mem) {
    const struct EventMessage *msg = (const struct EventMessage *) mem;
    const uint16_t stream_id = ntohs(*(uint16_t *) msg->telem_header.Msg.CCSDS.Pri.StreamId);
    return stream_id;
}
