#include "bgp.h"
#include "const.h"
#include "agent_process_message.h"

// [src_as_id][class_id][dest_as_id], 1 means send, 0 means not
uint32_t g_export_policies[POLICY_CLASS_NUM][AS_NUM] = {
    {0, 1, 1},
    {0, 1, 1},
    {0, 1, 1}
};

uint32_t handle_r_exch_data(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    handle_r_exch_data_core(src_id, dst_id, msg, msg_size, &g_export_policies);
}
