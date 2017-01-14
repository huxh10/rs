#ifndef _AGENT_PROCES_MESSAGE_H_
#define _AGENT_PROCES_MESSAGE_H_

#include "stdio.h"
#include "stdint.h"
#include "bgp.h"

uint32_t handle_r_exch_data_core(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size, export_policy_t *p_export_policies);

#endif
