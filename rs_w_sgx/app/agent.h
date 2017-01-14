#ifndef _AGENT_H_
#define _AGENT_H_

uint32_t agnt_send_message_ocall(uint32_t src_id, void *resp_message, size_t resp_message_size, int channel);
void *agent(void *threadid);

#endif
