#ifndef _AS_PROCESS_MESSAGE_H_
#define _AS_PROCESS_MESSAGE_H_

void as_start_session_handshake_to_agnt(int sfd, uint32_t id);
int load_rib(const char *file_name);

uint32_t as_process_message(int sfd, void *req_message, size_t req_message_size);
uint32_t handle_r_send_msg0(int sfd, void *msg, size_t msg_size);
uint32_t handle_r_send_msg1(int sfd, void *msg, size_t msg_size);
uint32_t handle_r_send_msg3(int sfd, void *msg, size_t msg_size);
uint32_t handle_r_exch_data(int sfd, void *msg, size_t msg_size);

#endif
