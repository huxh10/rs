#ifndef __RS_W_SGX_H__
#define __RS_W_SGX_H__

void init_rs_w_sgx(uint32_t num, as_conf_t *p_as_conf);

void run_rs_w_sgx(int total_msg_numm, int preloaded_msg_num, bgp_msg_t **pp_bgp_msgs, int method, int verbose);

#endif
