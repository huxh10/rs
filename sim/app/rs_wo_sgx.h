#ifndef __RS_WO_SGX_H__
#define __RS_WO_SGX_H__

void init_rs_wo_sgx(uint32_t num, as_conf_t *p_as_conf);

void run_rs_wo_sgx(int total_msg_num, int preloaded_msg_num, bgp_msg_t **pp_bgp_msgs, int method, int verbose);

#endif
