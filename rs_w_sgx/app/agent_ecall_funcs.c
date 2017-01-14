#include "agent_ecall_funcs.h"
#include "../enclave0/enclave0_u.h"
#include "../enclave1/enclave1_u.h"
#include "../enclave2/enclave2_u.h"

agnt_handler_t g_handlers[AGNT_NUM];

void init_agent_handlers()
{
    // agent 0
    g_handlers[0].handle_l_init_session_ecall = enclave0_handle_l_init_session;
    g_handlers[0].handle_l_req_session_ecall = enclave0_handle_l_req_session;
    g_handlers[0].handle_l_rep_msg1_ecall = enclave0_handle_l_rep_msg1;
    g_handlers[0].handle_l_exch_report_ecall = enclave0_handle_l_exch_report;
    g_handlers[0].handle_l_rep_msg3_ecall = enclave0_handle_l_rep_msg3;
    g_handlers[0].handle_l_exch_data_ecall = enclave0_handle_l_exch_data;
    g_handlers[0].handle_r_init_session_ecall = enclave0_handle_r_init_session;
    g_handlers[0].init_ra_ecall = enclave0_init_ra;
    g_handlers[0].ra_get_ga_ecall = enclave0_sgx_ra_get_ga;
    g_handlers[0].handle_r_rep_msg0_ecall = enclave0_handle_r_rep_msg0;
    g_handlers[0].get_ra_context_ecall = enclave0_get_ra_context;
    g_handlers[0].ra_proc_msg2_ecall = enclave0_sgx_ra_proc_msg2_trusted;
    g_handlers[0].ra_get_msg3_ecall = enclave0_sgx_ra_get_msg3_trusted;
    g_handlers[0].handle_r_send_msg2_ecall = enclave0_handle_r_send_msg2;
    g_handlers[0].handle_r_send_result_ecall = enclave0_handle_r_send_result;
    g_handlers[0].handle_r_exch_data_ecall = enclave0_handle_r_exch_data;
    // agent 1
    g_handlers[1].handle_l_init_session_ecall = enclave1_handle_l_init_session;
    g_handlers[1].handle_l_req_session_ecall = enclave1_handle_l_req_session;
    g_handlers[1].handle_l_rep_msg1_ecall = enclave1_handle_l_rep_msg1;
    g_handlers[1].handle_l_exch_report_ecall = enclave1_handle_l_exch_report;
    g_handlers[1].handle_l_rep_msg3_ecall = enclave1_handle_l_rep_msg3;
    g_handlers[1].handle_l_exch_data_ecall = enclave1_handle_l_exch_data;
    g_handlers[1].handle_r_init_session_ecall = enclave1_handle_r_init_session;
    g_handlers[1].init_ra_ecall = enclave1_init_ra;
    g_handlers[1].ra_get_ga_ecall = enclave1_sgx_ra_get_ga;
    g_handlers[1].handle_r_rep_msg0_ecall = enclave1_handle_r_rep_msg0;
    g_handlers[1].get_ra_context_ecall = enclave1_get_ra_context;
    g_handlers[1].ra_proc_msg2_ecall = enclave1_sgx_ra_proc_msg2_trusted;
    g_handlers[1].ra_get_msg3_ecall = enclave1_sgx_ra_get_msg3_trusted;
    g_handlers[1].handle_r_send_msg2_ecall = enclave1_handle_r_send_msg2;
    g_handlers[1].handle_r_send_result_ecall = enclave1_handle_r_send_result;
    g_handlers[1].handle_r_exch_data_ecall = enclave1_handle_r_exch_data;
    // agent 2
    g_handlers[2].handle_l_init_session_ecall = enclave2_handle_l_init_session;
    g_handlers[2].handle_l_req_session_ecall = enclave2_handle_l_req_session;
    g_handlers[2].handle_l_rep_msg1_ecall = enclave2_handle_l_rep_msg1;
    g_handlers[2].handle_l_exch_report_ecall = enclave2_handle_l_exch_report;
    g_handlers[2].handle_l_rep_msg3_ecall = enclave2_handle_l_rep_msg3;
    g_handlers[2].handle_l_exch_data_ecall = enclave2_handle_l_exch_data;
    g_handlers[2].handle_r_init_session_ecall = enclave2_handle_r_init_session;
    g_handlers[2].init_ra_ecall = enclave2_init_ra;
    g_handlers[2].ra_get_ga_ecall = enclave2_sgx_ra_get_ga;
    g_handlers[2].handle_r_rep_msg0_ecall = enclave2_handle_r_rep_msg0;
    g_handlers[2].get_ra_context_ecall = enclave2_get_ra_context;
    g_handlers[2].ra_proc_msg2_ecall = enclave2_sgx_ra_proc_msg2_trusted;
    g_handlers[2].ra_get_msg3_ecall = enclave2_sgx_ra_get_msg3_trusted;
    g_handlers[2].handle_r_send_msg2_ecall = enclave2_handle_r_send_msg2;
    g_handlers[2].handle_r_send_result_ecall = enclave2_handle_r_send_result;
    g_handlers[2].handle_r_exch_data_ecall = enclave2_handle_r_exch_data;
}
