#ifndef _AGENT_ECALL_FUNCS_H_
#define _AGENT_ECALL_FUNCS_H_

#include <stdio.h>
#include "const.h"
#include "sgx_eid.h"
#include "sgx_ukey_exchange.h"

// ra handle rep_msg0 functions
typedef sgx_status_t (*enclave_init_ra_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        int b_pse,
        sgx_ra_context_t *p_context);

typedef sgx_status_t (*sgx_ra_get_msg1_t)(
        sgx_ra_context_t context,
        sgx_enclave_id_t eid,
        sgx_ecall_get_ga_trusted_t p_get_ga,
        sgx_ra_msg1_t *p_msg1);

typedef sgx_status_t (*enclave_handle_ra_rep_msg0_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        uint32_t dst_id,
        sgx_ra_msg1_t *p_msg1);

// ra handle send_msg2 functions
typedef sgx_status_t (*enclave_get_ra_context_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        sgx_ra_context_t *p_context);

typedef sgx_status_t (*sgx_ra_proc_msg2_t)(
        sgx_ra_context_t context,
        sgx_enclave_id_t eid,
        sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
        sgx_ecall_get_msg3_trusted_t p_get_msg3,
        const sgx_ra_msg2_t *p_msg2,
        uint32_t msg2_size,
        sgx_ra_msg3_t **pp_msg3,
        uint32_t *p_msg3_size);

typedef sgx_status_t (*enclave_handle_ra_rep_msg0_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        uint32_t dst_id,
        sgx_ra_msg1_t *p_msg1);

typedef sgx_status_t (*enclave_handle_init_msg_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        uint32_t dst_id);

typedef sgx_status_t (*enclave_handle_genrl_msg_t)(
        sgx_enclave_id_t eid,
        uint32_t *retval,
        uint32_t src_id,
        uint32_t dst_id,
        void *msg,
        size_t msg_size);

typedef sgx_status_t (*wo_enclave_handle_genrl_msg_t)(
        uint32_t src_id,
        uint32_t dst_id,
        void *msg,
        size_t msg_size);

typedef struct {
    //----handle la
    enclave_handle_init_msg_t handle_l_init_session_ecall;
    enclave_handle_init_msg_t handle_l_req_session_ecall;
    enclave_handle_genrl_msg_t handle_l_rep_msg1_ecall;
    enclave_handle_genrl_msg_t handle_l_exch_report_ecall;
    enclave_handle_genrl_msg_t handle_l_rep_msg3_ecall;
    enclave_handle_genrl_msg_t handle_l_exch_data_ecall;
    enclave_handle_init_msg_t handle_r_init_session_ecall;
    //----handle ra rep_msg0
    enclave_init_ra_t init_ra_ecall;
    sgx_ecall_get_ga_trusted_t ra_get_ga_ecall;
    enclave_handle_ra_rep_msg0_t handle_r_rep_msg0_ecall;
    //----handle ra send_msg2
    enclave_get_ra_context_t get_ra_context_ecall;
    sgx_ecall_proc_msg2_trusted_t ra_proc_msg2_ecall;
    sgx_ecall_get_msg3_trusted_t ra_get_msg3_ecall;
    enclave_handle_genrl_msg_t handle_r_send_msg2_ecall;
    //----other ra handlers
    enclave_handle_genrl_msg_t handle_r_send_result_ecall;
    wo_enclave_handle_genrl_msg_t handle_r_exch_data_ecall;
} agnt_handler_t;

extern agnt_handler_t g_handlers[AGNT_NUM];

void init_agent_handlers();

#endif
