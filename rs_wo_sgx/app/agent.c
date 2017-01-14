#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/epoll.h>
#include <mqueue.h>
#include <errno.h>
#include <string.h>
#include "app.h"
#include "epoll_utils.h"
#include "agent.h"
#include "agent_ecall_funcs.h"
#include "msg_buffer.h"
#include "const.h"
#include "error_codes.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "datatypes.h"
#include "dh_session_protocol.h"
#include "sgx_tcrypto.h"
#include "time_utils.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

typedef struct {
    uint32_t id;
    ds_t *p_ds;
} agnt_read_closure_t;

static mqd_t g_agnt_rn_sender_mqds[AGNT_NUM];
static mqd_t g_agnt_ln_sender_mqds[AGNT_NUM];

static sgx_enclave_id_t g_agnt_enclave_ids[AGNT_NUM];

rib_t g_rib[AGNT_NUM] = {[0 ... AGNT_NUM-1] = {0, NULL}};
dh_session_t g_l_session_info[AGNT_NUM][AGNT_NUM];    // [src][dst]
sgx_aes_gcm_128bit_key_t g_r_session_key[AS_NUM];
uint32_t g_r_session_info[AS_NUM] = {[0 ... AGNT_NUM-1] = 0};

uint32_t handle_l_exch_data(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t call_status = SUCCESS, ret_status = SUCCESS;
    bgp_message_t *p_msg = NULL;
    exch_route_t *p_exch_route = NULL;
    route_t *p_route = NULL;
    route_t *p_potential_best_route = NULL;
    exch_secure_message_t *p_l_exch_sec_msg = msg;
    exch_secure_message_t *p_r_exch_sec_msg = NULL;
    int decrypted_data_length = msg_size - sizeof(exch_secure_message_t);
    int send_to_as = 0;
    int exch_route_size;
    uint8_t *decrypted_data, potential_oprt_type;
    char s_de_func_start[30];
    char s_de_func_end[30];
    sprintf(s_de_func_start, "agent%u decrypt start", dst_id);
    sprintf(s_de_func_end, "agent%u decrypt end", dst_id);

    if (g_l_session_info[dst_id][src_id].status != ACTIVE) {
        return INVALID_SESSION;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }
    if (msg_size <= sizeof(exch_secure_message_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    // the sender should have increased the nonce
    if (*((uint32_t *) p_l_exch_sec_msg->secret.reserved) != g_l_session_info[dst_id][src_id].active.counter + 1) {
        return NOUNCE_ERROR;
    }
    g_l_session_info[dst_id][src_id].active.counter++;

    // decrypt local data
    decrypted_data = (uint8_t *) malloc(decrypted_data_length);
    if (!decrypted_data) {
        return MALLOC_ERROR;
    }
    memset(decrypted_data, 0, decrypted_data_length);
    print_current_time_with_us(s_de_func_start);
    call_status = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_l_session_info[dst_id][src_id].active.AEK,
            p_l_exch_sec_msg->secret.payload,
            decrypted_data_length,
            decrypted_data,
            p_l_exch_sec_msg->secret.reserved,
            sizeof(p_l_exch_sec_msg->secret.reserved),
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t *) &p_l_exch_sec_msg->secret.payload_tag);
    print_current_time_with_us(s_de_func_end);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(decrypted_data);
        return call_status;
    }

    // parse data
    p_exch_route = (exch_route_t *) decrypted_data;
    parse_route_from_channel(&p_route, p_exch_route->route);
    //printf("\n[agent%u] p_route->as_path.length:%u\n", dst_id, p_route->as_path.length);
    if (p_exch_route->oprt_type == ANNOUNCE) {
        // printf("\n[agent%u] receive route ANNOUNCE from agent%u:\n", dst_id, src_id);
        // print_route(p_route);
        send_to_as = add_rib_entry(&g_rib[dst_id], &p_potential_best_route, p_route);
        potential_oprt_type = WITHDRAW;
    } else if (p_exch_route->oprt_type == WITHDRAW) {
        // printf("\n[agent%u] receive route WITHDRAW from agent%u:\n", dst_id, src_id);
        // print_route(p_route);
        send_to_as = del_rib_entry(&g_rib[dst_id], &p_potential_best_route, p_route);
        potential_oprt_type = ANNOUNCE;
    }

    // printf("[agent%u] Current rib:\n", dst_id);
    // print_rib(&g_rib[dst_id]);

    // we donot need to send data
    if (!send_to_as) {
        SAFE_FREE(decrypted_data);
        return SGX_SUCCESS;
    }
    if (g_r_session_info[dst_id] != R_WAIT_DATA) {
        SAFE_FREE(decrypted_data);
        return INVALID_SESSION;
    }

    // encrypt data with remote key and send data to rs
    // first deal with the original data from rs
    p_msg = malloc(HEADER_LEN + msg_size);
    if (!p_msg) {
        SAFE_FREE(decrypted_data);
        return MALLOC_ERROR;
    }
    p_msg->msg_len = HEADER_LEN + msg_size;
    p_msg->msg_type = R_EXCH_DATA;
    p_msg->src_id = dst_id;
    p_msg->dst_id = dst_id;
    p_r_exch_sec_msg = (exch_secure_message_t *) p_msg->msg;
    p_r_exch_sec_msg->secret.payload_size = decrypted_data_length;
    // TODO add nounce to iv
    uint8_t aes_gcm_iv[12] = {0};
    call_status = sgx_rijndael128GCM_encrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_r_session_key[dst_id],
            decrypted_data,
            decrypted_data_length,
            p_r_exch_sec_msg->secret.payload,
            aes_gcm_iv,
            12,
            NULL,
            0,
            &p_r_exch_sec_msg->secret.payload_tag);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(decrypted_data);
        SAFE_FREE(p_msg);
        return SGX_ERROR_UNEXPECTED;
    }
    SAFE_FREE(decrypted_data);

    // printf("\n[agent%u] send the new route back to as\n", dst_id);
    call_status = agnt_send_message_ocall(dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_RN);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    if (!p_potential_best_route) {
        return SGX_SUCCESS;
    }

    // then, deal with new(for del) or old(for add) best route
    p_exch_route = NULL;
    generate_exch_route(&p_exch_route, &exch_route_size, p_potential_best_route, NULL, PEER, potential_oprt_type);
    p_msg = (bgp_message_t *) malloc(HEADER_LEN + sizeof(exch_secure_message_t) + exch_route_size);
    if (!p_msg) {
        return MALLOC_ERROR;
    }
    p_msg->msg_len = HEADER_LEN + sizeof(exch_secure_message_t) + exch_route_size;
    p_msg->msg_type = R_EXCH_DATA;
    p_msg->src_id = dst_id;
    p_msg->dst_id = dst_id;
    p_r_exch_sec_msg = (exch_secure_message_t *) p_msg->msg;
    p_r_exch_sec_msg->secret.payload_size = exch_route_size;
    call_status = sgx_rijndael128GCM_encrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_r_session_key[dst_id],
            (const uint8_t *) p_exch_route,
            exch_route_size,
            p_r_exch_sec_msg->secret.payload,
            aes_gcm_iv,
            12,
            NULL,
            0,
            &p_r_exch_sec_msg->secret.payload_tag);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(p_msg);
        return SGX_ERROR_UNEXPECTED;
    }

    // printf("\n[agent%u] send the potential route back to as\n", dst_id);
    // print_route(p_potential_best_route);
    call_status = agnt_send_message_ocall(dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_RN);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    return SUCCESS;
}

uint32_t handle_r_exch_data_core(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size, export_policy_t *p_export_policies)
{
    uint32_t call_status, ret_status, i, j, k;
    bgp_message_t *p_msg;
    exch_secure_message_t *p_r_exch_sec_msg = msg;
    exch_secure_message_t *p_l_exch_sec_msg;
    int decrypted_data_length = msg_size - sizeof(exch_secure_message_t);
    uint8_t *decrypted_data;
    exch_route_t *p_exch_route;
    char s_en_func_start[30];
    char s_en_func_end[30];
    sprintf(s_en_func_start, "agent%u encrypt start", dst_id);
    sprintf(s_en_func_end, "agent%u encrypt end", dst_id);

    if (g_r_session_info[src_id] != R_WAIT_DATA) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }
    if (msg_size <= sizeof(exch_secure_message_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    // decrypted remote data
    decrypted_data = (uint8_t *) malloc(decrypted_data_length);
    if (!decrypted_data) {
        return MALLOC_ERROR;
    }
    memset(decrypted_data, 0, decrypted_data_length);
    // TODO add nounce to iv
    uint8_t aes_gcm_iv[12] = {0};
    call_status = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_r_session_key[dst_id],
            p_r_exch_sec_msg->secret.payload,
            decrypted_data_length,
            decrypted_data,
            aes_gcm_iv,
            12,
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t *) p_r_exch_sec_msg->secret.payload_tag);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(decrypted_data);
        return SGX_ERROR_UNEXPECTED;
    }

    p_exch_route = (exch_route_t *) decrypted_data;

    // encrypt data with local key and send data to other agents
    p_msg = (bgp_message_t *) malloc(HEADER_LEN + msg_size);
    if (!p_msg) {
        SAFE_FREE(decrypted_data);
        return MALLOC_ERROR;
    }
    p_msg->msg_len = HEADER_LEN + msg_size;
    p_msg->msg_type = L_EXCH_DATA;
    p_msg->src_id = dst_id;
    p_l_exch_sec_msg = (exch_secure_message_t *) p_msg->msg;
    p_l_exch_sec_msg->secret.payload_size = decrypted_data_length;
    for (i = 0; i < AGNT_NUM; i++) {
        if (!p_export_policies[p_exch_route->export_policy_class][i] || i == dst_id) {
            continue;
        }
        p_msg->dst_id = i;
        //Use the session nonce as the payload IV, increase nonce before copy
        g_l_session_info[dst_id][i].active.counter++;
        memcpy(p_l_exch_sec_msg->secret.reserved, &g_l_session_info[dst_id][i].active.counter, sizeof(g_l_session_info[dst_id][i].active.counter));
        print_current_time_with_us(s_en_func_start);
        call_status = sgx_rijndael128GCM_encrypt(
                (const sgx_aes_gcm_128bit_key_t *) &g_l_session_info[dst_id][i].active.AEK,
                decrypted_data,
                decrypted_data_length,
                p_l_exch_sec_msg->secret.payload,
                p_l_exch_sec_msg->secret.reserved,
                sizeof(p_l_exch_sec_msg->secret.reserved),
                NULL,
                0,
                &p_l_exch_sec_msg->secret.payload_tag);
        print_current_time_with_us(s_en_func_end);
        if (call_status != SGX_SUCCESS) {
            SAFE_FREE(decrypted_data);
            SAFE_FREE(p_msg);
            return SGX_ERROR_UNEXPECTED;
        }

        call_status = agnt_send_message_ocall(dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_LN);
        if (call_status != SGX_SUCCESS) {
            return call_status;
        }
    }

    return SUCCESS;
}

static void agnt_process_message(uint32_t agnt_id, void *msg, size_t msg_size)
{
    uint32_t ret_status = SUCCESS;
    sgx_status_t call_status = SGX_SUCCESS;
    int payload_size = msg_size - HEADER_LEN;
    bgp_message_t *bgp_msg = msg;
    sgx_ra_context_t context;
    sgx_ra_msg1_t *p_ra_msg1 = NULL;
    sgx_ra_msg3_t *p_ra_msg3 = NULL;
    uint32_t ra_msg3_size;
    char *s_func_start = "receive R_EXCH_DATA";
    char *s_func_end = "finish R_EXCH_DATA";

    // handle different request message types
    // invoke ecall, if there are some msgs to be sent
    // send_message_ocall will be invoked
    switch (bgp_msg->msg_type) {
        case L_REQ_SESSION:
            // fprintf(stdout, "\n[agent%d] received L_REQ_SESSION msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_l_req_session_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] L_REQ_SESSION processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] L_REQ_SESSION processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case L_REP_MSG1:
            // fprintf(stdout, "\n[agent%d] received L_REP_MSG1 msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_l_rep_msg1_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] L_REP_MSG1 processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] L_REP_MSG1 processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case L_EXCH_REPORT:
            // fprintf(stdout, "\n[agent%d] received L_EXCH_REPORT msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_l_exch_report_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            if (ret_status == SUCCESS) {
                fprintf(stdout, "\n[agent%d] Local attestation succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                fprintf(stdout, "\n[agent%d] Local attestation failed at L_EXCH_REPORT, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case L_REP_MSG3:
            // fprintf(stdout, "\n[agent%d] received L_REP_MSG3 msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_l_rep_msg3_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            if (ret_status == SUCCESS) {
                fprintf(stdout, "\n[agent%d] Local attestation succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                fprintf(stdout, "\n[agent%d] Local attestation failed at L_REP_MSG3, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case L_EXCH_DATA:
            // fprintf(stdout, "\n[agent%d] received L_EXCH_DATA msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            ret_status = handle_l_exch_data(
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] L_EXCH_DATA processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] L_EXCH_DATA processing failed, errno:%u, peer%d<->me%d\n", agnt_id, ret_status, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case R_INIT_SESSION:
            // fprintf(stdout, "\n[agent%d] received R_INIT_SESSION msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_r_init_session_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_INIT_SESSION processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_INIT_SESSION processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case R_REP_MSG0:
            // fprintf(stdout, "\n[agent%d] received R_REP_MSG0 msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].init_ra_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, false, &context);
            p_ra_msg1 = malloc(sizeof *p_ra_msg1);
            call_status = sgx_ra_get_msg1(
                    context, g_agnt_enclave_ids[agnt_id],
                    g_handlers[agnt_id].ra_get_ga_ecall, p_ra_msg1);
            call_status = g_handlers[agnt_id].handle_r_rep_msg0_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id, p_ra_msg1);
            SAFE_FREE(p_ra_msg1);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_REP_MSG0 processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_REP_MSG0 processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case R_SEND_MSG2:
            // fprintf(stdout, "\n[agent%d] received R_SEND_MSG2 msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            ret_status = g_handlers[agnt_id].get_ra_context_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, &context);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 1 processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 1 processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            ret_status = sgx_ra_proc_msg2(
                    context, g_agnt_enclave_ids[agnt_id],
                    g_handlers[agnt_id].ra_proc_msg2_ecall,
                    g_handlers[agnt_id].ra_get_msg3_ecall,
                    (const sgx_ra_msg2_t *) bgp_msg->msg,
                    payload_size, &p_ra_msg3, &ra_msg3_size);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 2 processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 2 processing failed, errno:%d, peer%d<->me%d\n", agnt_id, ret_status, bgp_msg->src_id, bgp_msg->dst_id);
            }
            call_status = g_handlers[agnt_id].handle_r_send_msg2_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) p_ra_msg3, ra_msg3_size);
            SAFE_FREE(p_ra_msg3);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 3 processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_SEND_MSG2 stage 3 processing failed, errno:%u, peer%d<->me%d\n", agnt_id, ret_status, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case R_SEND_RESULT:
            // fprintf(stdout, "\n[agent%d] received R_SEND_RESULT msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            call_status = g_handlers[agnt_id].handle_r_send_result_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            if (ret_status == SUCCESS) {
                fprintf(stdout, "\n[agent%d] Remote attestation succeeded at R_SEND_RESULT, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                fprintf(stdout, "\n[agent%d] Remote attestation failed at R_SEND_RESULT, errno:%u, peer%d<->me%d\n", agnt_id, ret_status, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        case R_EXCH_DATA:
            // fprintf(stdout, "\n[agent%d] received R_EXCH_DATA msg, src%d->dst%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            print_current_time_with_us(s_func_start);
            call_status = g_handlers[agnt_id].handle_r_exch_data_ecall(
                    bgp_msg->src_id, bgp_msg->dst_id,
                    (void *) bgp_msg->msg, payload_size);
            print_current_time_with_us(s_func_end);
            if (ret_status == SUCCESS) {
                // fprintf(stdout, "\n[agent%d] R_EXCH_DATA processing succeeded, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            } else {
                // fprintf(stdout, "\n[agent%d] R_EXCH_DATA processing failed, peer%d<->me%d\n", agnt_id, bgp_msg->src_id, bgp_msg->dst_id);
            }
            break;
        default:
            return;
    }

    /*
    if (call_status != SGX_SUCCESS) {
        // fprintf(stdout, "id:%u ecall failed [%s]\n", agnt_id, __FUNCTION__);
    } else if (ret_status != SUCCESS) {
        // fprintf(stdout, "id:%u handle_msg failed [%s]\n", agnt_id, __FUNCTION__);
    }
    */
}

static void agnt_handle_read_event(epoll_event_handler_t *h, uint32_t events)
{
    int bytes, msg_size;
    char buffer[BUFFER_SIZE], *msg;
    uint32_t ret_status;
    sgx_status_t call_status;
    agnt_read_closure_t *closure = h->closure;

    //// fprintf(stdout, "\n[agent%u] read event from mqd:%d [%s]\n", closure->id, h->fd, __FUNCTION__);

    // receive msgs from mqueue
    while (1) {
        bytes = mq_receive(h->fd, buffer, BUFFER_SIZE, NULL);

        // we have read all messages, the mqueue is empty
        if (bytes == -1 && errno == EAGAIN) {
            break;
        }

        // mqueue error
        if (bytes == -1) {
            // fprintf(stdout, "\n[agent%u] mq_receive failed, err: %s [%s]\n", closure->id, strerror(errno), __FUNCTION__);
            return;
        }

        //// fprintf(stdout, "\n[agent%u] mq_receive %d bytes [%s]\n", closure->id, bytes, __FUNCTION__);

        // add received buffer to local flow buffer to extract messages
        append_ds(closure->p_ds, buffer, bytes);
    }

    // processing parsed msgs
    while (1) {
        get_msg(closure->p_ds, &msg, &msg_size);
        if (msg == NULL || msg_size == 0) {
            // we have processed all available msgs
            break;
        }

        agnt_process_message(closure->id, msg, msg_size);
    }
}

static void agnt_register_read_event_handler(int efd, mqd_t mqd, uint32_t id)
{
    epoll_event_handler_t *handler = malloc(sizeof *handler);
    if (!handler) {
        // fprintf(stdout, "\n[agent%u] malloc failed [%s]\n", id, __FUNCTION__);
        return;
    }
    handler->efd = efd;
    handler->fd = mqd;
    handler->handle = agnt_handle_read_event;

    agnt_read_closure_t *closure = malloc(sizeof *closure);
    closure->p_ds = NULL;
    if (!closure) {
        // fprintf(stdout, "\n[agent%u] malloc failed [%s]\n", id, __FUNCTION__);
        return;
    }
    closure->id = id;
    init_ds(&closure->p_ds);
    if (!closure->p_ds) {
        free(closure);
        // fprintf(stdout, "\n[agent%u] malloc failed [%s]\n", id, __FUNCTION__);
        return;
    }
    handler->closure = closure;

    epoll_ctl_handler(handler, EPOLL_CTL_ADD, EPOLLIN | EPOLLET | EPOLLRDHUP);
}

static void agnt_start_session_handshake(uint32_t id)
{
    uint32_t ret_status, i;
    sgx_status_t call_status;

    for (i = 0; i < id; i++) {
        // fprintf(stdout, "\n[agent%d] start to conenct to agent%d [%s]\n", id, i, __FUNCTION__);
        call_status = g_handlers[id].handle_l_init_session_ecall(
                g_agnt_enclave_ids[id], &ret_status, i, id);
        if (call_status != SGX_SUCCESS) {
            // fprintf(stdout, "id:%d ecall failed [%s]\n", id, __FUNCTION__);
        } else if (ret_status != SUCCESS) {
            // fprintf(stdout, "id:%d process_message failed [%s]\n", id, __FUNCTION__);
        }
    }
}

static void agnt_init(int efd, uint32_t agnt_id)
{
    char enclave_path[STR_LEN];
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;
    mqd_t ln_to_me_mq, me_to_ln_mq, rn_to_me_mq, me_to_rn_mq;

    // create enclave
    sprintf(enclave_path, "libenclave%d.so", agnt_id);
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &g_agnt_enclave_ids[agnt_id], NULL);
    // wait for enclave output
    sleep(1);
    if (ret != SGX_SUCCESS) {
        // fprintf(stdout, "sgx_create_enclave failed id:%d [%s]\n", agnt_id, __FUNCTION__);
        abort();
    } else {
        // fprintf(stdout, "\nenclave%d - id %lu\n", agnt_id, g_agnt_enclave_ids[agnt_id]);
    }

    // mqueue
    rn_to_me_mq = mq_open(g_rn_to_agnt_mq_name[agnt_id], O_RDONLY | O_NONBLOCK);
    ln_to_me_mq = mq_open(g_ln_to_agnt_mq_name[agnt_id], O_RDONLY | O_NONBLOCK);
    g_agnt_rn_sender_mqds[agnt_id] = mq_open(g_agnt_to_rn_mq_name[agnt_id], O_WRONLY | O_NONBLOCK);
    g_agnt_ln_sender_mqds[agnt_id] = mq_open(g_agnt_to_ln_mq_name[agnt_id], O_WRONLY | O_NONBLOCK);

    agnt_register_read_event_handler(efd, rn_to_me_mq, agnt_id);
    agnt_register_read_event_handler(efd, ln_to_me_mq, agnt_id);

    // enclave local attestation
    agnt_start_session_handshake(agnt_id);
}

/* OCall functions */
void ocall_update_l_session(dh_session_t *session, uint32_t src_id, uint32_t dst_id)
{
    g_l_session_info[src_id][dst_id].status = ACTIVE;
    memcpy(&g_l_session_info[src_id][dst_id].active.AEK, &session->active.AEK, sizeof(sgx_aes_gcm_128bit_key_t));
    g_l_session_info[src_id][dst_id].active.counter = 0;
}

/* OCall functions */
void ocall_update_r_session(sgx_ec_key_128bit_t *p_key, uint32_t as_id)
{
    memcpy(&g_r_session_key[as_id], p_key, sizeof(sgx_ec_key_128bit_t));
    g_r_session_info[as_id] = R_WAIT_DATA;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

uint32_t agnt_send_message_ocall(uint32_t src_id, void *resp_message, size_t resp_message_size, int channel)
{
    int ret, diff, bytes, offset = 0;
    //// fprintf(stdout, "\n[agent%d] prepares to send msg, msg_size:%d [%s]\n", src_id, resp_message_size, __FUNCTION__);
    mqd_t dest_mqd = (channel == AGNT_TO_LN) ? g_agnt_ln_sender_mqds[src_id] : g_agnt_rn_sender_mqds[src_id];
    char *buffer = resp_message;

    // send the msg
    while (resp_message_size != offset) {
        diff = resp_message_size - offset;
        bytes = (diff <= MAX_MSG_SIZE) ? diff : MAX_MSG_SIZE;
        ret = mq_send(dest_mqd, buffer + offset, bytes, 0);
        if (ret == -1) {
            // fprintf(stdout, "\n[agent%d] write mqueue failed, err: %s [%s]\n", src_id, strerror(errno), __FUNCTION__);
            // TODO handle error
            return SESSION_SEND_ERROR;
        } else {
            //// fprintf(stdout, "\n[agent%d] write mqueue %d bytes successfully [%s]\n", src_id, bytes, __FUNCTION__);
            offset += bytes;
        }
    }

    return SUCCESS;
}

void *agent(void *threadid)
{
    int efd;
    uint32_t agnt_id = *((uint32_t *) threadid);
    free(threadid);

    efd = epoll_init();
    agnt_init(efd, agnt_id);
    epoll_run(efd);
    sgx_destroy_enclave(g_agnt_enclave_ids[agnt_id]);
}
