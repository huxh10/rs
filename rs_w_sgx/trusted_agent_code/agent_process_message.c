#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sys/limits.h"

//la
#include "sgx_dh.h"

// ra
#include "sgx_tkey_exchange.h"
#include "sgx_ecp_types.h"
#include "isv_enclave.h"
#include "remote_attestation_result.h"
#include "stdbool.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "assert.h"
#include "const.h"
#include "error_codes.h"
#include "bgp.h"
#include "datatypes.h"
#include "dh_session_protocol.h"

#define MAX_SESSION_COUNT 16

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

//Session Tracker to generate session ids
typedef struct _session_id_tracker_t {
    uint32_t session_id;
} session_id_tracker_t;

// array of open session ids
session_id_tracker_t *g_session_id_tracker[MAX_SESSION_COUNT];

dh_session_t *g_p_l_session_info[AGNT_NUM];
ra_dh_session_t *g_p_r_session_info[AS_NUM];

rib_t g_rib = {0, NULL};

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

// returns a new sessionID for the source destination session
uint32_t generate_session_id(uint32_t *session_id)
{
    uint32_t i;
    uint32_t status = SUCCESS;

    if (!session_id) {
        return INPUT_NULL_POINTER;
    }
    //if the session structure is untintialized, set that as the next session ID
    for (i = 0; i < MAX_SESSION_COUNT; i++) {
        if (g_session_id_tracker[i] == NULL) {
            *session_id = i;

            // allocate memory for the session id tracker
            g_session_id_tracker[i] = malloc(sizeof(session_id_tracker_t));
            if (!g_session_id_tracker[i]) {
                return MALLOC_ERROR;
            }
            g_session_id_tracker[i]->session_id = i;

            return status;
        }
    }
    status = NO_AVAILABLE_SESSION_ERROR;
    return status;
}

//Function that is used to verify the trust of the other enclave
//Each enclave can have its own way verifying the peer enclave identity
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if (!peer_enclave_identity)
    {
        return INPUT_NULL_POINTER;
    }
    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
    {
        return ENCLAVE_TRUST_ERROR;
    }
    else
    {
        return SUCCESS;
    }
}

uint32_t handle_l_init_session(uint32_t src_id, uint32_t dst_id)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_ocall_msg;
    g_p_l_session_info[src_id] = malloc(sizeof(dh_session_t));
    if (!g_p_l_session_info[src_id]) {
        return MALLOC_ERROR;
    }
    g_p_l_session_info[src_id]->status = IN_PROGRESS;

    // intialize the session as a session initiator
    call_status = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &g_p_l_session_info[src_id]->in_progress.dh_session);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    p_ocall_msg = malloc(sizeof(bgp_message_t));
    if (!p_ocall_msg) {
        return MALLOC_ERROR;
    }
    p_ocall_msg->msg_len = HEADER_LEN;
    p_ocall_msg->msg_type = L_REQ_SESSION;
    p_ocall_msg->src_id = dst_id;
    p_ocall_msg->dst_id = src_id;

    // deliver msg to untrusted env
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_ocall_msg, p_ocall_msg->msg_len, AGNT_TO_LN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS)
            return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t handle_l_req_session(uint32_t src_id, uint32_t dst_id)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_ocall_msg;
    l_rep_msg1_t *p_rep_msg1;

    p_ocall_msg = malloc(sizeof(l_rep_msg1_t) + HEADER_LEN);
    if (!p_ocall_msg) {
        return MALLOC_ERROR;
    }
    p_ocall_msg->msg_len = sizeof(l_rep_msg1_t) + HEADER_LEN;
    p_ocall_msg->msg_type = L_REP_MSG1;
    p_ocall_msg->src_id = dst_id;
    p_ocall_msg->dst_id = src_id;
    p_rep_msg1 = (l_rep_msg1_t *) p_ocall_msg->msg;

    g_p_l_session_info[src_id] = malloc(sizeof(dh_session_t));
    if (!g_p_l_session_info[src_id]) {
        return MALLOC_ERROR;
    }

    // intialize the session as a session responder
    call_status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &g_p_l_session_info[src_id]->in_progress.dh_session);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    // get a new SessionID
    if ((call_status = generate_session_id(&p_rep_msg1->session_id)) != SUCCESS) {
        return call_status; //no more sessions available
    }
    g_p_l_session_info[src_id]->status = IN_PROGRESS;

    // generate Message1 that will be returned to Source Enclave
    call_status = sgx_dh_responder_gen_msg1(&p_rep_msg1->dh_msg1, &g_p_l_session_info[src_id]->in_progress.dh_session);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(g_session_id_tracker[p_rep_msg1->session_id]);
        return call_status;
    }

    // deliver response msg to untrusted env
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_ocall_msg, p_ocall_msg->msg_len, AGNT_TO_LN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t handle_l_rep_msg1(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t call_status, ret_status;
    l_rep_msg1_t *p_rep_msg1 = (l_rep_msg1_t *) msg;

    assert(msg_size == sizeof(l_rep_msg1_t));
    if (!msg) {
        return INPUT_NULL_POINTER;
    }

    l_rep_msg2_t *p_rep_msg2;
    bgp_message_t *p_ocall_msg = malloc(sizeof(l_rep_msg2_t) + HEADER_LEN);
    if (!p_ocall_msg) {
        return MALLOC_ERROR;
    }
    p_ocall_msg->msg_len = sizeof(l_rep_msg2_t) + HEADER_LEN;
    p_ocall_msg->msg_type = L_EXCH_REPORT;
    p_ocall_msg->src_id = dst_id;
    p_ocall_msg->dst_id = src_id;
    p_rep_msg2 = (l_rep_msg2_t *) p_ocall_msg->msg;

    if (g_p_l_session_info[src_id]->status != IN_PROGRESS) {
        return INVALID_SESSION;
    }

    // retreive the mession_id from the other side
    g_p_l_session_info[src_id]->session_id = p_rep_msg1->session_id;

    // process the msg1 received from desination enclave and generate msg2
    // dh_session states are updated inside the proc function
    call_status = sgx_dh_initiator_proc_msg1(&p_rep_msg1->dh_msg1, &p_rep_msg2->dh_msg2, &g_p_l_session_info[src_id]->in_progress.dh_session);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    // assemble the massage that should be sent to desination enclave, deliver it
    p_rep_msg2->session_id = g_p_l_session_info[src_id]->session_id;
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_ocall_msg, p_ocall_msg->msg_len, AGNT_TO_LN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t handle_l_exch_report(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t call_status, ret_status;
    l_rep_msg2_t *p_rep_msg2 = (l_rep_msg2_t *) msg;
    sgx_key_128bit_t dh_aek;   // Session key
    sgx_dh_session_enclave_identity_t initiator_identity;

    assert(msg_size == sizeof(l_rep_msg2_t));
    if (!msg) {
        return INPUT_NULL_POINTER;
    }

    l_rep_msg3_t *p_rep_msg3;
    bgp_message_t *p_ocall_msg = malloc(sizeof(l_rep_msg3_t) + HEADER_LEN);
    if (!p_ocall_msg) {
        return MALLOC_ERROR;
    }
    p_ocall_msg->msg_len = sizeof(l_rep_msg3_t) + HEADER_LEN;
    p_ocall_msg->msg_type = L_REP_MSG3;
    p_ocall_msg->src_id = dst_id;
    p_ocall_msg->dst_id = src_id;
    p_rep_msg3 = (l_rep_msg3_t *) p_ocall_msg->msg;

    if (g_p_l_session_info[src_id]->status != IN_PROGRESS) {
        return INVALID_SESSION;
    }

    p_rep_msg3->dh_msg3.msg3_body.additional_prop_length = 0;
    // process msg2 from source enclave and get msg3
    call_status = sgx_dh_responder_proc_msg2(&p_rep_msg2->dh_msg2, &p_rep_msg3->dh_msg3, &g_p_l_session_info[src_id]->in_progress.dh_session, &dh_aek, &initiator_identity);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }

    // verify source enclave's trust
    if (verify_peer_enclave_trust(&initiator_identity) != SUCCESS) {
        return INVALID_SESSION;
    }

    // deliver response msg to untrusted env
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_ocall_msg, p_ocall_msg->msg_len, AGNT_TO_LN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    // session established, update session info, change to active mode
    g_p_l_session_info[src_id]->session_id = p_rep_msg2->session_id;
    g_p_l_session_info[src_id]->status = ACTIVE;
    g_p_l_session_info[src_id]->active.counter = 0;
    memcpy(&g_p_l_session_info[src_id]->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));

    return SUCCESS;
}

uint32_t handle_l_rep_msg3(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t status;
    l_rep_msg3_t *p_rep_msg3 = (l_rep_msg3_t *) msg;
    sgx_key_128bit_t dh_aek;    // Session Key
    sgx_dh_session_enclave_identity_t responder_identity;

    assert(msg_size == sizeof(l_rep_msg3_t));
    if (!msg) {
        return INPUT_NULL_POINTER;
    }

    if (g_p_l_session_info[src_id]->status != IN_PROGRESS) {
        return INVALID_SESSION;
    }

    // process Message 3 obtained from the destination enclave
    // dh_session states are updated inside the proc function
    status = sgx_dh_initiator_proc_msg3(&p_rep_msg3->dh_msg3, &g_p_l_session_info[src_id]->in_progress.dh_session, &dh_aek, &responder_identity);
    if (status != SGX_SUCCESS) {
        return status;
    }

    // verify the identity of the destination enclave
    if (verify_peer_enclave_trust(&responder_identity) != SUCCESS) {
        return INVALID_SESSION;
    }

    // session established, update session info, change to active mode
    memcpy(&g_p_l_session_info[src_id]->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    g_p_l_session_info[src_id]->active.counter = 0;
    g_p_l_session_info[src_id]->status = ACTIVE;
    memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));

    return SUCCESS;
}

uint32_t handle_l_exch_data(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_msg = NULL;
    exch_route_t *p_exch_route = NULL;
    route_t *p_route = NULL;
    route_t *p_potential_best_route = NULL;
    exch_secure_message_t *p_l_exch_sec_msg = msg;
    exch_secure_message_t *p_r_exch_sec_msg = NULL;
    sgx_ec_key_128bit_t sk_key;
    int decrypted_data_length = msg_size - sizeof(exch_secure_message_t);
    int send_to_as = 0;
    int exch_route_size;
    uint8_t *decrypted_data, potential_oprt_type;

    if (g_p_l_session_info[src_id]->status != ACTIVE) {
        return INVALID_SESSION;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }
    if (msg_size <= sizeof(exch_secure_message_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    // the sender should have increased the nonce
    if (*((uint32_t *) p_l_exch_sec_msg->secret.reserved) != g_p_l_session_info[src_id]->active.counter + 1) {
        return NOUNCE_ERROR;
    }
    g_p_l_session_info[src_id]->active.counter++;

    // decrypt local data
    decrypted_data = (uint8_t *) malloc(decrypted_data_length);
    if (!decrypted_data) {
        return MALLOC_ERROR;
    }
    memset(decrypted_data, 0, decrypted_data_length);
    call_status = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *) &g_p_l_session_info[src_id]->active.AEK,
            p_l_exch_sec_msg->secret.payload,
            decrypted_data_length,
            decrypted_data,
            p_l_exch_sec_msg->secret.reserved,
            sizeof(p_l_exch_sec_msg->secret.reserved),
            NULL,
            0,
            (const sgx_aes_gcm_128bit_tag_t *) &p_l_exch_sec_msg->secret.payload_tag);
    if (call_status != SGX_SUCCESS) {
        SAFE_FREE(decrypted_data);
        return SGX_ERROR_UNEXPECTED;
    }

    // parse data
    p_exch_route = (exch_route_t *) decrypted_data;
    parse_route_from_channel(&p_route, p_exch_route->route);
    //printf("\n[agent%u] p_route->as_path.length:%u\n", dst_id, p_route->as_path.length);
    if (p_exch_route->oprt_type == ANNOUNCE) {
        // printf("\n[agent%u] receive route ANNOUNCE from agent%u:\n", dst_id, src_id);
        // print_route(p_route);
        send_to_as = add_rib_entry(&g_rib, &p_potential_best_route, p_route);
        potential_oprt_type = WITHDRAW;
    } else if (p_exch_route->oprt_type == WITHDRAW) {
        // printf("\n[agent%u] receive route WITHDRAW from agent%u:\n", dst_id, src_id);
        // print_route(p_route);
        send_to_as = del_rib_entry(&g_rib, &p_potential_best_route, p_route);
        potential_oprt_type = ANNOUNCE;
    }

    // printf("[agent%u] Current rib:\n", dst_id);
    // print_rib(&g_rib);

    // we donot need to send data
    if (!send_to_as) {
        SAFE_FREE(decrypted_data);
        return SGX_SUCCESS;
    }
    if (!g_p_r_session_info[dst_id] || g_p_r_session_info[dst_id]->status != R_WAIT_DATA) {
        SAFE_FREE(decrypted_data);
        return INVALID_SESSION;
    }

    // encrypt data with remote key and send data to rs
    // first deal with the original data from rs
    call_status = sgx_ra_get_keys(g_p_r_session_info[dst_id]->context, SGX_RA_KEY_SK, &sk_key);
    if (call_status != SGX_SUCCESS) {
        return INVALID_PARAMETER_ERROR;
    }
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
            (const sgx_aes_gcm_128bit_key_t *) &sk_key,
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
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_RN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
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
            (const sgx_aes_gcm_128bit_key_t *) &sk_key,
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
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_RN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t handle_r_init_session(uint32_t src_id, uint32_t dst_id)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_rep_msg;

    p_rep_msg = (bgp_message_t *) malloc(HEADER_LEN + sizeof(r_msg0_t));
    if (!p_rep_msg) {
        return MALLOC_ERROR;
    }
    p_rep_msg->msg_len = HEADER_LEN + sizeof(r_msg0_t);
    p_rep_msg->msg_type = R_SEND_MSG0;
    p_rep_msg->src_id = dst_id;
    p_rep_msg->dst_id = src_id;
    ((r_msg0_t *) p_rep_msg->msg)->extended_epid_group_id = EXTENDED_EPID_GROUP_ID;

    g_p_r_session_info[src_id] = malloc(sizeof(ra_dh_session_t));
    if (!g_p_r_session_info[src_id]) {
        free(p_rep_msg);
        return MALLOC_ERROR;
    }
    g_p_r_session_info[src_id]->status = R_WAIT_M0_RESP;
    g_p_r_session_info[src_id]->context = INT_MAX;

    // deliver msg to untrusted env
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_rep_msg, p_rep_msg->msg_len, AGNT_TO_RN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t init_ra(uint32_t src_id, int b_pse, sgx_ra_context_t *p_context)
{
    uint32_t call_status;

    if (g_p_r_session_info[src_id]->status != R_WAIT_M0_RESP) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    // invoke the init_ra function from isv_enclave.cpp
    call_status = enclave_init_ra(b_pse, &g_p_r_session_info[src_id]->context);
    if (call_status != SGX_SUCCESS) {
        return call_status;
    }
    p_context = &g_p_r_session_info[src_id]->context;
    return SGX_SUCCESS;
}

uint32_t handle_r_rep_msg0(uint32_t src_id, uint32_t dst_id, sgx_ra_msg1_t *p_msg1)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_rep_msg;

    if (g_p_r_session_info[src_id]->status != R_WAIT_M0_RESP) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!p_msg1) {
        return INPUT_NULL_POINTER;
    }

    // essemble msg1 header
    p_rep_msg = (bgp_message_t *) malloc(HEADER_LEN + sizeof(sgx_ra_msg1_t));
    if (!p_rep_msg) {
        return MALLOC_ERROR;
    }
    p_rep_msg->msg_len = HEADER_LEN + sizeof(sgx_ra_msg1_t);
    p_rep_msg->msg_type = R_SEND_MSG1;
    p_rep_msg->src_id = dst_id;
    p_rep_msg->dst_id = src_id;
    memcpy(p_rep_msg->msg, p_msg1, sizeof *p_msg1);

    // The ISV application sends msg1 to the SP to get msg2,
    // msg2 needs to be freed when no longer needed.
    // The ISV decides whether to use linkable or unlinkable signatures.
    g_p_r_session_info[src_id]->status = R_WAIT_M2;
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_rep_msg, p_rep_msg->msg_len, AGNT_TO_RN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) return ret_status;
    } else {
        return call_status;
    }

    return SUCCESS;
}

uint32_t get_ra_context(uint32_t src_id, sgx_ra_context_t *p_context)
{
    if (g_p_r_session_info[src_id]->status != R_WAIT_M2) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    p_context = &g_p_r_session_info[src_id]->context;
    return SGX_SUCCESS;
}

uint32_t handle_r_send_msg2(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t call_status, ret_status;
    bgp_message_t *p_rep_msg;

    if (g_p_r_session_info[src_id]->status != R_WAIT_M2) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }

    p_rep_msg = malloc(msg_size + HEADER_LEN);
    if (!p_rep_msg) {
        call_status = SGX_ERROR_OUT_OF_MEMORY;
        goto CLEANUP;
    }
    p_rep_msg->msg_len = msg_size + HEADER_LEN;
    p_rep_msg->msg_type = R_SEND_MSG3;
    p_rep_msg->src_id = dst_id;
    p_rep_msg->dst_id = src_id;
    memcpy(p_rep_msg->msg, msg, msg_size);

    // send msg3
    // The ISV application sends msg3 to the SP to get the attestation
    // result message, attestation result message needs to be freed when
    // no longer needed. The ISV service provider decides whether to use
    // linkable or unlinkable signatures. The format of the attestation
    // result is up to the service provider. This format is used for
    // demonstration.  Note that the attestation result message makes use
    // of both the MK for the MAC and the SK for the secret. These keys are
    // established from the SIGMA secure channel binding.
    g_p_r_session_info[src_id]->status = R_WAIT_RSLT;
    call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_rep_msg, p_rep_msg->msg_len, AGNT_TO_RN);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SUCCESS) {
            call_status = ret_status;
            goto CLEANUP;
        }
    } else {
        goto CLEANUP;
    }
    return SUCCESS;

CLEANUP:
    if (call_status)
        SAFE_FREE(p_rep_msg);
    return call_status;
}

uint32_t handle_r_send_result(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size)
{
    uint32_t status;
    sample_ra_att_result_msg_t *p_msg_rslt = msg;

    if (g_p_r_session_info[src_id]->status != R_WAIT_RSLT) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }
    if (msg_size <= sizeof(sample_ra_att_result_msg_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    // Check the MAC using MK on the attestation result message.
    // The format of the attestation result message is ISV specific.
    // This is a simple form for demonstration. In a real product,
    // the ISV may want to communicate more information.
    status = verify_att_result_mac(
            g_p_r_session_info[src_id]->context,
            (uint8_t*)&p_msg_rslt->platform_info_blob,
            sizeof(ias_platform_info_blob_t),
            (uint8_t*)&p_msg_rslt->mac,
            sizeof(sgx_mac_t));
    if (status != SGX_SUCCESS) {
        return status;
    }

    bool attestation_passed = true;
    /*
    // Check the attestation result for pass or fail.
    // Whether attestation passes or fails is a decision made by the ISV Server.
    // When the ISV server decides to trust the enclave, then it will return success.
    // When the ISV server decided to not trust the enclave, then it will return failure.
    if (0 != p_att_result_msg_full->status[0]
       || 0 != p_att_result_msg_full->status[1])
    {
        attestation_passed = false;
    }
    */

    // The attestation result message should contain a field for the Platform
    // Info Blob (PIB).  The PIB is returned by attestation server in the attestation report.
    // It is not returned in all cases, but when it is, the ISV app
    // should pass it to the blob analysis API called sgx_report_attestation_status()
    // along with the trust decision from the ISV server.
    // The ISV application will take action based on the update_info.
    // returned in update_info by the API.  
    // This call is stubbed out for the sample.
    // 
    // sgx_update_info_bit_t update_info;
    // ret = sgx_report_attestation_status(
    //     &p_msg_rslt->platform_info_blob,
    //     attestation_passed ? 0 : 1, &update_info);

    // Get the shared secret sent by the server using SK (if attestation
    // passed)
    if (attestation_passed)
    {
        status = put_secret_data(g_p_r_session_info[src_id]->context, p_msg_rslt->secret.payload, p_msg_rslt->secret.payload_size, p_msg_rslt->secret.payload_tag);
        if(status != SGX_SUCCESS) {
            return status;
        }
    }

    //return INVALID_REQUEST_TYPE_ERROR;

    // enter exchange data stage
    g_p_r_session_info[src_id]->status = R_WAIT_DATA;
    return SGX_SUCCESS;
}

uint32_t handle_r_exch_data_core(uint32_t src_id, uint32_t dst_id, void *msg, size_t msg_size, export_policy_t *p_export_policies)
{
    uint32_t call_status, ret_status, i;
    bgp_message_t *p_msg;
    exch_secure_message_t *p_r_exch_sec_msg = msg;
    exch_secure_message_t *p_l_exch_sec_msg;
    sgx_ec_key_128bit_t sk_key;
    int decrypted_data_length = msg_size - sizeof(exch_secure_message_t);
    uint8_t *decrypted_data;
    exch_route_t *p_exch_route;

    if (g_p_r_session_info[src_id]->status != R_WAIT_DATA) {
        return INVALID_REQUEST_TYPE_ERROR;
    }

    if (!msg) {
        return INPUT_NULL_POINTER;
    }
    if (msg_size <= sizeof(exch_secure_message_t)) {
        return INVALID_PARAMETER_ERROR;
    }

    call_status = sgx_ra_get_keys(g_p_r_session_info[src_id]->context, SGX_RA_KEY_SK, &sk_key);
    if (call_status != SGX_SUCCESS) {
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
            (const sgx_aes_gcm_128bit_key_t *) &sk_key,
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
        g_p_l_session_info[i]->active.counter++;
        memcpy(p_l_exch_sec_msg->secret.reserved, &g_p_l_session_info[i]->active.counter, sizeof(g_p_l_session_info[i]->active.counter));
        call_status = sgx_rijndael128GCM_encrypt(
                (const sgx_aes_gcm_128bit_key_t *) &g_p_l_session_info[i]->active.AEK,
                decrypted_data,
                decrypted_data_length,
                p_l_exch_sec_msg->secret.payload,
                p_l_exch_sec_msg->secret.reserved,
                sizeof(p_l_exch_sec_msg->secret.reserved),
                NULL,
                0,
                &p_l_exch_sec_msg->secret.payload_tag);
        if (call_status != SGX_SUCCESS) {
            SAFE_FREE(decrypted_data);
            SAFE_FREE(p_msg);
            return SGX_ERROR_UNEXPECTED;
        }

        call_status = agnt_send_message_ocall(&ret_status, dst_id, (void *) p_msg, p_msg->msg_len, AGNT_TO_LN);
        if (call_status == SGX_SUCCESS) {
            if (ret_status != SUCCESS) return ret_status;
        } else {
            return call_status;
        }
    }

    return SUCCESS;
}
