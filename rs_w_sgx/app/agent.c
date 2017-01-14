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

static void agnt_process_message(uint32_t agnt_id, void *msg, size_t msg_size)
{
    uint32_t ret_status;
    sgx_status_t call_status;
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
            call_status = g_handlers[agnt_id].handle_l_exch_data_ecall(
                    g_agnt_enclave_ids[agnt_id], &ret_status,
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
                    g_agnt_enclave_ids[agnt_id], &ret_status,
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
