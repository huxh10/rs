#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "datatypes.h"
#include "error_codes.h"
#include "time_utils.h"
#include "bgp.h"
#include "rs.h"
#include "../enclave/enclave_u.h"
#include "rs_w_sgx.h"

sgx_enclave_id_t g_enclave_id;

sgx_enclave_id_t load_enclave()
{
    char enclave_path[] = "libenclave.so";
    int launch_token_updated;
    sgx_launch_token_t launch_token;
    sgx_enclave_id_t enclave_id;
    uint32_t ret;

    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &enclave_id, NULL);
    if (ret != SGX_SUCCESS) {
        fprintf(IO_STREAM, "sgx_create_enclave failed [%s]\n", __FUNCTION__);
        exit(-1);
    } else {
        fprintf(IO_STREAM, "enclave - id %lu [%s]\n", enclave_id, __FUNCTION__);
        return enclave_id;
    }
}

void init_rs_w_sgx(uint32_t num, as_conf_t *p_as_conf)
{
    uint32_t ret_status, call_status, i;
    g_enclave_id = load_enclave();
    for (i = 0; i < num; i++) {
        call_status = enclave_ecall_load_as_conf(g_enclave_id, &ret_status, i, (void *) p_as_conf[i].import_policy, num * sizeof(uint32_t), (void *) p_as_conf[i].export_policy, num * num * sizeof(uint32_t));
        if (ret_status == SUCCESS) {
            //fprintf(IO_STREAM, "enclave_load_as_conf asn:%u succeeded [%s]\n", i, __FUNCTION__);
        } else {
            //fprintf(IO_STREAM, "enclave_load_as_conf failed, asn:%u, errno:%u [%s]\n", i, ret_status, __FUNCTION__);
            exit(-1);
        }
    }
}

void run_rs_w_sgx(int msg_num, bgp_msg_t **pp_bgp_msgs, int method, int verbose)
{
    int i = 0;
    uint32_t call_status, ret_status;
    uint64_t time_start, time_end;

    for (i = 0; i < msg_num; i++) {
        if (method == GLOBAL_ACCESS) {
            time_start = get_us_time();
            call_status = enclave_ecall_compute_route_by_global_access(g_enclave_id, &ret_status, (void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size);
            time_end = get_us_time();
        } else if (method == MSG_QUEUE) {
            time_start = get_us_time();
            call_status = enclave_ecall_compute_route_by_msg_queue(g_enclave_id, &ret_status, (void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size);
            time_end = get_us_time();
        }
        if (verbose == 0) {
            if (i == 0 || i == 1 || i == 50 || i == 51 || i == 100 || i == 101 || i == 150 || i == 151 || i == 200 || i == 201) {
                printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
            }
        } else if (verbose == 1) {
            if (i % 2 == 0) printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 2) {
            if (i % 2 == 1) printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 3) {
            printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
        } else if (verbose == 4) {
            printf("msg_id:%u time to compute: %lu\n", i, time_end - time_start);
            if (method == GLOBAL_ACCESS) {
                call_status = enclave_ecall_print_rs_simplified_ribs(g_enclave_id, &ret_status);
            } else if (method == MSG_QUEUE) {
                call_status = enclave_ecall_print_rs_ribs(g_enclave_id, &ret_status);
            }
        }
    }
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

uint32_t ocall_update_route(void *msg, size_t msg_size)
{
    //printf("\n");
    //print_current_time_with_us("receive routes");
    //return update_route(msg, msg_size);
    //return update_simplified_route(msg, msg_size);
    return SUCCESS;
}
