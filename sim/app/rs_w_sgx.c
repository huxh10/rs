#include <stdio.h>
#include <stdlib.h>
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "datatypes.h"
#include "error_codes.h"
#include "time_utils.h"
#include "bgp.h"
#include "../enclave/enclave_u.h"
#include "rs_w_sgx.h"
#include "uthash.h"

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
        call_status = enclave_load_as_conf(g_enclave_id, &ret_status, i, (void *) p_as_conf[i].import_policy, num * sizeof(uint32_t), (void *) p_as_conf[i].export_policy, num * num * sizeof(uint32_t));
        if (ret_status == SUCCESS) {
            fprintf(IO_STREAM, "enclave_load_as_conf asn:%u succeeded [%s]\n", i, __FUNCTION__);
        } else {
            fprintf(IO_STREAM, "enclave_load_as_conf failed, asn:%u, errno:%u [%s]\n", i, ret_status, __FUNCTION__);
            exit(-1);
        }
    }
}

void run_rs_w_sgx(int msg_num, bgp_msg_t **pp_bgp_msgs)
{
    int i = 0;
    uint32_t call_status, ret_status;

    for (i = 0; i < msg_num; i++) {
        print_current_time_with_us("compute routes");
        call_status = enclave_compute_route(g_enclave_id, &ret_status, (void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size);
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
    print_current_time_with_us("receive routes");
    int msg_num = *((int *) msg), i = 0, offset = 4;
    uint32_t asn;
    uint8_t oprt_type;
    route_t *p_route = NULL;
    for (i = 0; i < msg_num; i++) {
        asn = *((uint32_t *) ((uint8_t *) msg + offset));
        offset += 4;
        oprt_type = *((uint8_t *) msg + offset);
        offset++;
        fprintf(IO_STREAM, "msg:%d, asn:%u, oprt_type:%u\n", i, asn, oprt_type);
        if (oprt_type == ANNOUNCE) {
            offset += parse_route_from_channel(&p_route, (uint8_t *) msg + offset);
            print_route(p_route);
            free_route(&p_route);
        }
    }
    return SUCCESS;
}
