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

void run_rs_w_sgx(int msg_num, bgp_msg_t **pp_bgp_msgs)
{
    int i = 0;
    uint32_t call_status, ret_status;

    for (i = 0; i < msg_num; i++) {
        printf("\n");
        print_current_time_with_us("compute routes");
        call_status = enclave_ecall_compute_route(g_enclave_id, &ret_status, (void *) pp_bgp_msgs[i], pp_bgp_msgs[i]->msg_size);
        printf("\n");
        print_current_time_with_us("receive routes");
        //printf("\n");
        //print_current_time_with_us("current rs routes");
        //call_status = enclave_ecall_print_rs_ribs(g_enclave_id, &ret_status);
        //
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
    return SUCCESS;
}
