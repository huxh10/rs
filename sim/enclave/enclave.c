#include <stdio.h>
#include <stdarg.h>
#include "enclave_t.h"
#include "sgx_trts.h"
#include "datatypes.h"
#include "bgp.h"
#include "rs.h"
#include "enclave.h"

uint32_t g_num = 0;
as_conf_t *g_p_policies = NULL;
rib_map_t **g_pp_ribs = NULL;

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

uint32_t ecall_load_as_conf(uint32_t asn, void *import_msg, size_t import_msg_size, void *export_msg, size_t export_msg_size)
{
    uint32_t i = 0, total_num = import_msg_size / sizeof(uint32_t);
    if (g_p_policies == NULL) {
        g_num = total_num;
        g_p_policies = malloc(total_num * sizeof *g_p_policies);
        g_pp_ribs = malloc(total_num * sizeof *g_pp_ribs);
        for (i = 0; i < total_num; i++) {
            g_pp_ribs[i] = NULL;
        }
    }
    g_p_policies[asn].asn = asn;
    g_p_policies[asn].total_num = total_num;
    g_p_policies[asn].import_policy = malloc(total_num * sizeof *g_p_policies[asn].import_policy);
    memcpy(g_p_policies[asn].import_policy, import_msg, import_msg_size);
    g_p_policies[asn].export_policy = malloc(total_num * total_num * sizeof *g_p_policies[asn].export_policy);
    memcpy(g_p_policies[asn].export_policy, export_msg, export_msg_size);
    return SGX_SUCCESS;
}

uint32_t ecall_compute_route(void *msg, size_t msg_size)
{
    void *sent_msg = NULL;
    size_t sent_msg_size = 0;
    uint32_t call_status, ret_status;
    compute_route(msg, msg_size, g_p_policies, g_pp_ribs, g_num, &sent_msg, &sent_msg_size);
    call_status = ocall_update_route(&ret_status, (void *) sent_msg, sent_msg_size);
    if (call_status == SGX_SUCCESS) {
        if (ret_status != SGX_SUCCESS) return ret_status;
    } else {
        return call_status;
    }
}

uint32_t ecall_print_rs_ribs()
{
    return print_rs_ribs(g_pp_ribs, g_num);
}
